/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string>
#include <unordered_map>

#include <dirent.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <cutils/sockets.h>

#include <aconfig_storage/aconfig_storage_read_api.hpp>
#include <aconfig_storage/aconfig_storage_write_api.hpp>
#include <protos/aconfig_storage_metadata.pb.h>

#include "aconfigd_util.h"
#include "aconfigd.h"

using storage_records_pb = android::aconfig_storage_metadata::storage_files;
using storage_record_pb = android::aconfig_storage_metadata::storage_file_info;
using namespace android::base;
using namespace aconfig_storage;

namespace android {
namespace aconfigd {

/// In memory data structure for storage file locations for each container
struct StorageRecord {
  int version;
  std::string container;
  std::string package_map;
  std::string flag_map;
  std::string flag_val;
  std::string flag_info;
  int timestamp;

  StorageRecord() = default;

  StorageRecord(storage_record_pb const& entry)
      : version(entry.version())
      , container(entry.container())
      , package_map(entry.package_map())
      , flag_map(entry.flag_map())
      , flag_val(entry.flag_val())
      , flag_info(entry.flag_info())
      , timestamp(entry.timestamp())
  {}
};

/// A map from container name to the respective storage file locations
using StorageRecords = std::unordered_map<std::string, StorageRecord>;

/// In memory storage file records. Parsed from the pb.
static StorageRecords persist_storage_records;

/// In memory cache for package to container mapping
static std::unordered_map<std::string, std::string> container_map;

namespace {

/// Write in memory aconfig storage records to the persistent pb file
Result<void> WritePersistentStorageRecordsToFile() {
  auto records_pb = storage_records_pb();
  for (auto const& [container, entry] : persist_storage_records) {
    auto* record_pb = records_pb.add_files();
    record_pb->set_version(entry.version);
    record_pb->set_container(entry.container);
    record_pb->set_package_map(entry.package_map);
    record_pb->set_flag_map(entry.flag_map);
    record_pb->set_flag_val(entry.flag_val);
    record_pb->set_flag_info(entry.flag_info);
    record_pb->set_timestamp(entry.timestamp);
  }

  return WriteStorageRecordsPbToFile(records_pb, kPersistentStorageRecordsFileName);
}

/// Create boot flag value copy for a container
Result<void> CreateBootSnapshotForContainer(const std::string& container) {
  // check existence persistent storage copy
  if (!persist_storage_records.count(container)) {
    return Error() << "Missing persistent storage records for " << container;
  }

  // create boot copy
  auto src_value_file = std::string("/metadata/aconfig/flags/") + container + ".val";
  auto dst_value_file = std::string("/metadata/aconfig/boot/") + container + ".val";
  auto src_info_file = std::string("/metadata/aconfig/flags/") + container + ".info";
  auto dst_info_file = std::string("/metadata/aconfig/boot/") + container + ".info";

  // If the boot copy already exists, do nothing. Never update the boot copy, the boot
  // copy should be boot stable. So in the following scenario: a container storage
  // file boot copy is created, then an updated container is mounted along side existing
  // container. In this case, we should update the persistent storage file copy. But
  // never touch the current boot copy.
  if (FileExists(dst_value_file) || FileExists(dst_info_file)) {
    return {};
  }

  auto copy_result = CopyFile(src_value_file, dst_value_file, 0444);
  if (!copy_result.ok()) {
    return Error() << "CopyFile failed for " << src_value_file << " :"
                   << copy_result.error();
  }

  copy_result = CopyFile(src_info_file, dst_info_file, 0444);
  if (!copy_result.ok()) {
    return Error() << "CopyFile failed for " << src_info_file << " :"
                   << copy_result.error();
  }

  // update available storage records pb
  auto const& entry = persist_storage_records[container];
  auto records_pb = ReadStorageRecordsPb(kAvailableStorageRecordsFileName);
  if (!records_pb.ok()) {
    return Error() << "Unable to read available storage records: "
                   << records_pb.error();
  }

  auto* record_pb = records_pb->add_files();
  record_pb->set_version(entry.version);
  record_pb->set_container(entry.container);
  record_pb->set_package_map(entry.package_map);
  record_pb->set_flag_map(entry.flag_map);
  record_pb->set_flag_val(dst_value_file);
  record_pb->set_flag_info(dst_info_file);
  record_pb->set_timestamp(entry.timestamp);

  auto write_result =  WriteStorageRecordsPbToFile(
      *records_pb, kAvailableStorageRecordsFileName);
  if (!write_result.ok()) {
    return Error() << "Failed to write available storage records: "
                   << write_result.error();
  }

  return {};
}

/// Handle container update, returns if container has been updated
Result<bool> HandleContainerUpdate(const std::string& container,
                                   const std::string& package_file,
                                   const std::string& flag_file,
                                   const std::string& value_file) {
  auto timestamp = GetFileTimeStamp(value_file);
  if (!timestamp.ok()) {
    return Error() << "Failed to get timestamp of " << value_file
                   << ": "<< timestamp.error();
  }

  // the storage record of a container needs to be updated if this is the first time
  // we encountered this container or the container has been updated.
  auto it = persist_storage_records.find(container);
  if (it == persist_storage_records.end() || it->second.timestamp != *timestamp) {
    // copy flag value file
    auto target_value_file = std::string("/metadata/aconfig/flags/") + container + ".val";
    auto copy_result = CopyFile(value_file, target_value_file, 0644);
    if (!copy_result.ok()) {
      return Error() << "CopyFile failed for " << value_file << " :"
                     << copy_result.error();
    }

    auto version = get_storage_file_version(value_file);
    if (!version.ok()) {
      return Error() << "Failed to get storage version: " << version.error();
    }

    // create flag info file
    auto flag_info_file = std::string("/metadata/aconfig/flags/") + container + ".info";
    auto create_result = create_flag_info(package_file, flag_file, flag_info_file);
    if (!create_result.ok()) {
      return Error() << "Failed to create flag info file for container " << container
                     << ": " << create_result.error();
    }

    // add to in memory storage file records
    auto& record = persist_storage_records[container];
    record.version = *version;
    record.container = container;
    record.package_map = package_file;
    record.flag_map = flag_file;
    record.flag_val = target_value_file;
    record.flag_info = flag_info_file;
    record.timestamp = *timestamp;

    // write to persistent storage records file
    auto write_result = WritePersistentStorageRecordsToFile();
    if (!write_result.ok()) {
      return Error() << "Failed to write to persistent storage records file"
                     << write_result.error();
    }

    return true;
  }

  return false;
}

/// Find the container name given flag package name
Result<std::string> FindContainer(const std::string& package) {
  if (container_map.count(package)) {
    return container_map[package];
  }

  auto records_pb = ReadStorageRecordsPb(kAvailableStorageRecordsFileName);
  if (!records_pb.ok()) {
    return Error() << "Unable to read available storage records: "
                   << records_pb.error();
  }

  for (auto& entry : records_pb->files()) {
    auto mapped_file = get_mapped_file(entry.container(), StorageFileType::package_map);
    if (!mapped_file.ok()) {
      return Error() << "Failed to map file for container " << entry.container()
                     << ": " << mapped_file.error();
    }

    auto context= get_package_read_context(*mapped_file, package);
    if (!context.ok()) {
      return Error() << "Failed to get offset for package " << package
                     << " from package map of " << entry.container() << " :"
                     << context.error();
    }

    if (context->package_exists) {
      container_map[package] = entry.container();
      return entry.container();
    }
  }

  return Error() << "package not found";
}

/// Find boolean flag offset in flag value file
Result<std::pair<FlagValueType, uint32_t>> FindFlagContext(
    const std::string& container,
    const std::string& package,
    const std::string& flag) {

  auto package_map = get_mapped_file(container, StorageFileType::package_map);
  if (!package_map.ok()) {
    return Error() << "Failed to map package map file for " << container
                   << ": " << package_map.error();
  }

  auto package_context = get_package_read_context(*package_map, package);
  if (!package_context.ok()) {
    return Error() << "Failed to get package offset of " << package
                   << " in " << container  << " :" << package_context.error();
  }

  if (!package_context->package_exists) {
    return Error() << package << " is not found in " << container;
  }

  uint32_t package_id = package_context->package_id;
  uint32_t package_start_index = package_context->boolean_start_index;

  auto flag_map = get_mapped_file(container, StorageFileType::flag_map);
  if (!flag_map.ok()) {
    return Error() << "Failed to map flag map file for " << container
                   << ": " << flag_map.error();
  }

  auto flag_context = get_flag_read_context(*flag_map, package_id, flag);
  if (!flag_context.ok()) {
    return Error() << "Failed to get flag offset of " << flag
                   << " in " << container  << " :" << flag_context.error();
  }

  if (!flag_context->flag_exists) {
    return Error() << flag << " is not found in " << container;
  }

  auto value_type = map_to_flag_value_type(flag_context->flag_type);
  if (!value_type.ok()) {
    return Error() << "Failed to get flag value type :" << value_type.error();
  }

  auto index = package_start_index + flag_context->flag_index;
  return std::make_pair(*value_type, index);
}

/// Add a new storage
Result<void> AddNewStorage(const std::string& container,
                           const std::string& package_map,
                           const std::string& flag_map,
                           const std::string& flag_val) {
  auto updated_result = HandleContainerUpdate(
      container, package_map, flag_map, flag_val);
  if (!updated_result.ok()) {
    return Error() << "Failed to update container " << container
                   << ":" << updated_result.error();
  }

  auto copy_result = CreateBootSnapshotForContainer(container);
  if (!copy_result.ok()) {
    return Error() << "Failed to make a boot copy: " << copy_result.error();
  }

  return {};
}

/// Update persistent flag value
Result<void> UpdatePersistentFlagValue(const std::string& package_name,
                                       const std::string& flag_name,
                                       const std::string& flag_value) {
  auto container_result = FindContainer(package_name);
  if (!container_result.ok()) {
    return Error() << "Failed for find container for package " << package_name
                   << ": " << container_result.error();
  }
  auto container = *container_result;

  auto context_result = FindFlagContext(container, package_name, flag_name);
  if (!context_result.ok()) {
    return Error() << "Failed to obtain " << package_name << "."
                   << flag_name << " flag value offset: " << context_result.error();
  }

  auto mapped_value_file = get_mutable_mapped_file(container, StorageFileType::flag_val);
  if (!mapped_value_file.ok()) {
    return Error() << "Failed to map flag value file for " << container
                   << ": " << mapped_value_file.error();
  }

  auto mapped_info_file = get_mutable_mapped_file(container, StorageFileType::flag_info);
  if (!mapped_info_file.ok()) {
    return Error() << "Failed to map flag info file for " << container
                   << ": " << mapped_info_file.error();
  }

  auto value_type = context_result->first;
  auto flag_index = context_result->second;

  switch (value_type) {
    case FlagValueType::Boolean: {
      if (flag_value != "true" && flag_value != "false") {
        return Error() << "Invalid boolean flag value, it should be true|false";
      }
      auto update_result = set_boolean_flag_value(
          *mapped_value_file, flag_index, flag_value == "true");
      if (!update_result.ok()) {
        return Error() << "Failed to update flag value: " << update_result.error();
      }
      update_result = set_flag_has_override(
          *mapped_info_file, value_type, flag_index, true);
      if (!update_result.ok()) {
        return Error() << "Failed to update flag has override: " << update_result.error();
      }
      break;
    }
    default:
      return Error() << "Unsupported flag value type";
  }

  return {};
}

/// Query persistent flag value and info
Result<std::pair<std::string, uint8_t>> QueryPersistentFlag(
    const std::string& package_name,
    const std::string& flag_name) {
  auto container = FindContainer(package_name);
  if (!container.ok()) {
    return Error() << "Failed for find container for package " << package_name
                   << ": " << container.error();
  }

  auto context = FindFlagContext(*container, package_name, flag_name);
  if (!context.ok()) {
    return Error() << "Failed to obtain " << package_name << "."
                   << flag_name << " flag value offset: " << context.error();
  }
  auto value_type = context->first;
  auto flag_index = context->second;

  auto value_file = get_mutable_mapped_file(*container, StorageFileType::flag_val);
  if (!value_file.ok()) {
    return Error() << "Failed to map flag value file for " << *container
                   << ": " << value_file.error();
  }

  auto info_file = get_mutable_mapped_file(*container, StorageFileType::flag_info);
  if (!info_file.ok()) {
    return Error() << "Failed to map flag info file for " << *container
                   << ": " << info_file.error();
  }

  // return value
  auto flag_value = std::string();
  uint8_t flag_info = 0;

  switch (value_type) {
    case FlagValueType::Boolean: {
      // get flag value
      auto ro_value_file = MappedStorageFile();
      ro_value_file.file_ptr = value_file->file_ptr;
      ro_value_file.file_size = value_file->file_size;
      auto value = get_boolean_flag_value(ro_value_file, flag_index);
      if (!value.ok()) {
        return Error() << "Failed to get flag value: " << value.error();
      }
      flag_value = *value ? "true" : "false";

      // get flag attribute
      auto ro_info_file = MappedStorageFile();
      ro_info_file.file_ptr = info_file->file_ptr;
      ro_info_file.file_size = info_file->file_size;
      auto attribute = get_flag_attribute(ro_info_file, value_type, flag_index);
      if (!attribute.ok()) {
        return Error() << "Failed to get flag info: " << attribute.error();
      }
      flag_info = *attribute;

      break;
    }
    default:
      return Error() << "Unsupported flag value type";
  }

  return std::make_pair(flag_value, flag_info);
}

} // namespace

/// Initialize in memory aconfig storage records
Result<void> InitializeInMemoryStorageRecords() {
  auto records_pb = ReadStorageRecordsPb(kPersistentStorageRecordsFileName);
  if (!records_pb.ok()) {
    return Error() << "Unable to read persistent storage records: "
                   << records_pb.error();
  }

  persist_storage_records.clear();
  for (auto& entry : records_pb->files()) {
    persist_storage_records.insert({entry.container(), StorageRecord(entry)});
  }

  return {};
}

/// Initialize platform RO partition flag storage
Result<void> InitializePlatformStorage() {
  auto value_files = std::vector<std::pair<std::string, std::string>>{
    {"system", "/system/etc/aconfig"},
    {"system_ext", "/system_ext/etc/aconfig"},
    {"vendor", "/vendor/etc/aconfig"},
    {"product", "/product/etc/aconfig"}};

  for (auto const& [container, storage_dir] : value_files) {
    auto package_file = std::string(storage_dir) + "/package.map";
    auto flag_file = std::string(storage_dir) + "/flag.map";
    auto value_file = std::string(storage_dir) + "/flag.val";

    if (!FileExists(value_file)) {
      continue;
    }

    auto updated = HandleContainerUpdate(
        container, package_file, flag_file, value_file);
    if (!updated.ok()) {
      return Error() << updated.error();
    }

    auto copied = CreateBootSnapshotForContainer(container);
    if (!copied.ok()) {
      return Error() << copied.error();
    }
  }

  return {};
}

/// Handle incoming messages to aconfigd socket
void HandleSocketRequest(const StorageRequestMessage& message,
                         StorageReturnMessage& return_message) {
  switch (message.msg_case()) {
    case StorageRequestMessage::kNewStorageMessage: {
      LOG(INFO) << "received a new storage request";
      auto msg = message.new_storage_message();
      auto result = AddNewStorage(msg.container(),
                                  msg.package_map(),
                                  msg.flag_map(),
                                  msg.flag_value());
      if (!result.ok()) {
        auto* errmsg = return_message.mutable_error_message();
        *errmsg = result.error().message();
      } else {
        return_message.mutable_new_storage_message();
      }
      break;
    }

    case StorageRequestMessage::kFlagOverrideMessage: {
      LOG(INFO) << "received a flag override request";
      auto msg = message.flag_override_message();
      auto result = UpdatePersistentFlagValue(msg.package_name(),
                                              msg.flag_name(),
                                              msg.flag_value());
      if (!result.ok()) {
        auto* errmsg = return_message.mutable_error_message();
        *errmsg = result.error().message();
      } else {
        return_message.mutable_flag_override_message();
      }
      break;
    }

    case StorageRequestMessage::kFlagQueryMessage: {
      LOG(INFO) << "received a flag query request";
      auto msg = message.flag_query_message();
      auto result = QueryPersistentFlag(msg.package_name(), msg.flag_name());
      if (!result.ok()) {
        auto* errmsg = return_message.mutable_error_message();
        *errmsg = result.error().message();
      } else {
        auto return_msg = return_message.mutable_flag_query_message();
        return_msg->set_flag_value(result->first);
        return_msg->set_is_sticky(result->second & FlagInfoBit::IsSticky);
        return_msg->set_is_readwrite(result->second & FlagInfoBit::IsReadWrite);
        return_msg->set_has_override(result->second & FlagInfoBit::HasOverride);
      }
      break;
    }
    default:
      auto* errmsg = return_message.mutable_error_message();
      *errmsg = "Unknown message type from aconfigd socket";
      break;
  }
}

} // namespace aconfigd
} // namespace android
