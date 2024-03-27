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
#include <aconfigd.pb.h>

#include "aconfigd_util.h"
#include "aconfigd.h"

using storage_records_pb = android::aconfig_storage_metadata::storage_files;
using storage_record_pb = android::aconfig_storage_metadata::storage_file_info;
using namespace android::base;

namespace android {
namespace aconfigd {

/// Persistent storage records pb file full path
static constexpr char kPersistentStorageRecordsFileName[] =
    "/metadata/aconfig/persistent_storage_file_records.pb";

/// Persistent storage records pb file full path
static constexpr char kAvailableStorageRecordsFileName[] =
    "/metadata/aconfig/boot/available_storage_file_records.pb";

/// In memory data structure for storage file locations for each container
struct StorageRecord {
  int version;
  std::string container;
  std::string package_map;
  std::string flag_map;
  std::string flag_val;
  int timestamp;

  StorageRecord() = default;

  StorageRecord(storage_record_pb const& entry)
      : version(entry.version())
      , container(entry.container())
      , package_map(entry.package_map())
      , flag_map(entry.flag_map())
      , flag_val(entry.flag_val())
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

/// Read persistent aconfig storage records pb file
Result<storage_records_pb> ReadStorageRecordsPb(const std::string& pb_file) {
  auto records = storage_records_pb();
  if (FileExists(pb_file)) {
    auto content = std::string();
    if (!ReadFileToString(pb_file, &content)) {
      return ErrnoError() << "ReadFileToString failed";
    }

    if (!records.ParseFromString(content)) {
      return ErrnoError() << "Unable to parse storage records protobuf";
    }
  }
  return records;
}

/// Write aconfig storage records protobuf to file
Result<void> WriteStorageRecordsPbToFile(const storage_records_pb& records_pb,
                                         const std::string& file_name) {
  auto content = std::string();
  if (!records_pb.SerializeToString(&content)) {
    return ErrnoError() << "Unable to serialize storage records protobuf";
  }

  if (!WriteStringToFile(content, file_name)) {
    return ErrnoError() << "WriteStringToFile failed";
  }

  if (chmod(file_name.c_str(), 0644) == -1) {
    return ErrnoError() << "chmod failed";
  };

  return {};
}

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

  // If the boot copy already exists, do nothing. Never update the boot copy, the boot
  // copy should be boot stable. So in the following scenario: a container storage
  // file boot copy is created, then an updated container is mounted along side existing
  // container. In this case, we should update the persistent storage file copy. But
  // never touch the current boot copy.
  if (FileExists(dst_value_file)) {
    return {};
  }

  auto copy_result = CopyFile(src_value_file, dst_value_file, 0444);
  if (!copy_result.ok()) {
    return Error() << "CopyFile failed for " << src_value_file << " :"
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

    auto version_result = aconfig_storage::get_storage_file_version(value_file);
    if (!version_result.ok()) {
      return Error() << "Failed to get storage version: " << version_result.error();
    }

    // add to in memory storage file records
    auto& record = persist_storage_records[container];
    record.version = *version_result;
    record.container = container;
    record.package_map = package_file;
    record.flag_map = flag_file;
    record.flag_val = target_value_file;
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
    auto mapped_file = aconfig_storage::get_mapped_file(
        entry.container(), aconfig_storage::StorageFileType::package_map);
    if (!mapped_file.ok()) {
      return Error() << "Failed to map file for container " << entry.container()
                     << ": " << mapped_file.error();
    }

    auto offset = aconfig_storage::get_package_offset(*mapped_file, package);
    if (!offset.ok()) {
      return Error() << "Failed to get offset for package " << package
                     << " from package map of " << entry.container() << " :"
                     << offset.error();
    }

    if (offset->package_exists) {
      container_map[package] = entry.container();
      return entry.container();
    }
  }

  return Error() << "package not found";
}

/// Find boolean flag offset in flag value file
Result<uint32_t> FindBooleanFlagOffset(const std::string& container,
                                       const std::string& package,
                                       const std::string& flag) {

  auto package_map = aconfig_storage::get_mapped_file(
      container, aconfig_storage::StorageFileType::package_map);
  if (!package_map.ok()) {
    return Error() << "Failed to map package map file for " << container
                   << ": " << package_map.error();
  }

  auto pkg_offset = aconfig_storage::get_package_offset(*package_map, package);
  if (!pkg_offset.ok()) {
    return Error() << "Failed to get package offset of " << package
                   << " in " << container  << " :" << pkg_offset.error();
  }

  if (!pkg_offset->package_exists) {
    return Error() << package << " is not found in " << container;
  }

  uint32_t package_id = pkg_offset->package_id;
  uint32_t package_offset = pkg_offset->boolean_offset;

  auto flag_map = aconfig_storage::get_mapped_file(
      container, aconfig_storage::StorageFileType::flag_map);
  if (!flag_map.ok()) {
    return Error() << "Failed to map flag map file for " << container
                   << ": " << flag_map.error();
  }

  auto flg_offset = aconfig_storage::get_flag_offset(*flag_map, package_id, flag);
  if (!flg_offset.ok()) {
    return Error() << "Failed to get flag offset of " << flag
                   << " in " << container  << " :" << flg_offset.error();
  }

  if (!flg_offset->flag_exists) {
    return Error() << flag << " is not found in " << container;
  }

  uint16_t flag_offset = flg_offset->flag_offset;
  return package_offset + flag_offset;
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

/// Update persistent boolean flag value
Result<void> UpdateBooleanFlagValue(const std::string& package_name,
                                    const std::string& flag_name,
                                    const std::string& flag_value) {
  auto container_result = FindContainer(package_name);
  if (!container_result.ok()) {
    return Error() << "Failed for find container for package " << package_name
                   << ": " << container_result.error();
  }
  auto container = *container_result;

  auto offset_result = FindBooleanFlagOffset(container, package_name, flag_name);
  if (!offset_result.ok()) {
    return Error() << "Failed to obtain " << package_name << "."
                   << flag_name << " flag value offset: " << offset_result.error();
  }

  auto mapped_file = aconfig_storage::get_mapped_flag_value_file(container);
  if (!mapped_file.ok()) {
    return Error() << "Failed to map flag value file for " << container
                   << ": " << mapped_file.error();
  }

  if (flag_value != "true" && flag_value != "false") {
    return Error() << "Invalid boolean flag value, it should be true|false";
  }

  auto update_result = aconfig_storage::set_boolean_flag_value(
      *mapped_file, *offset_result, flag_value == "true");
  if (!update_result.ok()) {
    return Error() << "Failed to update flag value: " << update_result.error();
  }

  return {};
}

/// Query persistent boolean flag value
Result<bool> GetBooleanFlagValue(const std::string& package_name,
                                 const std::string& flag_name) {
  auto container_result = FindContainer(package_name);
  if (!container_result.ok()) {
    return Error() << "Failed for find container for package " << package_name
                   << ": " << container_result.error();
  }
  auto container = *container_result;
  auto offset_result = FindBooleanFlagOffset(container, package_name, flag_name);
  if (!offset_result.ok()) {
    return Error() << "Failed to obtain " << package_name << "."
                   << flag_name << " flag value offset: " << offset_result.error();
  }

  auto mapped_file_result = aconfig_storage::get_mapped_flag_value_file(container);
  if (!mapped_file_result.ok()) {
    return Error() << "Failed to map flag value file for " << container
                   << ": " << mapped_file_result.error();
  }

  auto ro_mapped_file = aconfig_storage::MappedStorageFile();
  ro_mapped_file.file_ptr = mapped_file_result->file_ptr;
  ro_mapped_file.file_size = mapped_file_result->file_size;
  auto value_result = aconfig_storage::get_boolean_flag_value(
      ro_mapped_file, *offset_result);
  if (!value_result.ok()) {
    return Error() << "Failed to get flag value: " << value_result.error();
  }

  return *value_result;
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

    auto updated_result = HandleContainerUpdate(
        container, package_file, flag_file, value_file);
    if (!updated_result.ok()) {
      return Error() << updated_result.error();
    }

    auto copy_result = CreateBootSnapshotForContainer(container);
    if (!copy_result.ok()) {
      return Error() << copy_result.error();
    }
  }

  return {};
}

/// Handle incoming messages to aconfigd socket
Result<std::string> HandleSocketRequest(const std::string& msg) {
  auto message = StorageMessage{};
  if (!message.ParseFromString(msg)) {
    return Error() << "Could not parse message from aconfig storage init socket";
  }

  auto return_message = std::string();
  switch (message.msg_case()) {
    case StorageMessage::kNewStorageMessage: {
      LOG(INFO) << "received a new storage request";
      auto msg = message.new_storage_message();
      auto result = AddNewStorage(msg.container(),
                                  msg.package_map(),
                                  msg.flag_map(),
                                  msg.flag_value());
      if (!result.ok()) {
        return Error() << result.error();
      }
      break;
    }
    case StorageMessage::kFlagOverrideMessage: {
      LOG(INFO) << "received a flag override request";
      auto msg = message.flag_override_message();
      auto result = UpdateBooleanFlagValue(msg.package_name(),
                                           msg.flag_name(),
                                           msg.flag_value());
      if (!result.ok()) {
        return Error() << result.error();
      }
      break;
    }
    case StorageMessage::kFlagQueryMessage: {
      LOG(INFO) << "received a flag query request";
      auto msg = message.flag_query_message();
      auto result = GetBooleanFlagValue(msg.package_name(),
                                        msg.flag_name());
      if (!result.ok()) {
        return Error() << result.error();
      }
      return_message = *result ? "true" : "false";
      break;
    }
    default:
      return Error() << "Unknown message type from aconfigd socket: " << message.msg_case();
  }

  return return_message;
}

} // namespace aconfigd
} // namespace android
