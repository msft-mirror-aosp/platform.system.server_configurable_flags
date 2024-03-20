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

/// In memort storage file records. Parsed from the pb.
static StorageRecords persist_storage_records;

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
  // TODO: remove this check once b/330134027 is fixed. This is temporary as android
  // on chrome os vm does not have /metadata partition at the moment.
  DIR* dir = opendir("/metadata/aconfig");
  if (!dir) {
    return {};
  }
  closedir(dir);

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
Result<void> HandleSocketRequest(const std::string& msg) {
  auto message = StorageMessage{};
  if (!message.ParseFromString(msg)) {
    return Error() << "Could not parse message from aconfig storage init socket";
  }

  switch (message.msg_case()) {
    case StorageMessage::kNewStorageMessage: {
      auto msg = message.new_storage_message();

      auto updated_result = HandleContainerUpdate(
          msg.container(), msg.package_map(), msg.flag_map(), msg.flag_value());
      if (!updated_result.ok()) {
        return Error() << "Failed to update container " << msg.container()
            << ":" << updated_result.error();
      }

      auto copy_result = CreateBootSnapshotForContainer(msg.container());
      if (!copy_result.ok()) {
        return Error() << "Failed to make a boot copy: " << copy_result.error();
      }
      break;
    }
    case StorageMessage::kFlagOverrideMessage: {
      // TODO
      // Update flag value based
      break;
    }
    default:
      return Error() << "Unknown message type from aconfigd socket: " << message.msg_case();
  }

  return {};
}

} // namespace aconfigd
} // namespace android
