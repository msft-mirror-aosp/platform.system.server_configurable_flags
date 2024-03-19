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
    "/metadata/aconfig/available_storage_file_records.pb";

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
Result<storage_records_pb> ReadPersistentStorageRecordsPb() {
  auto records = storage_records_pb();
  if (FileExists(kPersistentStorageRecordsFileName)) {
    auto content = std::string();
    if (!ReadFileToString(kPersistentStorageRecordsFileName, &content)) {
      return ErrnoError() << "ReadFileToString failed";
    }

    if (!records.ParseFromString(content)) {
      return ErrnoError() << "Unable to parse persistent storage records protobuf";
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

/// Initialize in memory aconfig storage records
Result<void> InitializeInMemoryStorageRecords() {
  auto records_pb = ReadPersistentStorageRecordsPb();
  if (!records_pb.ok()) {
    return Error() << "Unable to write to persistent storage records: "
                   << records_pb.error();
  }

  persist_storage_records.clear();
  for (auto& entry : records_pb->files()) {
    persist_storage_records.insert({entry.container(), StorageRecord(entry)});
  }

  return {};
}

/// Create boot flag value copy for a container
Result<void> CreateBootSnapshotForContainer(const std::string& container,
                                            storage_records_pb& available_storage) {
  auto src_value_file = std::string("/metadata/aconfig/flags/") + container + ".val";
  auto dst_value_file = std::string("/metadata/aconfig/boot/") + container + ".val";
  auto copy_result = CopyFile(src_value_file, dst_value_file, 0444);
  if (!copy_result.ok()) {
    return Error() << "CopyFile failed for " << src_value_file << " :"
                   << copy_result.error();
  }

  if (!persist_storage_records.count(container)) {
    return Error() << "Missing persistent storage records for " << container;
  }

  auto const& entry = persist_storage_records[container];
  auto* record_pb = available_storage.add_files();
  record_pb->set_version(entry.version);
  record_pb->set_container(entry.container);
  record_pb->set_package_map(entry.package_map);
  record_pb->set_flag_map(entry.flag_map);
  record_pb->set_flag_val(dst_value_file);
  record_pb->set_timestamp(entry.timestamp);

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

  // check if a partition has been updated by checking timestamp
  auto it = persist_storage_records.find(container);
  if (it == persist_storage_records.end() || it->second.timestamp != *timestamp) {
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

    auto& record = persist_storage_records[container];
    record.version = *version_result;
    record.container = container;
    record.package_map = package_file;
    record.flag_map = flag_file;
    record.flag_val = target_value_file;
    record.timestamp = *timestamp;

    return true;
  }

  return false;
}

} // namespace

/// Initialize platform RO partition flag storage
Result<void> InitializePlatformStorage() {
  auto init_result = InitializeInMemoryStorageRecords();
  if (!init_result.ok()) {
    return Error() << "Failed to initialize persistent storage records in memory: "
                   << init_result.error();
  }

  auto value_files = std::vector<std::pair<std::string, std::string>>{
    {"system", "/system/etc/aconfig"},
    {"system_ext", "/system_ext/etc/aconfig"},
    {"vendor", "/vendor/etc/aconfig"},
    {"product", "/product/etc/aconfig"}};

  auto available_storage_pb = storage_records_pb();
  bool update_persistent_storage_records = false;
  for (auto const& [container, storage_dir] : value_files) {
    auto package_file = std::string(storage_dir) + "/package.map";
    auto flag_file = std::string(storage_dir) + "/flag.map";
    auto value_file = std::string(storage_dir) + "/flag.val";

    if (!FileExists(value_file)) {
      continue;
    }

    auto updated_result = HandleContainerUpdate(container, package_file, flag_file, value_file);
    if (!updated_result.ok()) {
      return Error() << updated_result.error();
    } else {
      update_persistent_storage_records |= *updated_result;
    }

    auto copy_result = CreateBootSnapshotForContainer(container, available_storage_pb);
    if (!copy_result.ok()) {
      return Error() << copy_result.error();
    }
  }

  if (update_persistent_storage_records) {
    auto write_result = WritePersistentStorageRecordsToFile();
    if (!write_result.ok()) {
      return Error() << "Failed to write to persistent storage records file"
                     << write_result.error();
    }
  }

  WriteStorageRecordsPbToFile(available_storage_pb, kAvailableStorageRecordsFileName);

  return {};
}

/// Handle incoming messages to aconfigd socket
void HandleSocketRequest(const std::string& msg) {
  auto message = StorageMessage{};
  if (!message.ParseFromString(msg)) {
    LOG(ERROR) << "Could not parse message from aconfig storage init socket";
    return;
  }

  switch (message.msg_case()) {
    case StorageMessage::kNewStorageMessage: {
      // TODO
      // Initialize for new storage
      break;
    }
    case StorageMessage::kFlagOverrideMessage: {
      // TODO
      // Update flag value based
      break;
    }
    default:
      LOG(ERROR) << "Unknown message type from aconfigd socket: " << message.msg_case();
  }
}

} // namespace aconfigd
} // namespace android
