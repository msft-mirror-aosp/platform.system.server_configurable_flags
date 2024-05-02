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
#include <protos/aconfig_storage_metadata.pb.h>

#include "storage_files_manager.h"
#include "storage_files.h"
#include "aconfigd_util.h"
#include "aconfigd.h"

using storage_records_pb = android::aconfig_storage_metadata::storage_files;
using storage_record_pb = android::aconfig_storage_metadata::storage_file_info;
using namespace android::base;
using namespace aconfig_storage;

namespace android {
namespace aconfigd {

/// Mapped files manager
static StorageFilesManager storage_files_manager;

namespace {

/// Write in memory aconfig storage records to the persistent pb file
Result<void> WritePersistentStorageRecordsToFile() {
  auto records_pb = aconfig_storage_metadata::storage_files();
  for (auto const& record : storage_files_manager.GetAllStorageRecords()) {
    auto* record_pb = records_pb.add_files();
    record_pb->set_version(record->version);
    record_pb->set_container(record->container);
    record_pb->set_package_map(record->package_map);
    record_pb->set_flag_map(record->flag_map);
    record_pb->set_flag_val(record->flag_val);
    record_pb->set_flag_info(record->flag_info);
    record_pb->set_local_overrides(record->local_overrides);
    record_pb->set_timestamp(record->timestamp);
  }
  return WritePbToFile<storage_records_pb>(records_pb, kPersistentStorageRecordsFileName);
}

/// Handle a local flag override request
Result<void> HandleLocalFlagOverride(const std::string& package,
                                     const std::string& flag,
                                     const std::string& flag_value) {
  auto container = storage_files_manager.GetContainer(package);
  RETURN_IF_ERROR(container, "Failed to find owning container");

  auto storage_files = storage_files_manager.GetStorageFiles(*container);
  RETURN_IF_ERROR(storage_files, "Failed to get storage files object");

  auto context = (**storage_files).GetPackageFlagContext(package, flag);
  RETURN_IF_ERROR(context, "Failed to find package flag context");

  auto update = (**storage_files).SetLocalFlagValue(*context, flag_value);
  RETURN_IF_ERROR(update, "Failed to set local flag override");

  return {};
}

/// Handle a server flag override request
Result<void> HandleServerFlagOverride(const std::string& package,
                                      const std::string& flag,
                                      const std::string& flag_value) {
  auto container = storage_files_manager.GetContainer(package);
  RETURN_IF_ERROR(container, "Failed to find owning container");

  auto storage_files = storage_files_manager.GetStorageFiles(*container);
  RETURN_IF_ERROR(storage_files, "Failed to get storage files object");

  auto context = (**storage_files).GetPackageFlagContext(package, flag);
  RETURN_IF_ERROR(context, "Failed to find package flag context");

  auto update =(**storage_files).SetServerFlagValue(*context, flag_value);
  RETURN_IF_ERROR(update, "Failed to set server flag value");

  return {};
}

/// Handle a flag override request
void HandleFlagOverride(const StorageRequestMessage::FlagOverrideMessage& msg,
                        StorageReturnMessage& return_msg) {
  auto result = Result<void>();
  if (msg.is_local()) {
    result = HandleLocalFlagOverride(msg.package_name(),
                                     msg.flag_name(),
                                     msg.flag_value());
  } else {
    result = HandleServerFlagOverride(msg.package_name(),
                                      msg.flag_name(),
                                      msg.flag_value());
  }

  if (!result.ok()) {
    auto* errmsg = return_msg.mutable_error_message();
    *errmsg = "Failed to set flag " + msg.package_name() + "/" + msg.flag_name() +
              ": " + result.error().message();
  } else {
    return_msg.mutable_flag_override_message();
  }
}

Result<void> ApplyLocalOverridesToBootCopy(const std::string& container,
                                           const std::string& flag_value_file) {
  auto storage_files = storage_files_manager.GetStorageFiles(container);
  RETURN_IF_ERROR(storage_files, "Failed to get storage files object");

  // change boot flag value file to 0644 to allow write
  if (chmod(flag_value_file.c_str(), 0644) == -1) {
    return base::ErrnoError() << "chmod() failed";
  };

  auto applied = (**storage_files).ApplyLocalOverride(flag_value_file);
  RETURN_IF_ERROR(applied, "Failed to apply local override");

  // change boot flag value file back to 0444
  if (chmod(flag_value_file.c_str(), 0444) == -1) {
    return base::ErrnoError() << "chmod() failed";
  };

  return {};
}


/// Create boot flag value copy for a container
Result<void> CreateBootSnapshotForContainer(const std::string& container) {
  if (!storage_files_manager.HasContainer(container)) {
    return Error() << "Cannot create boot copy without persist copy for " << container;
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
  if (FileExists(dst_value_file) && FileExists(dst_info_file)) {
    return {};
  }

  auto copy_result = CopyFile(src_value_file, dst_value_file, 0444);
  RETURN_IF_ERROR(copy_result, "CopyFile failed for " + src_value_file);

  auto apply_result = ApplyLocalOverridesToBootCopy(container, dst_value_file);
  RETURN_IF_ERROR(apply_result, "Failed to apply local overrides to " + dst_value_file);

  copy_result = CopyFile(src_info_file, dst_info_file, 0444);
  RETURN_IF_ERROR(copy_result, "CopyFile failed for " + src_info_file);

  // update available storage records pb
  auto storage_files = storage_files_manager.GetStorageFiles(container);
  RETURN_IF_ERROR(storage_files, "Failed to get storage files object");
  const auto& record = (**storage_files).GetStorageRecord();

  auto available_pb = ReadPbFromFile<storage_records_pb>(kAvailableStorageRecordsFileName);
  RETURN_IF_ERROR(available_pb, "Unable to read available storage records");

  auto* record_pb = available_pb->add_files();
  record_pb->set_version(record.version);
  record_pb->set_container(record.container);
  record_pb->set_package_map(record.package_map);
  record_pb->set_flag_map(record.flag_map);
  record_pb->set_flag_val(dst_value_file);
  record_pb->set_flag_info(dst_info_file);
  record_pb->set_timestamp(record.timestamp);

  auto write_result = WritePbToFile<storage_records_pb>(
      *available_pb, kAvailableStorageRecordsFileName);
  RETURN_IF_ERROR(write_result, "Failed to write available storage records pb");

  return {};
}

/// Persist local flag overrides bit in flag info file
Result<void> PersistLocalOverrides(const std::string& container) {
  auto storage_files = storage_files_manager.GetStorageFiles(container);
  RETURN_IF_ERROR(storage_files, "Failed to get storage files object");

  // mark exsting local overrides on new flag info file
  auto pb_file = (**storage_files).GetStorageRecord().local_overrides;
  auto pb = ReadPbFromFile<LocalFlagOverrides>(pb_file);
  RETURN_IF_ERROR(pb, "Failed to read pb from " + pb_file);

  for (const auto& entry : pb->overrides()) {
    auto has_flag = (**storage_files).HasFlag(entry.package_name(), entry.flag_name());
    RETURN_IF_ERROR(has_flag, "Failed to check if has flag for " + entry.package_name()
                    + "/" + entry.flag_name());

    if (*has_flag) {
      auto context = (**storage_files).GetPackageFlagContext(
          entry.package_name(), entry.flag_name());
      RETURN_IF_ERROR(context, "Failed to find package flag context for " +
                      entry.package_name() + "/" + entry.flag_name());

      auto update = (**storage_files).SetHasLocalOverride(*context, true);
      RETURN_IF_ERROR(update, "Failed to set flag has local override");
    }
  }

  return {};
}

/// Persist server flag overrides
Result<void> PersistServerOverrides(
    const std::vector<FlagValueAndInfoSummary>& current_server_overrides) {
  for (const auto& server_override : current_server_overrides) {
    auto update = HandleServerFlagOverride(server_override.package_name,
                                           server_override.flag_name,
                                           server_override.flag_value);
    RETURN_IF_ERROR(update, "Failed to persist server flag override for " +
                    server_override.package_name + "/" +
                    server_override.flag_name + " to " +
                    server_override.flag_value);
  }

  return {};
}

/// Add a container storage if not existed, otherwise update if needed
Result<bool> AddOrUpdateStorageForContainer(const std::string& container,
                                            const std::string& package_file,
                                            const std::string& flag_file,
                                            const std::string& value_file) {
  auto timestamp = GetFileTimeStamp(value_file);
  RETURN_IF_ERROR(timestamp, "Failed to get timestamp of " + value_file);

  // the storage record of a container needs to be updated if this is the first time
  // we encountered this container or the container has been updated.
  bool new_container = !storage_files_manager.HasContainer(container);
  bool update_existing_container = false;
  if (!new_container) {
    auto storage_files = storage_files_manager.GetStorageFiles(container);
    RETURN_IF_ERROR(storage_files, "Failed to get storage files object");
    if ((**storage_files).GetStorageRecord().timestamp != *timestamp) {
      update_existing_container = true;
    }
  }

  // early return if no update is needed
  if (!(new_container || update_existing_container)) {
    return false;
  }

  // backup server flag update before switch over to new storage files
  auto current_server_overrides = std::vector<FlagValueAndInfoSummary>();
  if (update_existing_container) {
    auto storage_files = storage_files_manager.GetStorageFiles(container);
    RETURN_IF_ERROR(storage_files, "Failed to get storage files object");
    auto current_server_overrides_result = (**storage_files).GetAllServerOverrides();
    RETURN_IF_ERROR(current_server_overrides_result,
                    "Failed to find all existing server overrides");
    current_server_overrides = *current_server_overrides_result;
  }

  // copy flag value file
  auto flags_dir = std::string("/metadata/aconfig/flags/");
  auto target_value_file = flags_dir + container + ".val";
  auto copy_result = CopyFile(value_file, target_value_file, 0644);
  RETURN_IF_ERROR(copy_result, "CopyFile failed for " + value_file);

  // create flag info file
  auto flag_info_file = std::string("/metadata/aconfig/flags/") + container + ".info";
  auto create_result = create_flag_info(package_file, flag_file, flag_info_file);
  RETURN_IF_ERROR(create_result, "Failed to create flag info file for " + container);

  // create new storage file record
  auto version = get_storage_file_version(value_file);
  RETURN_IF_ERROR(version, "Failed to get storage version");
  auto record = StorageRecord();
  record.version = *version;
  record.container = container;
  record.package_map = package_file;
  record.flag_map = flag_file;
  record.flag_val = target_value_file;
  record.flag_info = flag_info_file;
  record.local_overrides = flags_dir + container + "_local_overrides.pb";
  record.timestamp = *timestamp;

  if (new_container) {
    storage_files_manager.AddStorageFiles(container, record);
  } else {
    auto storage_files = storage_files_manager.GetStorageFiles(container);
    RETURN_IF_ERROR(storage_files, "Failed to get storage files object");
    (**storage_files).SetStorageRecord(record);
    auto update = PersistLocalOverrides(container);
    RETURN_IF_ERROR(update, "Failed to persist local overrides");
    update = PersistServerOverrides(current_server_overrides);
    RETURN_IF_ERROR(update, "Failed to persist server overrides");
  }

  // write to persistent storage records file
  auto write_result = WritePersistentStorageRecordsToFile();
  RETURN_IF_ERROR(write_result, "Failed to write to persistent storage records");

  return true;
}

/// Handle new storage request
void HandleNewStorage(const StorageRequestMessage::NewStorageMessage& msg,
                      StorageReturnMessage& return_msg) {
  auto updated = AddOrUpdateStorageForContainer(
      msg.container(), msg.package_map(), msg.flag_map(), msg.flag_value());
  if (!updated.ok()) {
    auto* errmsg = return_msg.mutable_error_message();
    *errmsg = "Failed to add or update container " + msg.container()
              + ": " + updated.error().message();
    return;
  }

  auto copy = CreateBootSnapshotForContainer(msg.container());
  if (!copy.ok()) {
    auto* errmsg = return_msg.mutable_error_message();
    *errmsg = "Failed to make a boot copy for " + msg.container()
              + ": " + copy.error().message();
    return;
  }

  auto result_msg = return_msg.mutable_new_storage_message();
  result_msg->set_storage_updated(*updated);
}

/// Get flag server value, local value and attribute
Result<std::tuple<std::string, std::string, uint8_t>> GetFlagValueAndAttribute(
    const std::string& package,
    const std::string& flag) {
  auto container = storage_files_manager.GetContainer(package);
  RETURN_IF_ERROR(container, "Failed to find owning container");

  auto storage_files = storage_files_manager.GetStorageFiles(*container);
  RETURN_IF_ERROR(storage_files, "Failed to get storage files object");

  auto context = (**storage_files).GetPackageFlagContext(package, flag);
  RETURN_IF_ERROR(context, "Failed to find package flag context");

  auto server_value = (**storage_files).GetServerFlagValue(*context);
  RETURN_IF_ERROR(server_value, "Failed to get server flag value");

  auto attribute = (**storage_files).GetFlagAttribute(*context);
  RETURN_IF_ERROR(context, "Failed to get flag attribute");

  auto local_value = std::string();
  if (*attribute & FlagInfoBit::HasLocalOverride) {
    auto value = (**storage_files).GetLocalFlagValue(*context);
    RETURN_IF_ERROR(value, "Failed to get local flag value");
    local_value = *value;
  }

  return std::make_tuple(*server_value, local_value, *attribute);
}

/// Handle a flag query request
void HandlePersistFlagQuery(const StorageRequestMessage::FlagQueryMessage& msg,
                            StorageReturnMessage& return_msg) {
  auto result = GetFlagValueAndAttribute(msg.package_name(), msg.flag_name());
  if (!result.ok()) {
    auto* errmsg = return_msg.mutable_error_message();
    *errmsg = "Flag query failed: " + result.error().message();
  } else {
    auto [server_value, local_value, attribute] = *result;
    auto result_msg = return_msg.mutable_flag_query_message();
    result_msg->set_server_flag_value(server_value);
    result_msg->set_local_flag_value(local_value);
    result_msg->set_has_server_override(attribute & FlagInfoBit::HasServerOverride);
    result_msg->set_is_readwrite(attribute & FlagInfoBit::IsReadWrite);
    result_msg->set_has_local_override(attribute & FlagInfoBit::HasLocalOverride);
  }
}

/// Remove all local overrides
Result<void> RemoveAllLocalOverrides() {
  for (auto const& record : storage_files_manager.GetAllStorageRecords()) {
    auto storage_files = storage_files_manager.GetStorageFiles(record->container);
    RETURN_IF_ERROR(storage_files, "Failed to get storage files object");
    auto update = (**storage_files).RemoveAllLocalFlagValue();
    RETURN_IF_ERROR(update, "Failed to remove all flag local overrides for "
                    + record->container);
  }
  return {};
}

/// Remove a local override
Result<void> RemoveFlagLocalOverride(const std::string& package,
                                     const std::string& flag) {

  auto container = storage_files_manager.GetContainer(package);
  RETURN_IF_ERROR(container, "Failed to find owning container");

  auto storage_files = storage_files_manager.GetStorageFiles(*container);
  RETURN_IF_ERROR(storage_files, "Failed to get storage files object");

  auto context = (**storage_files).GetPackageFlagContext(package, flag);
  RETURN_IF_ERROR(context, "Failed to find package flag context");

  auto removed = (**storage_files).RemoveLocalFlagValue(*context);
  RETURN_IF_ERROR(removed, "Failed to remove local override");

  return {};
}

/// Handle override removal request
void HandleLocalOverrideRemoval(
    const StorageRequestMessage::RemoveLocalOverrideMessage& msg,
    StorageReturnMessage& return_msg) {
  auto result = Result<void>();
  if (msg.remove_all()) {
    result = RemoveAllLocalOverrides();
  } else {
    result = RemoveFlagLocalOverride(msg.package_name(), msg.flag_name());
  }

  if (!result.ok()) {
    auto* errmsg = return_msg.mutable_error_message();
    *errmsg = result.error().message();
  } else {
    return_msg.mutable_remove_local_override_message();
  }
}

} // namespace

/// Initialize in memory aconfig storage records
Result<void> InitializeInMemoryStorageRecords() {
  auto records_pb = ReadPbFromFile<storage_records_pb>(kPersistentStorageRecordsFileName);
  RETURN_IF_ERROR(records_pb, "Unable to read persistent storage records");

  for (auto& entry : records_pb->files()) {
    auto storage_record = StorageRecord();
    storage_record.version = entry.version();
    storage_record.container = entry.container();
    storage_record.package_map = entry.package_map();
    storage_record.flag_map = entry.flag_map();
    storage_record.flag_val = entry.flag_val();
    storage_record.flag_info = entry.flag_info();
    storage_record.local_overrides = entry.local_overrides();
    storage_record.timestamp = entry.timestamp();
    storage_files_manager.AddStorageFiles(entry.container(), storage_record);
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

    auto updated = AddOrUpdateStorageForContainer(
        container, package_file, flag_file, value_file);
    RETURN_IF_ERROR(updated, "Failed to add or update storage for container "
                    + container);

    auto copied = CreateBootSnapshotForContainer(container);
    RETURN_IF_ERROR(copied, "Failed to create boot snapshot for container "
                    + container)
  }

  return {};
}

/// Handle incoming messages to aconfigd socket
void HandleSocketRequest(const StorageRequestMessage& message,
                         StorageReturnMessage& return_message) {
  switch (message.msg_case()) {
    case StorageRequestMessage::kNewStorageMessage: {
      auto msg = message.new_storage_message();
      LOG(INFO) << "received a new storage request for " << msg.container()
                << " with storage files " << msg.package_map() << " "
                << msg.flag_map() << " " << msg.flag_value();
      HandleNewStorage(msg, return_message);
      break;
    }
    case StorageRequestMessage::kFlagOverrideMessage: {
      auto msg = message.flag_override_message();
      LOG(INFO) << "received a" << (msg.is_local() ? " local " : " server ")
          << "flag override request for " << msg.package_name() << "/"
          << msg.flag_name() << " to " << msg.flag_value();
      HandleFlagOverride(msg, return_message);
      break;
    }
    case StorageRequestMessage::kFlagQueryMessage: {
      auto msg = message.flag_query_message();
      LOG(INFO) << "received a flag query request for " << msg.package_name()
                << "/" << msg.flag_name();
      HandlePersistFlagQuery(msg, return_message);
      break;
    }
    case StorageRequestMessage::kRemoveLocalOverrideMessage: {
      auto msg = message.remove_local_override_message();
      if (msg.remove_all()) {
        LOG(INFO) << "received a global local override removal request";
      } else {
        LOG(INFO) << "received local override removal request for "
                  << msg.package_name() << "/" << msg.flag_name();
      }
      HandleLocalOverrideRemoval(msg, return_message);
      break;
    }
    default:
      auto* errmsg = return_message.mutable_error_message();
      *errmsg = "Unknown message type from aconfigd socket";
      break;
  }

  if (return_message.has_error_message()) {
    LOG(ERROR) << "Failed to handle socket request: " << return_message.error_message();
  } else {
    LOG(INFO) << "Successfully handled socket request";
  }
}

} // namespace aconfigd
} // namespace android
