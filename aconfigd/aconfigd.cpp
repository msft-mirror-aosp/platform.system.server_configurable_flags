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

Result<void> ApplyLocalOverridesToBootCopy(const std::string& container,
                                           const std::string& flag_value_file) {
  auto storage_files = storage_files_manager.GetStorageFiles(container);
  if (!storage_files.ok()) {
    return Error() << storage_files.error();
  }

  const auto& override_file = (**storage_files).GetStorageRecord().local_overrides;
  auto overrides_pb = ReadPbFromFile<LocalFlagOverrides>(override_file);
  if (!overrides_pb.ok()) {
    return Error() << "Unable to read local overrides pb: " << overrides_pb.error();
  }

  // change boot flag value file to 0644 to allow write
  if (chmod(flag_value_file.c_str(), 0644) == -1) {
    return base::ErrnoError() << "chmod() failed";
  };

  auto applied_pb = (**storage_files).ApplyLocalOverride(flag_value_file, *overrides_pb);
  if (!applied_pb.ok()) {
    return base::Error() << "Failed to apply local override: " << applied_pb.error();
  }

  // change boot flag value file back to 0444
  if (chmod(flag_value_file.c_str(), 0444) == -1) {
    return base::ErrnoError() << "chmod() failed";
  };

  if (overrides_pb->overrides_size() != applied_pb->overrides_size()) {
    auto result = WritePbToFile<LocalFlagOverrides>(*applied_pb, override_file);
    if (!result.ok()) {
      return base::Error() << result.error();
    }
  }

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
  if (!copy_result.ok()) {
    return Error() << "CopyFile failed for " << src_value_file << " :"
                   << copy_result.error();
  }

  auto apply_result = ApplyLocalOverridesToBootCopy(container, dst_value_file);
  if (!apply_result.ok()) {
    return Error() << "Failed to apply local overrides: " << apply_result.error();
  }

  copy_result = CopyFile(src_info_file, dst_info_file, 0444);
  if (!copy_result.ok()) {
    return Error() << "CopyFile failed for " << src_info_file << " :"
                   << copy_result.error();
  }

  // update available storage records pb
  auto storage_files = storage_files_manager.GetStorageFiles(container);
  if (!storage_files.ok()) {
    return Error() << storage_files.error();
  }
  const auto& record = (**storage_files).GetStorageRecord();

  auto records_pb = ReadPbFromFile<storage_records_pb>(kAvailableStorageRecordsFileName);
  if (!records_pb.ok()) {
    return Error() << "Unable to read available storage records: "
                   << records_pb.error();
  }

  auto* record_pb = records_pb->add_files();
  record_pb->set_version(record.version);
  record_pb->set_container(record.container);
  record_pb->set_package_map(record.package_map);
  record_pb->set_flag_map(record.flag_map);
  record_pb->set_flag_val(dst_value_file);
  record_pb->set_flag_info(dst_info_file);
  record_pb->set_timestamp(record.timestamp);

  auto write_result =  WritePbToFile<storage_records_pb>(
      *records_pb, kAvailableStorageRecordsFileName);
  if (!write_result.ok()) {
    return Error() << "Failed to write available storage records: "
                   << write_result.error();
  }

  return {};
}

/// Add a container storage if not existed, otherwise update if needed
Result<bool> AddOrUpdateStorageForContainer(const std::string& container,
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
  bool new_container = !storage_files_manager.HasContainer(container);
  bool update_existing_container = false;
  if (!new_container) {
    auto storage_files = storage_files_manager.GetStorageFiles(container);
    if (!storage_files.ok()) {
      return Error() << storage_files.error();
    }
    if ((**storage_files).GetStorageRecord().timestamp != *timestamp) {
      update_existing_container = true;
    }
  }

  if (new_container || update_existing_container) {
    // copy flag value file
    auto flags_dir = std::string("/metadata/aconfig/flags/");
    auto target_value_file = flags_dir + container + ".val";
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
      if (!storage_files.ok()) {
        return Error() << storage_files.error();
      }
      (**storage_files).SetStorageRecord(record);
    }

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

  return_msg.mutable_new_storage_message();
}

/// Handle a local flag override request
Result<void> HandleLocalFlagOverride(const std::string& package,
                                     const std::string& flag,
                                     const std::string& flag_value) {
  auto container = storage_files_manager.GetContainer(package);
  if (!container.ok()) {
    return Error() << "Failed to find package " << package << ": "
                     << container.error();
  }

  // check if flag is overridable
  auto storage_files = storage_files_manager.GetStorageFiles(*container);
  if (!storage_files.ok()) {
    return Error() << storage_files.error();
  }

  auto attribute = (**storage_files).GetPersistFlagAttribute(package, flag);
  if (!attribute.ok()) {
    return Error() << "Failed to get flag attribute for " << package << "/" << flag;
  }

  if (!(*attribute & FlagInfoBit::IsReadWrite)) {
    return base::Error() << "Cannot update read only flag " << package << "/" << flag;
  }

  auto pb_file = (**storage_files).GetStorageRecord().local_overrides;
  auto pb = ReadPbFromFile<LocalFlagOverrides>(pb_file);
  if (!pb.ok()) {
    return Error() << "Failed to read pb from " << pb_file << ": " << pb.error();
  }

  bool exist = false;
  for (auto& entry : *(pb->mutable_overrides())) {
    if (entry.package_name() == package && entry.flag_name() == flag) {
      if (entry.flag_value() == flag_value) {
        return {};
      }
      exist = true;
      entry.set_flag_value(flag_value);
      break;
    }
  }

  if (!exist) {
    // add a new override entry to pb
    auto new_override = pb->add_overrides();
    new_override->set_package_name(package);
    new_override->set_flag_name(flag);
    new_override->set_flag_value(flag_value);

    // mark override sticky
    auto update = (**storage_files).MarkHasLocalOverride(package, flag, true);
    if (!update.ok()) {
      return Error() << "Failed to mark flag " << package + "." + flag << " sticky: "
                     << update.error();
    }
  }

  auto write = WritePbToFile<LocalFlagOverrides>(*pb, pb_file);
  if (!write.ok()) {
    return Error() << "Failed to write pb to " << pb_file << ": " << write.error();
  }

  return {};
}

/// Handle a server flag override request
Result<void> HandleServerFlagOverride(const std::string& package,
                                      const std::string& flag,
                                      const std::string& flag_value) {
  auto container = storage_files_manager.GetContainer(package);
  if (!container.ok()) {
      return Error() << "Failed to find package " << package << ": "
                     << container.error();
  }
  auto storage_files = storage_files_manager.GetStorageFiles(*container);
  if (!storage_files.ok()) {
    return Error() << storage_files.error();
  }
  return (**storage_files).UpdatePersistFlag(package, flag, flag_value);
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
    *errmsg = result.error().message();
  } else {
    return_msg.mutable_flag_override_message();
  }
}

/// Handle a flag query request
void HandlePersistFlagQuery(const StorageRequestMessage::FlagQueryMessage& msg,
                            StorageReturnMessage& return_msg) {
  auto container = storage_files_manager.GetContainer(msg.package_name());
  if (!container.ok()) {
    auto* errmsg = return_msg.mutable_error_message();
    *errmsg = "Failed to find package " + msg.package_name() + ": "
              + container.error().message();
    return;
  }

  // get flag local override value if local override exists
  auto storage_files = storage_files_manager.GetStorageFiles(*container);
  if (!storage_files.ok()) {
    auto* errmsg = return_msg.mutable_error_message();
    *errmsg = storage_files.error().message();
    return;
  }
  auto const& entry = (**storage_files).GetStorageRecord();
  auto overrides_pb = ReadPbFromFile<LocalFlagOverrides>(entry.local_overrides);
  if (!overrides_pb.ok()) {
    auto* errmsg = return_msg.mutable_error_message();
    *errmsg = "Unable to read local overrides pb: " + overrides_pb.error().message();
    return;
  }

  auto local_override_value = std::string();
  for (auto& entry : overrides_pb->overrides()) {
    if (msg.package_name() == entry.package_name()
        && msg.flag_name() == entry.flag_name()) {
      local_override_value = entry.flag_value();
    }
  }

  // get flag server override value
  auto result = (**storage_files).GetPersistFlagValueAndAttribute(
      msg.package_name(), msg.flag_name());

  if (!result.ok()) {
    auto* errmsg = return_msg.mutable_error_message();
    *errmsg = result.error().message();
  } else {
    auto result_msg = return_msg.mutable_flag_query_message();
    result_msg->set_server_flag_value(result->first);
    result_msg->set_local_flag_value(local_override_value);
    result_msg->set_has_server_override(result->second & FlagInfoBit::HasServerOverride);
    result_msg->set_is_readwrite(result->second & FlagInfoBit::IsReadWrite);
    result_msg->set_has_local_override(result->second & FlagInfoBit::HasLocalOverride);
  }
}

/// Remove all local overrides
Result<void> RemoveAllLocalOverrides() {
  for (auto const& record : storage_files_manager.GetAllStorageRecords()) {
    auto overrides_pb = ReadPbFromFile<LocalFlagOverrides>(record->local_overrides);
    if (!overrides_pb.ok()) {
      return Error() << "Unable to read local overrides pb: " << overrides_pb.error();
    }

    auto storage_files = storage_files_manager.GetStorageFiles(record->container);
    if (!storage_files.ok()) {
      return storage_files.error();
    }

    for (auto& entry : overrides_pb->overrides()) {
      auto update = (**storage_files).MarkHasLocalOverride(
          entry.package_name(), entry.flag_name(), false);
      if (!update.ok()) {
        return Error() << "Failed to mark flag " << entry.package_name() + "." +
            entry.flag_name() << " sticky: " << update.error();
      }
    }

    if (unlink(record->local_overrides.c_str()) == -1) {
      return ErrnoError() << "unlink() failed for " << record->local_overrides;
    }
  }

  return {};
}

/// Remove a local override
Result<void> RemoveFlagLocalOverride(const std::string& package,
                                     const std::string& flag) {
  auto container = storage_files_manager.GetContainer(package);
  if (!container.ok()) {
      return Error() << "Failed to find package " << package << ": "
                     << container.error();
  }

  auto storage_files = storage_files_manager.GetStorageFiles(*container);
  if (!storage_files.ok()) {
    return storage_files.error();
  }
  const auto& record = (**storage_files).GetStorageRecord();
  auto overrides_pb = ReadPbFromFile<LocalFlagOverrides>(record.local_overrides);
  if (!overrides_pb.ok()) {
    return Error() << "Unable to read local overrides pb: " << overrides_pb.error();
  }

  auto updated_overrides = LocalFlagOverrides();
  for (auto entry : overrides_pb->overrides()) {
    if (entry.package_name() == package && entry.flag_name() == flag) {
      auto update = (**storage_files).MarkHasLocalOverride(
          entry.package_name(), entry.flag_name(), false);
      if (!update.ok()) {
        return Error() << "Failed to mark flag " << entry.package_name() + "." +
            entry.flag_name() << " sticky: " << update.error();
      }
      continue;
    }
    auto kept_override = updated_overrides.add_overrides();
    kept_override->set_package_name(entry.package_name());
    kept_override->set_flag_name(entry.flag_name());
    kept_override->set_flag_value(entry.flag_value());
  }

  if (updated_overrides.overrides_size() != overrides_pb->overrides_size()) {
    auto result = WritePbToFile<LocalFlagOverrides>(
        updated_overrides, record.local_overrides);
    if (!result.ok()) {
      return base::Error() << result.error();
    }
  }

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
  if (!records_pb.ok()) {
    return Error() << "Unable to read persistent storage records: "
                   << records_pb.error();
  }

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

    if (!FileNonZeroSize(value_file)) {
      continue;
    }

    auto updated = AddOrUpdateStorageForContainer(
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
      HandleNewStorage(msg, return_message);
      break;
    }
    case StorageRequestMessage::kFlagOverrideMessage: {
      LOG(INFO) << "received a flag override request";
      auto msg = message.flag_override_message();
      HandleFlagOverride(msg, return_message);
      break;
    }
    case StorageRequestMessage::kFlagQueryMessage: {
      LOG(INFO) << "received a flag query request";
      auto msg = message.flag_query_message();
      HandlePersistFlagQuery(msg, return_message);
      break;
    }
    case StorageRequestMessage::kRemoveLocalOverrideMessage: {
      LOG(INFO) << "received a local override removal request";
      auto msg = message.remove_local_override_message();
      HandleLocalOverrideRemoval(msg, return_message);
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
