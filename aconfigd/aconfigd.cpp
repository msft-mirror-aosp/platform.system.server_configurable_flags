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

#include "aconfigd.h"

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <dirent.h>

#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "aconfigd_util.h"
#include "storage_files_manager.h"

using namespace android::base;

namespace android {
namespace aconfigd {

/// Handle a flag override request
Result<void> Aconfigd::HandleFlagOverride(
    const StorageRequestMessage::FlagOverrideMessage& msg,
    StorageReturnMessage& return_msg) {
  auto result = storage_files_manager_->UpdateFlagValue(
      msg.package_name(), msg.flag_name(), msg.flag_value(),
      msg.override_type());
  RETURN_IF_ERROR(result, "Failed to set flag override");
  return_msg.mutable_flag_override_message();
  return {};
}

/// Handle ota flag staging request
Result<void> Aconfigd::HandleOTAStaging(
    const StorageRequestMessage::OTAFlagStagingMessage& msg,
    StorageReturnMessage& return_msg) {
  auto ota_flags_pb_file = root_dir_ + "/flags/ota.pb";
  auto stored_pb_result =
      ReadPbFromFile<StorageRequestMessage::OTAFlagStagingMessage>(
          ota_flags_pb_file);

  if (!stored_pb_result.ok() ||
      (msg.build_id() != (*stored_pb_result).build_id())) {
    LOG(INFO) << "discarding staged flags from " +
                     (*stored_pb_result).build_id() +
                     "; staging new flags for " + msg.build_id();
    auto result = WritePbToFile<StorageRequestMessage::OTAFlagStagingMessage>(
        msg, ota_flags_pb_file);
    RETURN_IF_ERROR(result, "Failed to stage OTA flags");
    return_msg.mutable_ota_staging_message();
    return {};
  }

  std::set<std::string> qualified_names;

  std::map<std::string, android::aconfigd::FlagOverride> new_name_to_override;
  for (const auto& flag_override : msg.overrides()) {
    auto qualified_name =
        flag_override.package_name() + "." + flag_override.flag_name();
    new_name_to_override[qualified_name] = flag_override;

    qualified_names.insert(qualified_name);
  }

  std::map<std::string, android::aconfigd::FlagOverride> prev_name_to_override;
  for (const auto& flag_override : (*stored_pb_result).overrides()) {
    auto qualified_name =
        flag_override.package_name() + "." + flag_override.flag_name();
    prev_name_to_override[qualified_name] = flag_override;

    qualified_names.insert(qualified_name);
  }

  std::vector<android::aconfigd::FlagOverride> overrides;
  for (const auto& qualified_name : qualified_names) {
    if (new_name_to_override.contains(qualified_name)) {
      overrides.push_back(new_name_to_override[qualified_name]);
    } else {
      overrides.push_back(prev_name_to_override[qualified_name]);
    }
  }

  StorageRequestMessage::OTAFlagStagingMessage message_to_persist;
  message_to_persist.set_build_id(msg.build_id());
  for (const auto& flag_override : overrides) {
    auto override_ = message_to_persist.add_overrides();
    override_->set_flag_name(flag_override.flag_name());
    override_->set_package_name(flag_override.package_name());
    override_->set_flag_value(flag_override.flag_value());
  }

  auto result = WritePbToFile<StorageRequestMessage::OTAFlagStagingMessage>(
      message_to_persist, ota_flags_pb_file);
  RETURN_IF_ERROR(result, "Failed to stage OTA flags");
  return_msg.mutable_ota_staging_message();
  return {};
}

/// Handle new storage request
Result<void> Aconfigd::HandleNewStorage(
    const StorageRequestMessage::NewStorageMessage& msg,
    StorageReturnMessage& return_msg) {
  auto updated = storage_files_manager_->AddOrUpdateStorageFiles(
      msg.container(), msg.package_map(), msg.flag_map(), msg.flag_value(),
      msg.flag_info());
  RETURN_IF_ERROR(updated, "Failed to add or update container");

  auto write_result = storage_files_manager_->WritePersistStorageRecordsToFile(
      persist_storage_records_);
  RETURN_IF_ERROR(write_result, "Failed to write to persist storage records");

  auto copy = storage_files_manager_->CreateStorageBootCopy(msg.container());
  RETURN_IF_ERROR(copy, "Failed to make a boot copy for " + msg.container());

  auto result_msg = return_msg.mutable_new_storage_message();
  result_msg->set_storage_updated(*updated);
  return {};
}

/// Handle a flag query request
Result<void> Aconfigd::HandleFlagQuery(
    const StorageRequestMessage::FlagQueryMessage& msg,
    StorageReturnMessage& return_msg) {
  auto snapshot = storage_files_manager_->ListFlag(msg.package_name(), msg.flag_name());
  RETURN_IF_ERROR(snapshot, "Failed query failed");
  auto result_msg = return_msg.mutable_flag_query_message();
  result_msg->set_package_name(snapshot->package_name);
  result_msg->set_flag_name(snapshot->flag_name);
  result_msg->set_server_flag_value(snapshot->server_flag_value);
  result_msg->set_local_flag_value(snapshot->local_flag_value);
  result_msg->set_boot_flag_value(snapshot->boot_flag_value);
  result_msg->set_default_flag_value(snapshot->default_flag_value);
  result_msg->set_has_server_override(snapshot->has_server_override);
  result_msg->set_is_readwrite(snapshot->is_readwrite);
  result_msg->set_has_local_override(snapshot->has_local_override);
  return {};
}

/// Handle override removal request
Result<void> Aconfigd::HandleLocalOverrideRemoval(
    const StorageRequestMessage::RemoveLocalOverrideMessage& msg,
    StorageReturnMessage& return_msg) {
  auto result = Result<void>();
  if (msg.remove_all()) {
    result = storage_files_manager_->RemoveAllLocalOverrides();
  } else {
    result = storage_files_manager_->RemoveFlagLocalOverride(
        msg.package_name(), msg.flag_name());
  }
  RETURN_IF_ERROR(result, "");
  return_msg.mutable_remove_local_override_message();
  return {};
}

/// Handle storage reset
Result<void> Aconfigd::HandleStorageReset(StorageReturnMessage& return_msg) {
  auto result = storage_files_manager_->ResetAllStorage();
  RETURN_IF_ERROR(result, "Failed to reset all storage");

  result = storage_files_manager_->WritePersistStorageRecordsToFile(
      persist_storage_records_);
  RETURN_IF_ERROR(result, "Failed to write persist storage records");

  return_msg.mutable_reset_storage_message();
  return {};
}

/// Handle list storage
Result<void> Aconfigd::HandleListStorage(
    const StorageRequestMessage::ListStorageMessage& msg,
    StorageReturnMessage& return_message) {
  auto flags = Result<std::vector<StorageFiles::FlagSnapshot>>();
  switch (msg.msg_case()) {
    case StorageRequestMessage::ListStorageMessage::kAll: {
      flags = storage_files_manager_->ListAllAvailableFlags();
      break;
    }
    case StorageRequestMessage::ListStorageMessage::kContainer: {
      flags = storage_files_manager_->ListFlagsInContainer(msg.container());
      break;
    }
    case StorageRequestMessage::ListStorageMessage::kPackageName: {
      flags = storage_files_manager_->ListFlagsInPackage(msg.package_name());
      break;
    }
    default:
      return Error() << "Unknown list storage message type from aconfigd socket";
  }
  RETURN_IF_ERROR(flags, "Failed to list flags");

  auto* result_msg = return_message.mutable_list_storage_message();
  for (const auto& flag : *flags) {
    auto* flag_msg = result_msg->add_flags();
    flag_msg->set_package_name(flag.package_name);
    flag_msg->set_flag_name(flag.flag_name);
    flag_msg->set_server_flag_value(flag.server_flag_value);
    flag_msg->set_local_flag_value(flag.local_flag_value);
    flag_msg->set_boot_flag_value(flag.boot_flag_value);
    flag_msg->set_default_flag_value(flag.default_flag_value);
    flag_msg->set_is_readwrite(flag.is_readwrite);
    flag_msg->set_has_server_override(flag.has_server_override);
    flag_msg->set_has_local_override(flag.has_local_override);
  }
  return {};
}

/// Read OTA flag overrides to be applied for current build
Result<std::vector<FlagOverride>> Aconfigd::ReadOTAFlagOverridesToApply() {
  auto ota_flags = std::vector<FlagOverride>();
  auto ota_flags_pb_file = root_dir_ + "/flags/ota.pb";
  if (FileExists(ota_flags_pb_file)) {
    auto build_id = GetProperty("ro.build.fingerprint", "");
    auto ota_flags_pb = ReadPbFromFile<StorageRequestMessage::OTAFlagStagingMessage>(
        ota_flags_pb_file);
    RETURN_IF_ERROR(ota_flags_pb, "Failed to read ota flags from pb file");
    if (ota_flags_pb->build_id() == build_id) {
      for (const auto& entry : ota_flags_pb->overrides()) {
        ota_flags.push_back(entry);
      }
      // delete staged ota flags file if it matches current build id, so that
      // it will not be reapplied in the future boots
      unlink(ota_flags_pb_file.c_str());
    }
  }
  return ota_flags;
}

/// Initialize in memory aconfig storage records
Result<void> Aconfigd::InitializeInMemoryStorageRecords() {
  auto records_pb = ReadPbFromFile<PersistStorageRecords>(persist_storage_records_);
  RETURN_IF_ERROR(records_pb, "Unable to read persistent storage records");
  for (const auto& entry : records_pb->records()) {
    storage_files_manager_->RestoreStorageFiles(entry);
  }
  return {};
}

/// Initialize platform RO partition flag storage
Result<void> Aconfigd::InitializePlatformStorage() {
  auto init_result = InitializeInMemoryStorageRecords();
  RETURN_IF_ERROR(init_result, "Failed to init from persist stoage records");

  auto remove_result = RemoveFilesInDir(root_dir_ + "/boot");
  RETURN_IF_ERROR(remove_result, "Failed to clean boot dir");

  auto ota_flags = ReadOTAFlagOverridesToApply();
  RETURN_IF_ERROR(ota_flags, "Failed to get remaining staged OTA flags");
  bool apply_ota_flag = !(ota_flags->empty());

  auto partitions = std::vector<std::pair<std::string, std::string>>{
    {"system", "/system/etc/aconfig"},
    {"vendor", "/vendor/etc/aconfig"},
    {"product", "/product/etc/aconfig"}};

  for (auto const& [container, storage_dir] : partitions) {
    auto package_file = std::string(storage_dir) + "/package.map";
    auto flag_file = std::string(storage_dir) + "/flag.map";
    auto value_file = std::string(storage_dir) + "/flag.val";
    auto info_file = std::string(storage_dir) + "/flag.info";

    if (!FileNonZeroSize(value_file)) {
      continue;
    }

    auto updated = storage_files_manager_->AddOrUpdateStorageFiles(
        container, package_file, flag_file, value_file, info_file);
    RETURN_IF_ERROR(updated, "Failed to add or update storage for container "
                    + container);

    if (apply_ota_flag) {
      ota_flags = storage_files_manager_->ApplyOTAFlagsForContainer(
          container, *ota_flags);
      RETURN_IF_ERROR(ota_flags, "Failed to apply staged OTA flags");
    }

    auto write_result = storage_files_manager_->WritePersistStorageRecordsToFile(
        persist_storage_records_);
    RETURN_IF_ERROR(write_result, "Failed to write to persist storage records");

    auto copied = storage_files_manager_->CreateStorageBootCopy(container);
    RETURN_IF_ERROR(copied, "Failed to create boot snapshot for container "
                    + container);
  }

  // TODO remove this logic once new storage launch complete
  // if flag enable_only_new_storage is true, writes a marker file
  {
    auto flags = storage_files_manager_->ListFlagsInPackage("com.android.aconfig.flags");
    RETURN_IF_ERROR(flags, "Failed to list flags");
    bool enable_only_new_storage = false;
    for (const auto& flag : *flags) {
      if (flag.flag_name == "enable_only_new_storage") {
        enable_only_new_storage = (flag.boot_flag_value == "true");
        break;
      }
    }
    auto marker_file = std::string("/metadata/aconfig/boot/enable_only_new_storage");
    if (enable_only_new_storage) {
      if (!FileExists(marker_file)) {
        int fd = open(marker_file.c_str(), O_CREAT, 0644);
        if (fd == -1) {
          return ErrnoError() << "failed to create marker file";
        }
        close(fd);
      }
    } else {
      if (FileExists(marker_file)) {
        unlink(marker_file.c_str());
      }
    }
  }

  return {};
}

/// Initialize mainline flag storage
Result<void> Aconfigd::InitializeMainlineStorage() {
  auto init_result = InitializeInMemoryStorageRecords();
  RETURN_IF_ERROR(init_result, "Failed to init from persist stoage records");

  auto apex_dir = std::unique_ptr<DIR, int (*)(DIR*)>(opendir("/apex"), closedir);
  if (!apex_dir) {
    return {};
  }

  struct dirent* entry;
  while ((entry = readdir(apex_dir.get())) != nullptr) {
    if (entry->d_type != DT_DIR) continue;

    auto container = std::string(entry->d_name);
    if (container[0] == '.') continue;
    if (container.find('@') != std::string::npos) continue;
    if (container == "sharedlibs") continue;

    auto storage_dir = std::string("/apex/") + container + "/etc";
    auto package_file = std::string(storage_dir) + "/package.map";
    auto flag_file = std::string(storage_dir) + "/flag.map";
    auto value_file = std::string(storage_dir) + "/flag.val";
    auto info_file = std::string(storage_dir) + "/flag.info";

    if (!FileExists(value_file) || !FileNonZeroSize(value_file)) {
      continue;
    }

    auto updated = storage_files_manager_->AddOrUpdateStorageFiles(
        container, package_file, flag_file, value_file, info_file);
    RETURN_IF_ERROR(updated, "Failed to add or update storage for container "
                    + container);

    auto write_result = storage_files_manager_->WritePersistStorageRecordsToFile(
        persist_storage_records_);
    RETURN_IF_ERROR(write_result, "Failed to write to persist storage records");

    auto copied = storage_files_manager_->CreateStorageBootCopy(container);
    RETURN_IF_ERROR(copied, "Failed to create boot snapshot for container "
                    + container);
  }

  return {};
}

/// Handle incoming messages to aconfigd socket
Result<void> Aconfigd::HandleSocketRequest(const StorageRequestMessage& message,
                                           StorageReturnMessage& return_message) {
  auto result = Result<void>();

  switch (message.msg_case()) {
    case StorageRequestMessage::kNewStorageMessage: {
      auto msg = message.new_storage_message();
      LOG(INFO) << "received a new storage request for " << msg.container()
                << " with storage files " << msg.package_map() << " "
                << msg.flag_map() << " " << msg.flag_value();
      result = HandleNewStorage(msg, return_message);
      break;
    }
    case StorageRequestMessage::kFlagOverrideMessage: {
      auto msg = message.flag_override_message();
      LOG(INFO) << "received a '" << OverrideTypeToStr(msg.override_type())
                << "' flag override request for " << msg.package_name() << "/"
                << msg.flag_name() << " to " << msg.flag_value();
      result = HandleFlagOverride(msg, return_message);
      break;
    }
    case StorageRequestMessage::kOtaStagingMessage: {
      auto msg = message.ota_staging_message();
      LOG(INFO) << "received ota flag staging requests for " << msg.build_id();
      result = HandleOTAStaging(msg, return_message);
      break;
    }
    case StorageRequestMessage::kFlagQueryMessage: {
      auto msg = message.flag_query_message();
      LOG(INFO) << "received a flag query request for " << msg.package_name()
                << "/" << msg.flag_name();
      result = HandleFlagQuery(msg, return_message);
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
      result = HandleLocalOverrideRemoval(msg, return_message);
      break;
    }
    case StorageRequestMessage::kResetStorageMessage: {
      LOG(INFO) << "received reset storage request";
      result = HandleStorageReset(return_message);
      break;
    }
    case StorageRequestMessage::kListStorageMessage: {
      auto msg = message.list_storage_message();
      LOG(INFO) << "received list storage request";
      result = HandleListStorage(msg, return_message);
      break;
    }
    default:
      result = Error() << "Unknown message type from aconfigd socket";
      break;
  }

  return result;
}

} // namespace aconfigd
} // namespace android
