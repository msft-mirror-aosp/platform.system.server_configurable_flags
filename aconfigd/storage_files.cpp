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

#include <protos/aconfig_storage_metadata.pb.h>
#include <android-base/logging.h>

#include "aconfigd.h"
#include "aconfigd_util.h"
#include "storage_files.h"

using namespace aconfig_storage;

namespace android {
  namespace aconfigd {

  /// constructor
  StorageFiles::StorageFiles(const std::string& container, const StorageRecord& record)
      : container_(container)
      , storage_record_(record)
      , package_map_(nullptr)
      , flag_map_(nullptr)
      , persist_flag_val_(nullptr)
      , persist_flag_info_(nullptr) {
  }

  /// move constructor
  StorageFiles::StorageFiles(StorageFiles&& rhs) {
    if (this != &rhs) {
      *this = std::move(rhs);
    }
  }

  /// move assignment
  StorageFiles& StorageFiles::operator=(StorageFiles&& rhs) {
    if (this != &rhs) {
      container_ = rhs.container_;
      storage_record_ = std::move(rhs.storage_record_);
      package_map_ = std::move(rhs.package_map_);
      flag_map_ = std::move(rhs.flag_map_);
      persist_flag_val_ = std::move(rhs.persist_flag_val_);
      persist_flag_info_ = std::move(rhs.persist_flag_info_);
    }
    return *this;
  }

  /// map a storage file
  base::Result<MappedStorageFile> StorageFiles::MapStorageFile(StorageFileType file_type) {
    switch (file_type) {
      case StorageFileType::package_map:
        if (storage_record_.package_map.empty()) {
          return Error() << "Missing package map file";
        }
        return map_storage_file(storage_record_.package_map);
        break;
      case StorageFileType::flag_map:
        if (storage_record_.flag_map.empty()) {
          return Error() << "Missing flag map file";
        }
        return map_storage_file(storage_record_.flag_map);
        break;
      default:
        return base::Error() << "Unsupported storage file type for MappedStorageFile";
    }
  }

  /// map a mutable storage file
  base::Result<MutableMappedStorageFile> StorageFiles::MapMutableStorageFile(
      StorageFileType file_type) {
    switch (file_type) {
      case StorageFileType::flag_val:
        if (storage_record_.flag_val.empty()) {
          return Error() << "Missing persist flag value file";
        }
        return map_mutable_storage_file(storage_record_.flag_val);
        break;
      case StorageFileType::flag_info:
        if (storage_record_.flag_info.empty()) {
          return Error() << "Missing persist flag info file";
        }
        return map_mutable_storage_file(storage_record_.flag_info);
        break;
      default:
        return base::Error() << "Unsupported storage file type to map";
    }
  }

  /// get package map
  base::Result<const MappedStorageFile*> StorageFiles::GetPackageMap() {
    if (!package_map_) {
      auto package_map = MapStorageFile(StorageFileType::package_map);
      if (!package_map.ok()) {
        return base::Error() << "Failed to map package map file for " << container_
                             << ": " << package_map.error();
      }
      package_map_.reset(new MappedStorageFile(*package_map));
    }
    return package_map_.get();
  }

  /// get flag map
  base::Result<const MappedStorageFile*> StorageFiles::GetFlagMap() {
    if (!flag_map_) {
      auto flag_map = MapStorageFile(StorageFileType::flag_map);
      if (!flag_map.ok()) {
        return base::Error() << "Failed to map flag map file for " << container_
                             << ": " << flag_map.error();
      }
      flag_map_.reset(new MappedStorageFile(*flag_map));
    }
    return flag_map_.get();
  }

  /// get persist flag val
  base::Result<const MutableMappedStorageFile*> StorageFiles::GetPersistFlagVal() {
    if (!persist_flag_val_) {
      auto flag_val = MapMutableStorageFile(StorageFileType::flag_val);
      if (!flag_val.ok()) {
        return base::Error() << "Failed to map persist flag value file for " << container_
                             << ": " << flag_val.error();
      }
      persist_flag_val_.reset(new MutableMappedStorageFile(*flag_val));
    }
    return persist_flag_val_.get();
  }

  /// get persist flag info
  base::Result<const MutableMappedStorageFile*> StorageFiles::GetPersistFlagInfo() {
    if (!persist_flag_info_) {
      auto flag_info = MapMutableStorageFile(StorageFileType::flag_info);
      if (!flag_info.ok()) {
        return base::Error() << "Failed to map persist flag info file for " << container_
                             << ": " << flag_info.error();
      }
      persist_flag_info_.reset(new MutableMappedStorageFile(*flag_info));
    }
    return persist_flag_info_.get();
  }

  /// check if flag is read only
  base::Result<bool> StorageFiles::IsFlagReadOnly(const PackageFlagContext& context) {
    auto flag_info_file = GetPersistFlagInfo();
    if (!flag_info_file.ok()) {
      return base::Error() << flag_info_file.error();
    }

    auto ro_info_file = MappedStorageFile();
    ro_info_file.file_ptr = (*flag_info_file)->file_ptr;
    ro_info_file.file_size = (*flag_info_file)->file_size;
    auto attribute = get_flag_attribute(
        ro_info_file, context.value_type, context.flag_index);

    if (!attribute.ok()) {
      return base::Error() << "Failed to get flag attribute";
    }

    return !(*attribute & FlagInfoBit::IsReadWrite);
  }

  /// set storage record
  void StorageFiles::SetStorageRecord(const StorageRecord& record) {
    storage_record_ = record;
    package_map_.reset(nullptr);
    flag_map_.reset(nullptr);
    persist_flag_val_.reset(nullptr);
    persist_flag_info_.reset(nullptr);
  }

  /// Find flag value type and global index
  base::Result<StorageFiles::PackageFlagContext> StorageFiles::GetPackageFlagContext(
      const std::string& package,
      const std::string& flag) {
    auto result = PackageFlagContext();

    // early return
    if (package.empty()) {
      result.package_exists = false;
      result.flag_exists = false;
      return result;
    }

    // find package context
    auto package_map = GetPackageMap();
    if (!package_map.ok()) {
      return base::Error() << package_map.error();
    }

    auto package_context = get_package_read_context(**package_map, package);
    if (!package_context.ok()) {
      return base::Error() << "Failed to get package context for " << package
                           << " in " << container_  << " :" << package_context.error();
    }

    if (!package_context->package_exists) {
      result.package_exists = false;
      result.flag_exists = false;
      return result;
    } else {
      result.package_exists = true;
    }

    // early return
    if (flag.empty()) {
      return result;
    }

    uint32_t package_id = package_context->package_id;
    uint32_t boolean_flag_start_index = package_context->boolean_start_index;

    // find flag context
    auto flag_map = GetFlagMap();
    if (!flag_map.ok()) {
      return base::Error() << flag_map.error();
    }

    auto flag_context = get_flag_read_context(**flag_map, package_id, flag);
    if (!flag_context.ok()) {
      return base::Error() << "Failed to get flag context of " << package << "/"
                           << flag << " in " << container_  << " :"
                           << flag_context.error();
    }

    if (!flag_context->flag_exists) {
      result.flag_exists = false;
      return result;
    }

    StoredFlagType stored_type = flag_context->flag_type;
    uint16_t within_package_flag_index = flag_context->flag_index;
    auto value_type = map_to_flag_value_type(stored_type);
    if (!value_type.ok()) {
      return base::Error() << "Failed to get flag value type :" << value_type.error();
    }

    result.flag_exists = true;
    result.value_type = *value_type;
    result.flag_index = boolean_flag_start_index + within_package_flag_index;
    return result;
  }

  /// check if has package
  base::Result<bool> StorageFiles::HasPackage(const std::string& package) {
    auto type_and_index = GetPackageFlagContext(package, "");
    if (!type_and_index.ok()) {
      return base::Error() << type_and_index.error();
    }
    return type_and_index->package_exists;
  }

  /// check if has flag
  base::Result<bool> StorageFiles::HasFlag(const std::string& package,
                                           const std::string& flag) {
    auto type_and_index = GetPackageFlagContext(package, flag);
    if (!type_and_index.ok()) {
      return base::Error() << type_and_index.error();
    }
    return type_and_index->flag_exists;
  }


  /// server flag override, update persistent flag value
  base::Result<void> StorageFiles::SetServerFlagValue(const PackageFlagContext& context,
                                                      const std::string& flag_value) {
    if (IsFlagReadOnly(context)) {
      return base::Error() << "Cannot update read only flag";
    }

    auto flag_value_file = GetPersistFlagVal();
    if (!flag_value_file.ok()) {
      return base::Error() << flag_value_file.error();
    }

    switch (context.value_type) {
      case FlagValueType::Boolean: {
        if (flag_value != "true" && flag_value != "false") {
          return base::Error() << "Invalid boolean flag value, it should be true|false";
        }

        auto update_result = set_boolean_flag_value(
            **flag_value_file, context.flag_index, flag_value == "true");
        if (!update_result.ok()) {
          return base::Error() << "Failed to update flag value: " << update_result.error();
        }

        break;
      }
      default:
        return base::Error() << "Unsupported flag value type";
    }

    return {};
  }

  /// set has server override in flag info
  base::Result<void> StorageFiles::SetHasServerOverride(const PackageFlagContext& context,
                                                        bool has_server_override) {
    auto flag_info_file = GetPersistFlagInfo();
    if (!flag_info_file.ok()) {
      return base::Error() << flag_info_file.error();
    }

    auto update_result = set_flag_has_server_override(
        **flag_info_file, context.value_type, context.flag_index, has_server_override);
    if (!update_result.ok()) {
      return base::Error() << "Failed to update flag has server override: "
                           << update_result.error();
    }

    return {};
  }

  /// set has local override in flag info
  base::Result<void> StorageFiles::SetHasLocalOverride(const PackageFlagContext& context,
                                                       bool has_local_override) {
    auto flag_info_file = GetPersistFlagInfo();
    if (!flag_info_file.ok()) {
      return base::Error() << flag_info_file.error();
    }

    auto update_result = set_flag_has_local_override(
        **flag_info_file, context.value_type, context.flag_index, has_local_override);
    if (!update_result.ok()) {
      return base::Error() << "Failed to update flag has local override: "
                           << update_result.error();
    }

    return {};
  }

  /// get persistent flag attribute
  base::Result<uint8_t> StorageFiles::GetPersistFlagAttribute(
      const std::string& package,
      const std::string& flag) {
    // find flag value type and index
    auto type_and_index = GetPackageFlagContext(package, flag);
    if (!type_and_index.ok()) {
      return base::Error() << "Failed to find flag " << flag << ": "
                           << type_and_index.error();
    }
    if (!type_and_index->flag_exists) {
      return base::Error() << "Failed to find flag " << flag;
    }
    auto value_type = type_and_index->value_type;
    auto flag_index = type_and_index->flag_index;

    // get flag attribute
    auto flag_info_file = GetPersistFlagInfo();
    if (!flag_info_file.ok()) {
      return base::Error() << flag_info_file.error();
    }

    auto ro_info_file = MappedStorageFile();
    ro_info_file.file_ptr = (*flag_info_file)->file_ptr;
    ro_info_file.file_size = (*flag_info_file)->file_size;

    auto attribute = get_flag_attribute(ro_info_file, value_type, flag_index);
    if (!attribute.ok()) {
      return base::Error() << "Failed to get flag info: " << attribute.error();
    }

    return *attribute;
  }

  /// get persistent flag value and attribute
  base::Result<std::pair<std::string, uint8_t>> StorageFiles::GetPersistFlagValueAndAttribute(
      const std::string& package,
      const std::string& flag) {

    // find flag value type and index
    auto type_and_index = GetPackageFlagContext(package, flag);
    if (!type_and_index.ok()) {
      return base::Error() << "Failed to find flag " << flag << ": "
                           << type_and_index.error();
    }
    if (!type_and_index->flag_exists) {
      return base::Error() << "Failed to find flag " << flag;
    }
    auto value_type = type_and_index->value_type;
    auto flag_index = type_and_index->flag_index;

    auto flag_value_file = GetPersistFlagVal();
    if (!flag_value_file.ok()) {
      return base::Error() << flag_value_file.error();
    }

    auto flag_info_file = GetPersistFlagInfo();
    if (!flag_info_file.ok()) {
      return base::Error() << flag_info_file.error();
    }

    // return value
    auto flag_value = std::string();
    uint8_t flag_attribute = 0;

    switch (value_type) {
      case FlagValueType::Boolean: {
        // get flag value
        auto ro_value_file = MappedStorageFile();
        ro_value_file.file_ptr = (*flag_value_file)->file_ptr;
        ro_value_file.file_size = (*flag_value_file)->file_size;
        auto value = get_boolean_flag_value(ro_value_file, flag_index);
        if (!value.ok()) {
          return base::Error() << "Failed to get flag value: " << value.error();
        }
        flag_value = *value ? "true" : "false";

        // get flag attribute
        auto ro_info_file = MappedStorageFile();
        ro_info_file.file_ptr = (*flag_info_file)->file_ptr;
        ro_info_file.file_size = (*flag_info_file)->file_size;
        auto attribute = get_flag_attribute(ro_info_file, value_type, flag_index);
        if (!attribute.ok()) {
          return base::Error() << "Failed to get flag info: " << attribute.error();
        }
        flag_attribute = *attribute;

        break;
      }
      default:
        return base::Error() << "Unsupported flag value type";
    }

    return std::make_pair(flag_value, flag_attribute);
  }

  /// apply local update to boot flag value copy
  base::Result<LocalFlagOverrides> StorageFiles::ApplyLocalOverride(
      const std::string& flag_value_file,
      const LocalFlagOverrides& local_overrides) {
    auto applied_overrides = LocalFlagOverrides();
    auto mutable_flag_value_file = map_mutable_storage_file(flag_value_file);
    if (!mutable_flag_value_file.ok()) {
      return base::Error() << "Failed to map flag value file for local override: "
                           << mutable_flag_value_file.error();
    }

    for (auto& entry : local_overrides.overrides()) {

      // find flag value type and index
      auto type_and_index = GetPackageFlagContext(entry.package_name(), entry.flag_name());
      if (!type_and_index.ok()) {
        return base::Error() << "Failed to find flag: " << type_and_index.error();
      }
      if (!type_and_index->flag_exists) {
        continue;
      }

      auto value_type = type_and_index->value_type;
      auto flag_index = type_and_index->flag_index;

      // apply a local override
      switch (value_type) {
        case FlagValueType::Boolean: {
          // validate value
          if (entry.flag_value() != "true" && entry.flag_value() != "false") {
            return base::Error() << "Invalid boolean flag value, it should be true|false";
          }

          // update flag value
          auto update_result = set_boolean_flag_value(
              *mutable_flag_value_file, flag_index, entry.flag_value() == "true");
          if (!update_result.ok()) {
            return base::Error() << "Failed to update flag value: " << update_result.error();
          }

          break;
        }
        default:
          return base::Error() << "Unsupported flag value type";
      }

      // mark it applied
      auto new_applied = applied_overrides.add_overrides();
      new_applied->set_package_name(entry.package_name());
      new_applied->set_flag_name(entry.flag_name());
      new_applied->set_flag_value(entry.flag_value());
    }

    return applied_overrides;
  }

  } // namespace aconfigd
} // namespace android
