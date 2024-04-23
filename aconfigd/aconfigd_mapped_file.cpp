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

#include "aconfigd.h"
#include "aconfigd_util.h"
#include "aconfigd_mapped_file.h"

using namespace aconfig_storage;

namespace android {
  namespace aconfigd {

  /// get mapped files for a container
  MappedFiles& MappedFilesManager::get_mapped_files(
      const std::string& container) {
    if (mapped_files_.count(container) == 0) {
      mapped_files_[container] = std::make_unique<MappedFiles>(container);
    }
    return *(mapped_files_[container]);
  }

  /// get container name given flag package name
  base::Result<std::string> MappedFilesManager::GetContainer(
      const std::string& package) {
    if (package_to_container_.count(package)) {
      return package_to_container_[package];
    }

    auto records_pb = ReadPbFromFile<aconfig_storage_metadata::storage_files>(
        kAvailableStorageRecordsFileName);
    if (!records_pb.ok()) {
      return base::Error() << "Unable to read available storage records: "
                           << records_pb.error();
    }

    for (auto& entry : records_pb->files()) {
      auto& mapped_file = get_mapped_files(entry.container());
      auto has_flag = mapped_file.HasPackage(package);
      if (!has_flag.ok()) {
        return base::Error() << has_flag.error();
      }

      if (*has_flag) {
        package_to_container_[package] = entry.container();
        return entry.container();
      }
    }

    return base::Error() << "container not found";
  }

  /// constructor
  MappedFiles::MappedFiles(const std::string& container)
      : container_(container)
      , package_map_(nullptr)
      , flag_map_(nullptr)
      , persist_flag_val_(nullptr)
      , persist_flag_info_(nullptr) {
  }

  /// move constructor
  MappedFiles::MappedFiles(MappedFiles&& rhs) {
    if (this != &rhs) {
      *this = std::move(rhs);
    }
  }

  /// move assignment
  MappedFiles& MappedFiles::operator=(MappedFiles&& rhs) {
    if (this != &rhs) {
      container_ = rhs.container_;
      package_map_ = std::move(rhs.package_map_);
      flag_map_ = std::move(rhs.flag_map_);
      persist_flag_val_ = std::move(rhs.persist_flag_val_);
      persist_flag_info_ = std::move(rhs.persist_flag_info_);
    }
    return *this;
  }

  /// map a storage file
  base::Result<MappedStorageFile> MappedFiles::MapStorageFile(StorageFileType file_type) {
    switch (file_type) {
      case StorageFileType::package_map:
      case StorageFileType::flag_map:
      case StorageFileType::flag_info:
        return get_mapped_file(container_, file_type);
        break;
      default:
        return base::Error() << "Unsupported storage file type to map";
    }
  }

  /// map a mutable storage file
  base::Result<MutableMappedStorageFile> MappedFiles::MapMutableStorageFile(
      StorageFileType file_type) {
    switch (file_type) {
      case StorageFileType::flag_val:
      case StorageFileType::flag_info:
        return get_mutable_mapped_file(container_, file_type);
        break;
      default:
        return base::Error() << "Unsupported storage file type to map";
    }
  }

  /// get package map
  base::Result<const MappedStorageFile*> MappedFiles::get_package_map() {
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
  base::Result<const MappedStorageFile*> MappedFiles::get_flag_map() {
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
  base::Result<const MutableMappedStorageFile*> MappedFiles::get_persist_flag_val() {
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
  base::Result<const MutableMappedStorageFile*> MappedFiles::get_persist_flag_info() {
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

  /// Find flag value type and global index
  base::Result<MappedFiles::FlagTypeAndIndex> MappedFiles::GetFlagTypeAndIndex(
      const std::string& package,
      const std::string& flag) {
    auto result = FlagTypeAndIndex();

    auto package_map = get_package_map();
    if (!package_map.ok()) {
      return base::Error() << package_map.error();
    }

    auto package_context = get_package_read_context(**package_map, package);
    if (!package_context.ok()) {
      return base::Error() << "Failed to get package context for " << package
                           << " in " << container_  << " :" << package_context.error();
    }

    if (!package_context->package_exists) {
      result.flag_exists = false;
      return result;
    }

    uint32_t package_id = package_context->package_id;
    uint32_t package_start_index = package_context->boolean_start_index;

    auto flag_map = get_flag_map();
    if (!flag_map.ok()) {
      return base::Error() << flag_map.error();
    }

    auto flag_context = get_flag_read_context(**flag_map, package_id, flag);
    if (!flag_context.ok()) {
      return base::Error() << "Failed to get flag context of " << flag
                           << " in " << container_  << " :" << flag_context.error();
    }

    if (!flag_context->flag_exists) {
      result.flag_exists = false;
      return result;
    }

    StoredFlagType stored_type = flag_context->flag_type;
    uint16_t flag_index = flag_context->flag_index;

    auto value_type = map_to_flag_value_type(stored_type);
    if (!value_type.ok()) {
      return base::Error() << "Failed to get flag value type :" << value_type.error();
    }

    result.flag_exists = true;
    result.value_type = *value_type;
    result.flag_index = package_start_index + flag_index;
    return result;
  }

  /// check if has package
  base::Result<bool> MappedFiles::HasPackage(const std::string& package) {
    auto package_map_file = get_package_map();
    if (!package_map_file.ok()) {
      return base::Error() << package_map_file.error();
    }

    auto context= get_package_read_context(**package_map_file, package);
    if (!context.ok()) {
      return base::Error() << "Failed to get context for package " << package
                           << " in container " << container_ << ": " << context.error();
    }

    return context->package_exists;
  }

  /// server flag override, update persistent flag value and info
  base::Result<void> MappedFiles::UpdatePersistFlag(const std::string& package,
                                                    const std::string& flag,
                                                    const std::string& flag_value) {

    // find flag value type and index
    auto type_and_index = GetFlagTypeAndIndex(package, flag);
    if (!type_and_index.ok()) {
      return base::Error() << "Failed to find flag " << flag << ": "
                           << type_and_index.error();
    }
    if (!type_and_index->flag_exists) {
      return base::Error() << "Failed to find flag " << flag;
    }
    auto value_type = type_and_index->value_type;
    auto flag_index = type_and_index->flag_index;

    auto flag_value_file = get_persist_flag_val();
    if (!flag_value_file.ok()) {
      return base::Error() << flag_value_file.error();
    }

    auto flag_info_file = get_persist_flag_info();
    if (!flag_info_file.ok()) {
      return base::Error() << flag_info_file.error();
    }

    switch (value_type) {
      case FlagValueType::Boolean: {
        // validate value
        if (flag_value != "true" && flag_value != "false") {
          return base::Error() << "Invalid boolean flag value, it should be true|false";
        }

        // update flag value
        auto update_result = set_boolean_flag_value(
            **flag_value_file, flag_index, flag_value == "true");
        if (!update_result.ok()) {
          return base::Error() << "Failed to update flag value: " << update_result.error();
        }

        // update flag info
        update_result = set_flag_has_server_override(
            **flag_info_file, value_type, flag_index, true);
        if (!update_result.ok()) {
          return base::Error() << "Failed to update flag has server override: "
                               << update_result.error();
        }
        break;
      }
      default:
        return base::Error() << "Unsupported flag value type";
    }

    return {};
  }

  /// mark this flag has local override
  base::Result<void> MappedFiles::MarkHasLocalOverride(const std::string& package,
                                                       const std::string& flag,
                                                       bool has_local_override) {
    // find flag value type and index
    auto type_and_index = GetFlagTypeAndIndex(package, flag);
    if (!type_and_index.ok()) {
      return base::Error() << "Failed to find flag " << flag << ": "
                           << type_and_index.error();
    }
    if (!type_and_index->flag_exists) {
      return base::Error() << "Failed to find flag " << flag;

    }

    auto value_type = type_and_index->value_type;
    auto flag_index = type_and_index->flag_index;

    auto flag_info_file = get_persist_flag_info();
    if (!flag_info_file.ok()) {
      return base::Error() << flag_info_file.error();
    }

    // update flag info, has local override
    auto update_result = set_flag_has_local_override(
        **flag_info_file, value_type, flag_index, has_local_override);
    if (!update_result.ok()) {
      return base::Error() << "Failed to update flag has local override: " << update_result.error();
    }

    return {};
  }

  /// get persistent flag value and info
  base::Result<std::pair<std::string, uint8_t>> MappedFiles::GetPersistFlagValueAndInfo(
      const std::string& package,
      const std::string& flag) {

    // find flag value type and index
    auto type_and_index = GetFlagTypeAndIndex(package, flag);
    if (!type_and_index.ok()) {
      return base::Error() << "Failed to find flag " << flag << ": "
                           << type_and_index.error();
    }
    if (!type_and_index->flag_exists) {
      return base::Error() << "Failed to find flag " << flag;

    }
    auto value_type = type_and_index->value_type;
    auto flag_index = type_and_index->flag_index;

    auto flag_value_file = get_persist_flag_val();
    if (!flag_value_file.ok()) {
      return base::Error() << flag_value_file.error();
    }

    auto flag_info_file = get_persist_flag_info();
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
  base::Result<LocalFlagOverrides> MappedFiles::ApplyLocalOverride(
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
      auto type_and_index = GetFlagTypeAndIndex(entry.package_name(), entry.flag_name());
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
