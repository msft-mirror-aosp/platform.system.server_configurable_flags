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

#pragma once

#include <string>
#include <memory>
#include <unordered_map>

#include <android-base/result.h>

#include <aconfigd.pb.h>
#include <aconfig_storage/aconfig_storage_read_api.hpp>
#include <aconfig_storage/aconfig_storage_write_api.hpp>

namespace android {
  namespace aconfigd {

    /// Mapped files for a container
    class MappedFiles {
      public:

      /// constructor
      MappedFiles(const std::string& container);

      /// destructor
      ~MappedFiles() = default;

      /// no copy
      MappedFiles(const MappedFiles&) = delete;
      MappedFiles& operator=(const MappedFiles&) = delete;

      /// move constructor and assignment
      MappedFiles(MappedFiles&& rhs);
      MappedFiles& operator=(MappedFiles&& rhs);

      /// check if has package
      base::Result<bool> HasPackage(const std::string& package);

      /// server flag override, update persistent flag value and info
      base::Result<void> UpdatePersistFlag(const std::string& package,
                                           const std::string& flag,
                                           const std::string& value);

      /// mark this flag has local override
      base::Result<void> MarkHasLocalOverride(const std::string& package,
                                              const std::string& flag,
                                              bool has_local_override);

      /// get persistent flag value and info
      base::Result<std::pair<std::string, uint8_t>> GetPersistFlagValueAndInfo(
          const std::string& package,
          const std::string& flag);

      /// apply local update to boot flag value copy, return stale local overrides
      base::Result<LocalFlagOverrides> ApplyLocalOverride(
          const std::string& flag_value_file,
          const LocalFlagOverrides& pb);

      private:

      /// map a storage file
      base::Result<aconfig_storage::MappedStorageFile> MapStorageFile(
          aconfig_storage::StorageFileType file_type);

      /// map a mutable storage file
      base::Result<aconfig_storage::MutableMappedStorageFile> MapMutableStorageFile(
          aconfig_storage::StorageFileType file_type);

      /// get package map
      base::Result<const aconfig_storage::MappedStorageFile*> get_package_map();

      /// get flag map
      base::Result<const aconfig_storage::MappedStorageFile*> get_flag_map();

      /// get persist flag val
      base::Result<const aconfig_storage::MutableMappedStorageFile*> get_persist_flag_val();

      /// get persist flag info
      base::Result<const aconfig_storage::MutableMappedStorageFile*> get_persist_flag_info();

      /// return result for flag type and index query
      struct FlagTypeAndIndex {
        bool flag_exists;
        aconfig_storage::FlagValueType value_type;
        uint32_t flag_index;
      };

      /// Find flag value type and global index
      base::Result<FlagTypeAndIndex> GetFlagTypeAndIndex(
          const std::string& package, const std::string& flag);

      private:

      /// container name
      std::string container_;

      /// mapped package map file
      std::unique_ptr<aconfig_storage::MappedStorageFile> package_map_;

      /// mapped flag map file
      std::unique_ptr<aconfig_storage::MappedStorageFile> flag_map_;

      /// mapped mutable flag value file
      std::unique_ptr<aconfig_storage::MutableMappedStorageFile> persist_flag_val_;

      /// mapped mutable flag info file
      std::unique_ptr<aconfig_storage::MutableMappedStorageFile> persist_flag_info_;

    }; // class MappedFiles

    /// Manager all mapped files across different containers
    class MappedFilesManager {
      public:

      /// constructor
      MappedFilesManager() = default;

      /// destructor
      ~MappedFilesManager() = default;

      /// no copy
      MappedFilesManager(const MappedFilesManager&) = delete;
      MappedFilesManager& operator=(const MappedFilesManager&) = delete;

      /// move constructor and assignment
      MappedFilesManager(MappedFilesManager&& rhs) = default;
      MappedFilesManager& operator=(MappedFilesManager&& rhs) = default;

      /// get mapped files for a container
      MappedFiles& get_mapped_files(const std::string& container);

      /// get container name given flag package name
      base::Result<std::string> GetContainer(const std::string& package);

      private:

      /// a hash table from container name to mapped files
      std::unordered_map<std::string, std::unique_ptr<MappedFiles>> mapped_files_;

      /// a hash table from package name to container name
      std::unordered_map<std::string, std::string> package_to_container_;

    }; // class MappedFilesManager

  } // namespace aconfigd
} // namespace android
