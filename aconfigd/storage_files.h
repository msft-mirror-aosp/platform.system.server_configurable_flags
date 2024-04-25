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

#include <android-base/result.h>

#include <aconfigd.pb.h>
#include <aconfig_storage/aconfig_storage_read_api.hpp>
#include <aconfig_storage/aconfig_storage_write_api.hpp>

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
      std::string local_overrides;
      int timestamp;
    };

    /// Mapped files for a container
    class StorageFiles {
      public:

      /// constructor
      StorageFiles(const std::string& container, const StorageRecord& record);

      /// destructor
      ~StorageFiles() = default;

      /// no copy
      StorageFiles(const StorageFiles&) = delete;
      StorageFiles& operator=(const StorageFiles&) = delete;

      /// move constructor and assignment
      StorageFiles(StorageFiles&& rhs);
      StorageFiles& operator=(StorageFiles&& rhs);

      /// get storage record
      const StorageRecord& GetStorageRecord() {
        return storage_record_;
      }

      /// set storage record
      void SetStorageRecord(const StorageRecord& record) {
        storage_record_ = record;
      }

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

      /// get persistent flag attribute
      base::Result<uint8_t> GetPersistFlagAttribute(const std::string& package,
                                                    const std::string& flag);


      /// get persistent flag value and attribute
      base::Result<std::pair<std::string, uint8_t>> GetPersistFlagValueAndAttribute(
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
      base::Result<const aconfig_storage::MappedStorageFile*> GetPackageMap();

      /// get flag map
      base::Result<const aconfig_storage::MappedStorageFile*> GetFlagMap();

      /// get persist flag val
      base::Result<const aconfig_storage::MutableMappedStorageFile*> GetPersistFlagVal();

      /// get persist flag info
      base::Result<const aconfig_storage::MutableMappedStorageFile*> GetPersistFlagInfo();

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

      // storage record for current container
      StorageRecord storage_record_;

      /// mapped package map file
      std::unique_ptr<aconfig_storage::MappedStorageFile> package_map_;

      /// mapped flag map file
      std::unique_ptr<aconfig_storage::MappedStorageFile> flag_map_;

      /// mapped mutable flag value file
      std::unique_ptr<aconfig_storage::MutableMappedStorageFile> persist_flag_val_;

      /// mapped mutable flag info file
      std::unique_ptr<aconfig_storage::MutableMappedStorageFile> persist_flag_info_;

    }; // class StorageFiles

  } // namespace aconfigd
} // namespace android
