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
#include <aconfig_storage/aconfig_storage_file.hpp>
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
      uint64_t timestamp;
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
      void SetStorageRecord(const StorageRecord& record);

      /// return result for package and flag context
      struct PackageFlagContext {
        const std::string& package;
        const std::string& flag;
        bool package_exists;
        bool flag_exists;
        aconfig_storage::FlagValueType value_type;
        uint32_t flag_index;

        PackageFlagContext(const std::string& package_name,
                           const std::string& flag_name)
            : package(package_name)
            , flag(flag_name)
            , package_exists(false)
            , flag_exists(false)
            , value_type()
            , flag_index()
        {}
      };

      /// Find package and flag context
      base::Result<PackageFlagContext> GetPackageFlagContext(
          const std::string& package, const std::string& flag);

      /// check if has package
      base::Result<bool> HasPackage(const std::string& package);

      /// check if has flag
      base::Result<bool> HasFlag(const std::string& package,
                                 const std::string& flag);

      /// get persistent flag attribute
      base::Result<uint8_t> GetFlagAttribute(const PackageFlagContext& context);

      /// get server or default flag value
      base::Result<std::string> GetServerFlagValue(const PackageFlagContext& context);

      /// get local flag value, will error if local flag value does not exist
      base::Result<std::string> GetLocalFlagValue(const PackageFlagContext& context);

      /// server flag override, update persistent flag value
      base::Result<void> SetServerFlagValue(const PackageFlagContext& context,
                                            const std::string& flag_value);

      /// local flag override, update local flag override pb filee
      base::Result<void> SetLocalFlagValue(const PackageFlagContext& context,
                                           const std::string& flag_value);

      /// set has server override in flag info
      base::Result<void> SetHasServerOverride(const PackageFlagContext& context,
                                              bool has_server_override);

      /// set has local override in flag info
      base::Result<void> SetHasLocalOverride(const PackageFlagContext& context,
                                             bool has_local_override);

      /// remove a single flag local override, return if removed
      base::Result<bool> RemoveLocalFlagValue(const PackageFlagContext& context);

      /// remove all local overrides
      base::Result<void> RemoveAllLocalFlagValue();

      /// apply local update to boot flag value copy, return stale local overrides
      base::Result<void> ApplyLocalOverride(const std::string& flag_value_file);

      /// get all current server override
      base::Result<std::vector<aconfig_storage::FlagValueAndInfoSummary>>
          GetAllServerOverrides();

      /// reset mapped files
      void resetMappedFiles();

      private:

      /// map a storage file
      base::Result<aconfig_storage::MappedStorageFile*> MapStorageFile(
          aconfig_storage::StorageFileType file_type);

      /// map a mutable storage file
      base::Result<aconfig_storage::MutableMappedStorageFile*> MapMutableStorageFile(
          aconfig_storage::StorageFileType file_type);

      /// get package map
      base::Result<const aconfig_storage::MappedStorageFile*> GetPackageMap();

      /// get flag map
      base::Result<const aconfig_storage::MappedStorageFile*> GetFlagMap();

      /// get persist flag val
      base::Result<const aconfig_storage::MutableMappedStorageFile*> GetPersistFlagVal();

      /// get persist flag info
      base::Result<const aconfig_storage::MutableMappedStorageFile*> GetPersistFlagInfo();

      /// check if flag is read only
      base::Result<bool> IsFlagReadOnly(const PackageFlagContext& context);

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
