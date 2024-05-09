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

#include <vector>
#include <string>
#include <memory>
#include <unordered_map>

#include "storage_files.h"

namespace android {
  namespace aconfigd {
    /// Manager all storage files across different containers
    class StorageFilesManager {
      public:

      /// constructor
      StorageFilesManager() = default;

      /// destructor
      ~StorageFilesManager() = default;

      /// no copy
      StorageFilesManager(const StorageFilesManager&) = delete;
      StorageFilesManager& operator=(const StorageFilesManager&) = delete;

      /// move constructor and assignment
      StorageFilesManager(StorageFilesManager&& rhs) = default;
      StorageFilesManager& operator=(StorageFilesManager&& rhs) = default;

      /// get mapped files for a container
      base::Result<StorageFiles*> GetStorageFiles(const std::string& container);

      /// create mapped files for a container
      base::Result<void> AddNewStorageFiles(const std::string& container,
                                            const std::string& package_map,
                                            const std::string& flag_map,
                                            const std::string& flag_val);

      /// restore storage files object from a storage record pb entry
      base::Result<void> RestoreStorageFiles(
          const aconfig_storage_metadata::storage_file_info& pb);

      /// get container name given flag package name
      base::Result<std::string> GetContainer(const std::string& package);

      /// get all storage records
      std::vector<const StorageRecord*> GetAllStorageRecords();

      /// has container
      bool HasContainer(const std::string& container) {
        return all_storage_files_.count(container);
      }

      /// get all containers
      std::vector<std::string> GetAllContainers();

      /// remove storage record
      bool RemoveContainer(const std::string& container) {
        return all_storage_files_.erase(container);
      }

      private:

      /// a hash table from container name to mapped files
      std::unordered_map<std::string, std::unique_ptr<StorageFiles>> all_storage_files_;

      /// a hash table from package name to container name
      std::unordered_map<std::string, std::string> package_to_container_;

    }; // class StorageFilesManager

  } // namespace aconfigd
} // namespace android
