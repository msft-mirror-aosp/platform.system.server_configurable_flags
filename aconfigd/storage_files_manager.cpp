
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
#include "storage_files_manager.h"

using namespace aconfig_storage;

namespace android {
  namespace aconfigd {

  /// get storage files object for a container
  Result<StorageFiles*> StorageFilesManager::GetStorageFiles(
      const std::string& container) {
    if (all_storage_files_.count(container) == 0) {
      return Error() << "Missing storage files object for " << container;
    }
    return all_storage_files_[container].get();
  }

  /// create mapped files for a container
  void StorageFilesManager::AddStorageFiles(const std::string& container,
                                            const StorageRecord& record) {
      all_storage_files_[container] = std::make_unique<StorageFiles>(container, record);
  }

  /// get container name given flag package name
  base::Result<std::string> StorageFilesManager::GetContainer(
      const std::string& package) {
    if (package_to_container_.count(package)) {
      return package_to_container_[package];
    }

    // check available storage records
    auto records_pb = ReadPbFromFile<aconfig_storage_metadata::storage_files>(
        kAvailableStorageRecordsFileName);
    if (!records_pb.ok()) {
      return base::Error() << "Unable to read available storage records: "
                           << records_pb.error();
    }

    for (auto& entry : records_pb->files()) {
      auto storage_files = GetStorageFiles(entry.container());
      if (!storage_files.ok()) {
        return base::Error() << storage_files.error();
      }
      auto has_flag = (**storage_files).HasPackage(package);
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

  /// Get all storage records
  std::vector<const StorageRecord*> StorageFilesManager::GetAllStorageRecords() {
    auto all_records = std::vector<const StorageRecord*>();
    for (auto const& [container, files_ptr] : all_storage_files_) {
      all_records.push_back(&(files_ptr->GetStorageRecord()));
    }
    return all_records;
  }

  } // namespace aconfigd
} // namespace android
