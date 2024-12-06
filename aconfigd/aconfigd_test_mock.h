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
#include <android-base/file.h>

#include "aconfigd.h"
#include "aconfigd_util.h"

namespace android {
namespace aconfigd {

struct AconfigdMock {
  TemporaryDir root_dir;
  const std::string flags_dir;
  const std::string maps_dir;
  const std::string boot_dir;
  const std::string persist_pb;
  Aconfigd aconfigd;

  AconfigdMock()
      : root_dir()
      , flags_dir(std::string(root_dir.path) + "/flags")
      , maps_dir(std::string(root_dir.path) + "/maps")
      , boot_dir(std::string(root_dir.path) + "/boot")
      , persist_pb(std::string(root_dir.path) + "/persist.pb")
      , aconfigd(root_dir.path, persist_pb) {
    mkdir(flags_dir.c_str(), 0770);
    mkdir(maps_dir.c_str(), 0770);
    mkdir(boot_dir.c_str(), 0775);
  }

  base::Result<StorageReturnMessage> SendRequestToSocket(
      const StorageRequestMessage& request) {
    auto return_msg = StorageReturnMessage();
    auto result = aconfigd.HandleSocketRequest(request, return_msg);
    if (!result.ok()) {
      return base::Error() << result.error();
    } else {
      return return_msg;
    }
  }
};

struct ContainerMock {
  TemporaryDir root_dir;
  const std::string container;
  const std::string package_map;
  const std::string flag_map;
  const std::string flag_val;
  const std::string flag_info;

  ContainerMock(const std::string& container_name,
                const std::string& package_map_file,
                const std::string& flag_map_file,
                const std::string& flag_val_file,
                const std::string& flag_info_file)
      : root_dir()
      , container(container_name)
      , package_map(std::string(root_dir.path) + "/etc/aconfig/package.map")
      , flag_map(std::string(root_dir.path) + "/etc/aconfig/flag.map")
      , flag_val(std::string(root_dir.path) + "/etc/aconfig/flag.val")
      , flag_info(std::string(root_dir.path) + "/etc/aconfig/flag.info") {
    auto etc_dir = std::string(root_dir.path) + "/etc";
    auto aconfig_dir = etc_dir + "/aconfig";
    mkdir(etc_dir.c_str(), 0777);
    mkdir(aconfig_dir.c_str(), 0777);
    CopyFile(package_map_file, package_map, 0444);
    CopyFile(flag_map_file, flag_map, 0444);
    CopyFile(flag_val_file, flag_val, 0444);
    CopyFile(flag_info_file, flag_info, 0444);
  }

  void UpdateFiles(const std::string& package_map_file,
                   const std::string& flag_map_file,
                   const std::string& flag_val_file,
                   const std::string& flag_info_file) {
    CopyFile(package_map_file, package_map, 0444);
    CopyFile(flag_map_file, flag_map, 0444);
    CopyFile(flag_val_file, flag_val, 0444);
    CopyFile(flag_info_file, flag_info, 0444);
  }
};

} // namespace aconfigd
} // namespace android
