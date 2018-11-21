/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <server_configurable_flags/disaster_recovery.h>
#include <server_configurable_flags/get_flags.h>
#include <string>

#include "android-base/logging.h"

int main(int argc, char**) {
  if (argc != 1) {
    LOG(ERROR) << "argc: " << std::to_string(argc) << ", it should only be 1.";
    return 1;
  }

  // Reading flags is only for E2E testing in droidfood. Flags_health_check
  // should always be enabled in release.
  // Code for reading the flag will be removed before release.
  // tracking bug: b/119627143
  std::string flag_value = server_configurable_flags::GetServerConfigurableFlag(
      "global_settings", "native_flags_health_check_enabled", "1");
  if (flag_value == "1") {
    LOG(INFO) << "Starting server configurable flags health check.";
    server_configurable_flags::ServerConfigurableFlagsReset();
  } else {
    LOG(INFO) << "Server configurable flags health check is disabled";
  }

  return 0;
}