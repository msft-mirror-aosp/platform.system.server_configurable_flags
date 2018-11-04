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
 * limitations under the License
 */

#include "server_configurable_flags/disaster_recovery.h"
#include "server_configurable_flags/get_flags.h"

#include <cutils/properties.h>
#include <regex>
#include <string>

#include "android-base/logging.h"
#include "android-base/properties.h"
#include "android-base/strings.h"

#define SYSTEM_PROPERTY_PREFIX "persist.device_config."

#define ATTEMPTED_BOOT_COUNT_PROPERTY "persist.device_config.attempted_boot_count"

#define ATTEMPTED_BOOT_COUNT_THRESHOLD 4

namespace server_configurable_flags {

static const std::regex NAME_VALID_CHARACTER_REGIX("^[\\w\\.\\-@:]*$");

static std::string MakeSystemPropertyName(const std::string& experiment_category_name,
                                          const std::string& experiment_flag_name) {
  return SYSTEM_PROPERTY_PREFIX + experiment_category_name + "." + experiment_flag_name;
}

static bool ValidateExperimentSegment(const std::string& segment) {
  return std::regex_match(segment, NAME_VALID_CHARACTER_REGIX) && segment.find(".") != 0 &&
         segment.find(".") != segment.size() - 1;
}

static void ResetFlag(const char* key, const char* value, void* /* cookie */) {
  if (android::base::StartsWith(key, SYSTEM_PROPERTY_PREFIX) && strlen(value) > 0) {
    android::base::SetProperty(key, "");
  }
}

void ServerConfigurableFlagsReset() {
  int fail_count = android::base::GetIntProperty(ATTEMPTED_BOOT_COUNT_PROPERTY, 0);
  if (fail_count < ATTEMPTED_BOOT_COUNT_THRESHOLD) {
    LOG(INFO) << __FUNCTION__ << " attempted boot count is under threshold, skipping reset.";

    // ATTEMPTED_BOOT_COUNT_PROPERTY will be reset to 0 when sys.boot_completed is set to 1.
    // The code lives in flags_health_check.rc.
    android::base::SetProperty(ATTEMPTED_BOOT_COUNT_PROPERTY, std::to_string(fail_count + 1));
  } else {
    LOG(INFO) << __FUNCTION__ << " attempted boot count reaches threshold, resetting flags.";
    property_list(ResetFlag, nullptr);
  }
}

std::string GetServerConfigurableFlags(const std::string& experiment_category_name,
                                       const std::string& experiment_flag_name,
                                       const std::string& default_value) {
  if (!ValidateExperimentSegment(experiment_category_name)) {
    LOG(ERROR) << __FUNCTION__ << " invalid category name " << experiment_category_name;
    return default_value;
  }
  if (!ValidateExperimentSegment(experiment_flag_name)) {
    LOG(ERROR) << __FUNCTION__ << " invalid flag name " << experiment_flag_name;
    return default_value;
  }
  return android::base::GetProperty(
      MakeSystemPropertyName(experiment_category_name, experiment_flag_name), default_value);
}

}  // namespace server_configurable_flags
