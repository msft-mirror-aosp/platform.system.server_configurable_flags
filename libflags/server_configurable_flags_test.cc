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

#include <gtest/gtest.h>

#include <string>

#include "android-base/properties.h"

using namespace server_configurable_flags;
using namespace android::base;

TEST(server_configurable_flags, empty_flag_returns_default) {
  std::string result =
      server_configurable_flags::GetServerConfigurableFlags("category", "flag", "default");
  ASSERT_EQ("default", result);
}

TEST(server_configurable_flags, set_flag_returns_value) {
  android::base::SetProperty("persist.device_config.category.flag", "hello");
  std::string result =
      server_configurable_flags::GetServerConfigurableFlags("category", "flag", "default");
  ASSERT_EQ("hello", result);

  // clean up
  android::base::SetProperty("persist.device_config.category.flag", "");
}

TEST(server_configurable_flags, invalid_flag_returns_default) {
  std::string result =
      server_configurable_flags::GetServerConfigurableFlags("category.", "flag", "default");
  ASSERT_EQ("default", result);

  result = server_configurable_flags::GetServerConfigurableFlags("category", "!flag", "default");
  ASSERT_EQ("default", result);

  result = server_configurable_flags::GetServerConfigurableFlags("category", ".flag", "default");
  ASSERT_EQ("default", result);
}

TEST(server_configurable_flags, mark_boot_clears_fail_count_property) {
  android::base::SetProperty("persist.device_config.attempted_boot_count", "1");
  server_configurable_flags::ServerConfigurableFlagsMarkBoot();

  std::string actual = android::base::GetProperty("persist.device_config.attempted_boot_count", "");
  ASSERT_EQ("", actual);
}

TEST(server_configurable_flags, flags_reset_skip_under_threshold) {
  android::base::SetProperty("persist.device_config.attempted_boot_count", "1");
  android::base::SetProperty("persist.device_config.category1.prop1", "val1");
  android::base::SetProperty("persist.device_config.category1.prop2", "val2");
  android::base::SetProperty("persist.device_config.category2.prop3", "val3");
  android::base::SetProperty("sys.category3.test", "val4");

  server_configurable_flags::ServerConfigurableFlagsReset();

  ASSERT_EQ("2", android::base::GetProperty("persist.device_config.attempted_boot_count", ""));
  ASSERT_EQ("val1", android::base::GetProperty("persist.device_config.category1.prop1", ""));
  ASSERT_EQ("val2", android::base::GetProperty("persist.device_config.category1.prop2", ""));
  ASSERT_EQ("val3", android::base::GetProperty("persist.device_config.category2.prop3", ""));
  ASSERT_EQ("val4", android::base::GetProperty("sys.category3.test", ""));
}

TEST(server_configurable_flags, flags_reset_performed_over_threshold) {
  android::base::SetProperty("persist.device_config.attempted_boot_count", "5");
  android::base::SetProperty("persist.device_config.category1.prop1", "val1");
  android::base::SetProperty("persist.device_config.category1.prop2", "val2");
  android::base::SetProperty("persist.device_config.category2.prop3", "val3");
  android::base::SetProperty("sys.category3.test", "val4");

  server_configurable_flags::ServerConfigurableFlagsReset();

  ASSERT_EQ("", android::base::GetProperty("persist.device_config.attempted_boot_count", ""));
  ASSERT_EQ("", android::base::GetProperty("persist.device_config.category1.prop1", ""));
  ASSERT_EQ("", android::base::GetProperty("persist.device_config.category1.prop2", ""));
  ASSERT_EQ("", android::base::GetProperty("persist.device_config.category2.prop3", ""));
  ASSERT_EQ("val4", android::base::GetProperty("sys.category3.test", ""));
}