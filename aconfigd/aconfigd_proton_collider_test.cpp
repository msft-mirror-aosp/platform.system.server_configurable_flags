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


#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <flag_macros.h>
#include <gtest/gtest.h>

#include "aconfigd_test_mock.h"
#include "aconfigd_util.h"

namespace android {
namespace aconfigd {

class AconfigdProtonColliderTest : public ::testing::Test {
 protected:

  StorageRequestMessage list_container_storage_message(const std::string& container) {
    auto message = StorageRequestMessage();
    auto* msg = message.mutable_list_storage_message();
    msg->set_container(container);
    return message;
  }

  StorageRequestMessage ota_flag_staging_message(
      const std::string& build_id,
      const std::vector<std::tuple<std::string, std::string, std::string>> flags) {
    auto message = StorageRequestMessage();
    auto* msg = message.mutable_ota_staging_message();
    msg->set_build_id(build_id);
    for (auto const& [package_name, flag_name, flag_value] : flags) {
      auto* flag = msg->add_overrides();
      flag->set_package_name(package_name);
      flag->set_flag_name(flag_name);
      flag->set_flag_value(flag_value);
    }
    return message;
  }

  void verify_ota_staging_return_message(base::Result<StorageReturnMessage> msg_result) {
    ASSERT_TRUE(msg_result.ok()) << msg_result.error();
    auto msg = *msg_result;
    ASSERT_TRUE(msg.has_ota_staging_message()) << msg.error_message();
  }

  void verify_error_message(base::Result<StorageReturnMessage> msg_result,
                            const std::string& errmsg) {
    ASSERT_FALSE(msg_result.ok());
    ASSERT_TRUE(msg_result.error().message().find(errmsg) != std::string::npos)
        << msg_result.error().message();
  }
}; // class AconfigdProtonColliderTest


TEST_F(AconfigdProtonColliderTest, ota_flag_staging) {
  auto a_mock = AconfigdMock();
  auto request_msg = ota_flag_staging_message(
      "mock_build_id",
      {{"package_1", "flag_1", "true"},
       {"package_2", "flag_1", "false"}});
  auto return_msg = a_mock.SendRequestToSocket(request_msg);
  verify_ota_staging_return_message(return_msg);
  ASSERT_TRUE(FileExists(a_mock.flags_dir + "/ota.pb"));
  auto pb = ReadPbFromFile<StorageRequestMessage::OTAFlagStagingMessage>(
      a_mock.flags_dir + "/ota.pb");
  ASSERT_TRUE(pb.ok());
  ASSERT_EQ(pb->build_id(), "mock_build_id");
  auto flags = pb->overrides();
  ASSERT_EQ(flags.size(), 2);
  auto flag = pb->overrides(0);
  ASSERT_EQ(flag.package_name(), "package_1");
  ASSERT_EQ(flag.flag_name(), "flag_1");
  ASSERT_EQ(flag.flag_value(), "true");
  flag = pb->overrides(1);
  ASSERT_EQ(flag.package_name(), "package_2");
  ASSERT_EQ(flag.flag_name(), "flag_1");
  ASSERT_EQ(flag.flag_value(), "false");
}

TEST_F(AconfigdProtonColliderTest, ota_flag_unstaging) {
  // cerate mock aconfigd and initialize platform storage
  auto a_mock = AconfigdMock();
  auto init_result = a_mock.aconfigd.InitializePlatformStorage();
  ASSERT_TRUE(init_result.ok()) << init_result.error();

  auto flags_to_stage =
      std::vector<std::tuple<std::string, std::string, std::string>>();

  // for fake OTA flag overrides, flip all RW flag value
  auto request_msg = list_container_storage_message("system");
  auto return_msg = a_mock.SendRequestToSocket(request_msg);
  ASSERT_TRUE(return_msg.ok()) << return_msg.error();
  auto flags_msg = return_msg->list_storage_message();

  for (auto const& flag : flags_msg.flags()) {
    if (flag.is_readwrite()) {
      flags_to_stage.push_back({
          flag.package_name(),
          flag.flag_name(),
          flag.server_flag_value() == "true" ? "false" : "true"
        });
    }
  }

  // fake an OTA staging request, using current build id
  auto build_id = base::GetProperty("ro.build.fingerprint", "");
  request_msg = ota_flag_staging_message(build_id, flags_to_stage);
  return_msg = a_mock.SendRequestToSocket(request_msg);
  verify_ota_staging_return_message(return_msg);
  ASSERT_TRUE(FileExists(a_mock.flags_dir + "/ota.pb"));

  init_result = a_mock.aconfigd.InitializePlatformStorage();
  ASSERT_TRUE(init_result.ok()) << init_result.error();
  ASSERT_FALSE(FileExists(a_mock.flags_dir + "/ota.pb"));

  // list container
  request_msg = list_container_storage_message("system");
  return_msg = a_mock.SendRequestToSocket(request_msg);
  ASSERT_TRUE(return_msg.ok()) << return_msg.error();
  flags_msg = return_msg->list_storage_message();

  size_t i = 0;
  for (auto const& flag : flags_msg.flags()) {
    if (flag.is_readwrite()) {
      ASSERT_EQ(flag.package_name(), std::get<0>(flags_to_stage[i]));
      ASSERT_EQ(flag.flag_name(), std::get<1>(flags_to_stage[i]));
      ASSERT_EQ(flag.server_flag_value(), std::get<2>(flags_to_stage[i]));
      ++i;
    }
  }
}

TEST_F(AconfigdProtonColliderTest, ota_flag_unstaging_negative) {
  // cerate mock aconfigd and initialize platform storage
  auto a_mock = AconfigdMock();
  auto init_result = a_mock.aconfigd.InitializePlatformStorage();
  ASSERT_TRUE(init_result.ok()) << init_result.error();

  // fake an OTA staging request, using fake build id
  auto request_msg = ota_flag_staging_message(
      "some_fake_build_id",
      {{"abc", "def", "true"}});
  auto return_msg = a_mock.SendRequestToSocket(request_msg);
  verify_ota_staging_return_message(return_msg);
  ASSERT_TRUE(FileExists(a_mock.flags_dir + "/ota.pb"));

  init_result = a_mock.aconfigd.InitializePlatformStorage();
  ASSERT_TRUE(init_result.ok()) << init_result.error();

  // the ota overrides file should still exist
  ASSERT_TRUE(FileExists(a_mock.flags_dir + "/ota.pb"));
}

} // namespace aconfigd
} // namespace android
