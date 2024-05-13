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

#include <sys/socket.h>
#include <sys/un.h>

#include <gtest/gtest.h>
#include <cutils/sockets.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>

#include "aconfig_storage/aconfig_storage_read_api.hpp"
#include "aconfig_storage/aconfig_storage_write_api.hpp"
#include <protos/aconfig_storage_metadata.pb.h>
#include <aconfigd.pb.h>
#include "aconfigd_util.h"
#include "aconfigd.h"

using storage_records_pb = android::aconfig_storage_metadata::storage_files;
using storage_record_pb = android::aconfig_storage_metadata::storage_file_info;

namespace android {
namespace aconfigd {

class AconfigdTest : public ::testing::Test {
 protected:
  base::Result<base::unique_fd> connect_aconfigd_socket() {
    auto sock_fd = base::unique_fd(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (sock_fd == -1) {
      return base::ErrnoError() << "failed create socket";
    }

    auto addr = sockaddr_un();
    addr.sun_family = AF_UNIX;
    auto path = std::string("/dev/socket/") + kAconfigdSocket;
    strlcpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path));

    bool success = false;
    for (int retry = 0; retry < 5; retry++) {
      if (connect(sock_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
        success = true;
        break;
      }
      sleep(1);
    }

    if (!success) {
      return base::ErrnoError() << "failed to connect to aconfigd socket";
    }

    return sock_fd;
  }

  // send a message to aconfigd socket, and capture return message
  base::Result<StorageReturnMessages> send_message(const StorageRequestMessages& messages) {
    auto sock_fd = connect_aconfigd_socket();
    if (!sock_fd.ok()) {
      return Error() << sock_fd.error();
    }

    auto message_string = std::string();
    if (!messages.SerializeToString(&message_string)) {
      return Error() << "failed to serialize pb to string";
    }

    unsigned char bytes[4];
    uint32_t msg_size = message_string.size();
    bytes[0] = (msg_size >> 24) & 0xFF;
    bytes[1] = (msg_size >> 16) & 0xFF;
    bytes[2] = (msg_size >> 8) & 0xFF;
    bytes[3] = (msg_size >> 0) & 0xFF;

    auto num_bytes = TEMP_FAILURE_RETRY(send(*sock_fd, bytes, 4, 0));
    if (num_bytes != 4) {
      return ErrnoError() << "send() failed for msg size";
    }

    num_bytes = TEMP_FAILURE_RETRY(
        send(*sock_fd, message_string.c_str(), message_string.size(), 0));
    if (num_bytes != static_cast<long>(message_string.size())) {
      return ErrnoError() << "send() failed for msg";
    }

    num_bytes = TEMP_FAILURE_RETRY(recv(*sock_fd, bytes, 4, 0));
    if (num_bytes != 4) {
      return ErrnoError() << "recv() failed for return msg size";
    }

    uint32_t payload_size =
        uint32_t(bytes[0]<<24 | bytes[1]<<16 | bytes[2]<<8 | bytes[3]);
    char buffer[payload_size];
    num_bytes = TEMP_FAILURE_RETRY(recv(*sock_fd, buffer, payload_size, 0));
    if (num_bytes != payload_size) {
      return ErrnoError() << "recv() failed for return msg";
    }

    auto return_messages = StorageReturnMessages{};
    if (!return_messages.ParseFromString(std::string(buffer, num_bytes))) {
      return Error() << "failed to parse string into proto";
    }

    if (return_messages.msgs_size() != messages.msgs_size()) {
      return Error() << "Send " << messages.msgs_size() << " request messages, get "
                     << return_messages.msgs_size() << " return messages";
    }

    return return_messages;
  }

  static Result<std::string> copy_to_temp_file(std::string const& source_file) {
    auto temp_file = std::string(std::tmpnam(nullptr));
    auto content = std::string();
    if (!ReadFileToString(source_file, &content)) {
      return Error() << "failed to read file: " << source_file;
    }
    if (!WriteStringToFile(content, temp_file)) {
      return Error() << "failed to copy file: " << source_file;
    }
    return temp_file;
  }

  void add_new_storage_message(StorageRequestMessages& messages,
                               const std::string& package_map_file,
                               const std::string& flag_map_file,
                               const std::string& flag_value_file) {
    auto* message = messages.add_msgs();
    auto* msg = message->mutable_new_storage_message();
    auto test_dir = base::GetExecutableDirectory();
    msg->set_container("mockup");
    msg->set_package_map(package_map_file);
    msg->set_flag_map(flag_map_file);
    msg->set_flag_value(flag_value_file);
  }

  void add_flag_override_message(StorageRequestMessages& messages,
                                 const std::string& package,
                                 const std::string& flag,
                                 const std::string& value,
                                 bool is_local) {
    auto* message = messages.add_msgs();
    auto* msg = message->mutable_flag_override_message();
    msg->set_package_name(package);
    msg->set_flag_name(flag);
    msg->set_flag_value(value);
    msg->set_is_local(is_local);
  }

  void add_flag_query_message(StorageRequestMessages& messages,
                              const std::string& package,
                              const std::string& flag) {
    auto* message = messages.add_msgs();
    auto* msg = message->mutable_flag_query_message();
    msg->set_package_name(package);
    msg->set_flag_name(flag);
  }

  void add_flag_local_override_remove_message(StorageRequestMessages& messages,
                                              const std::string& package,
                                              const std::string& flag,
                                              bool remove_all) {
    auto* message = messages.add_msgs();
    auto* msg = message->mutable_remove_local_override_message();
    msg->set_package_name(package);
    msg->set_flag_name(flag);
    msg->set_remove_all(remove_all);
  }

  void add_reset_storage_message(StorageRequestMessages& messages) {
    auto* message = messages.add_msgs();
    auto* msg = message->mutable_reset_storage_message();
  }

  void add_list_storage_message(StorageRequestMessages& messages) {
    auto* message = messages.add_msgs();
    auto* msg = message->mutable_list_storage_message();
    msg->set_all(true);
  }

  void add_list_container_storage_message(StorageRequestMessages& messages,
                                          const std::string& container) {
    auto* message = messages.add_msgs();
    auto* msg = message->mutable_list_storage_message();
    msg->set_container(container);
  }

  void add_list_package_storage_message(StorageRequestMessages& messages,
                                        const std::string& package) {
    auto* message = messages.add_msgs();
    auto* msg = message->mutable_list_storage_message();
    msg->set_package_name(package);
  }

  void verify_new_storage_return_message(const StorageReturnMessage& msg,
                                         bool ensure_updated = false) {
    ASSERT_TRUE(msg.has_new_storage_message()) << msg.error_message();
    if (ensure_updated) {
      auto message = msg.new_storage_message();
      ASSERT_TRUE(message.storage_updated());
    }
  }

  void verify_flag_override_return_message(const StorageReturnMessage& msg) {
    ASSERT_TRUE(msg.has_flag_override_message()) << msg.error_message();
  }

  void verify_flag_query_return_message(
      const StorageReturnMessage::FlagQueryReturnMessage& message,
      const std::string& package_name,
      const std::string& flag_name,
      const std::string& server_value,
      const std::string& local_value,
      const std::string& boot_value,
      const std::string& default_value,
      bool is_readwrite,
      bool has_server_override,
      bool has_local_override) {
    ASSERT_EQ(message.package_name(), package_name);
    ASSERT_EQ(message.flag_name(), flag_name);
    ASSERT_EQ(message.server_flag_value(), server_value);
    ASSERT_EQ(message.local_flag_value(), local_value);
    ASSERT_EQ(message.boot_flag_value(), boot_value);
    ASSERT_EQ(message.default_flag_value(), default_value);
    ASSERT_EQ(message.is_readwrite(), is_readwrite);
    ASSERT_EQ(message.has_server_override(), has_server_override);
    ASSERT_EQ(message.has_local_override(), has_local_override);
  }

  void verify_flag_query_return_message(const StorageReturnMessage& msg,
                                        const std::string& package_name,
                                        const std::string& flag_name,
                                        const std::string& server_value,
                                        const std::string& local_value,
                                        const std::string& boot_value,
                                        const std::string& default_value,
                                        bool is_readwrite,
                                        bool has_server_override,
                                        bool has_local_override) {
    ASSERT_TRUE(msg.has_flag_query_message()) << msg.error_message();
    auto message = msg.flag_query_message();
    verify_flag_query_return_message(
        message, package_name, flag_name, server_value, local_value, boot_value,
        default_value, is_readwrite, has_server_override, has_local_override);
  }

  void verify_local_override_remove_return_message(const StorageReturnMessage& msg) {
    ASSERT_TRUE(msg.has_remove_local_override_message()) << msg.error_message();
  }

  void verify_reset_storage_message(const StorageReturnMessage& msg) {
    ASSERT_TRUE(msg.has_reset_storage_message()) << msg.error_message();
  }

  void verify_error_message(const StorageReturnMessage& msg,
                            const std::string& errmsg) {
    ASSERT_TRUE(msg.has_error_message());
    ASSERT_TRUE(msg.error_message().find(errmsg) != std::string::npos)
        << msg.error_message();
  }

  // setup test suites
  static void SetUpTestSuite() {
    // create two temp flag vals, the second one is used to mimic stoarge update
    auto test_dir = base::GetExecutableDirectory();
    auto package_file = copy_to_temp_file(test_dir + "/tests/package.map");
    ASSERT_TRUE(package_file.ok());
    temp_package_map_ = *package_file;

    auto flag_file = copy_to_temp_file(test_dir + "/tests/flag.map");
    ASSERT_TRUE(flag_file.ok());
    temp_flag_map_ = *flag_file;

    auto value_file = copy_to_temp_file(test_dir + "/tests/flag.val");
    ASSERT_TRUE(value_file.ok());
    temp_flag_val_ = *value_file;

    std::this_thread::sleep_for(std::chrono::milliseconds{20});

    value_file = copy_to_temp_file(test_dir + "/tests/flag.val");
    ASSERT_TRUE(value_file.ok());
    another_temp_flag_val_ = *value_file;
  }

  static std::string temp_package_map_;
  static std::string temp_flag_map_;
  static std::string temp_flag_val_;
  static std::string another_temp_flag_val_;
}; // class AconfigdTest

std::string AconfigdTest::temp_package_map_;
std::string AconfigdTest::temp_flag_map_;
std::string AconfigdTest::temp_flag_val_;
std::string AconfigdTest::another_temp_flag_val_;

TEST_F(AconfigdTest, add_new_storage) {
  auto request_msgs = StorageRequestMessages();
  add_new_storage_message(request_msgs, temp_package_map_, temp_flag_map_, temp_flag_val_);

  auto return_msgs = send_message(request_msgs);
  ASSERT_TRUE(return_msgs.ok()) << return_msgs.error();
  verify_new_storage_return_message(return_msgs->msgs(0));

  auto pb_file = "/metadata/aconfig/boot/available_storage_file_records.pb";
  auto records_pb = storage_records_pb();
  auto content = std::string();
  ASSERT_TRUE(base::ReadFileToString(pb_file, &content)) << strerror(errno);
  ASSERT_TRUE(records_pb.ParseFromString(content)) << strerror(errno);

  bool found = false;
  for (auto& entry : records_pb.files()) {
    if (entry.container() == "mockup") {
      found = true;
      break;
    }
  }
  ASSERT_TRUE(found);
}

TEST_F(AconfigdTest, mimic_storage_update_in_ota) {
  auto request_msgs = StorageRequestMessages();
  add_new_storage_message(request_msgs, temp_package_map_, temp_flag_map_, temp_flag_val_);
  auto return_msgs = send_message(request_msgs);
  ASSERT_TRUE(return_msgs.ok()) << return_msgs.error();
  verify_new_storage_return_message(return_msgs->msgs(0));

  // after OTA, the old RO package.map and RO flag.map are gone, now the updated
  // package.map, flag.map is there. ensure we can still extract old flag information
  // necessary to persist server and local flag override.
  auto test_dir = base::GetExecutableDirectory();
  auto copy = CopyFile(test_dir + "/tests/updated_package.map", temp_package_map_, 0444);
  ASSERT_TRUE(copy.ok());
  copy = CopyFile(test_dir + "/tests/updated_flag.map", temp_flag_map_, 0444);
  ASSERT_TRUE(copy.ok());
  copy = CopyFile(test_dir + "/tests/updated_flag.val", temp_flag_val_, 0444);
  ASSERT_TRUE(copy.ok());

  // send in another new storage request to force a storage update
  request_msgs = StorageRequestMessages();
  add_new_storage_message(request_msgs, temp_package_map_, temp_flag_map_, temp_flag_val_);
  return_msgs = send_message(request_msgs);
  ASSERT_TRUE(return_msgs.ok()) << return_msgs.error();
  verify_new_storage_return_message(return_msgs->msgs(0));

  // restore back to original file
  copy = CopyFile(test_dir + "/tests/package.map", temp_package_map_, 0444);
  ASSERT_TRUE(copy.ok());
  copy = CopyFile(test_dir + "/tests/flag.map", temp_flag_map_, 0444);
  ASSERT_TRUE(copy.ok());
  copy = CopyFile(test_dir + "/tests/flag.val", temp_flag_val_, 0444);
  ASSERT_TRUE(copy.ok());

  request_msgs = StorageRequestMessages();
  add_new_storage_message(request_msgs, temp_package_map_, temp_flag_map_, temp_flag_val_);
  return_msgs = send_message(request_msgs);
  ASSERT_TRUE(return_msgs.ok()) << return_msgs.error();
  verify_new_storage_return_message(return_msgs->msgs(0));
}

TEST_F(AconfigdTest, flag_server_override) {
  auto request_msgs = StorageRequestMessages();
  add_new_storage_message(request_msgs, temp_package_map_, temp_flag_map_, temp_flag_val_);
  add_reset_storage_message(request_msgs);
  add_flag_override_message(
      request_msgs, "com.android.aconfig.storage.test_1", "enabled_rw", "false", false);
  add_flag_query_message(
      request_msgs, "com.android.aconfig.storage.test_1", "enabled_rw");
  add_flag_override_message(
      request_msgs, "com.android.aconfig.storage.test_1", "enabled_rw", "true", false);
  add_flag_query_message(
      request_msgs, "com.android.aconfig.storage.test_1", "enabled_rw");
  auto return_msgs = send_message(request_msgs);
  ASSERT_TRUE(return_msgs.ok()) << return_msgs.error();
  verify_new_storage_return_message(return_msgs->msgs(0));
  verify_reset_storage_message(return_msgs->msgs(1));
  verify_flag_override_return_message(return_msgs->msgs(2));
  verify_flag_query_return_message(
      return_msgs->msgs(3), "com.android.aconfig.storage.test_1", "enabled_rw",
      "false", "", "true", "true", true, true, false);
  verify_flag_override_return_message(return_msgs->msgs(4));
  verify_flag_query_return_message(
      return_msgs->msgs(5), "com.android.aconfig.storage.test_1", "enabled_rw",
      "true", "", "true", "true", true, true, false);
}

TEST_F(AconfigdTest, server_override_survive_update) {
  auto request_msgs = StorageRequestMessages();
  add_new_storage_message(request_msgs, temp_package_map_, temp_flag_map_, temp_flag_val_);
  add_reset_storage_message(request_msgs);
  add_flag_override_message(
      request_msgs, "com.android.aconfig.storage.test_1", "enabled_rw", "false", false);
  add_flag_query_message(
      request_msgs, "com.android.aconfig.storage.test_1", "enabled_rw");
  add_new_storage_message(request_msgs, temp_package_map_, temp_flag_map_, another_temp_flag_val_);
  add_flag_query_message(
      request_msgs, "com.android.aconfig.storage.test_1", "enabled_rw");
  auto return_msgs = send_message(request_msgs);
  ASSERT_TRUE(return_msgs.ok()) << return_msgs.error();
  verify_new_storage_return_message(return_msgs->msgs(0));
  verify_reset_storage_message(return_msgs->msgs(1));
  verify_flag_override_return_message(return_msgs->msgs(2));
  verify_flag_query_return_message(
      return_msgs->msgs(3), "com.android.aconfig.storage.test_1", "enabled_rw",
      "false", "", "true", "true", true, true, false);
  verify_new_storage_return_message(return_msgs->msgs(4), true);
  verify_flag_query_return_message(
      return_msgs->msgs(5), "com.android.aconfig.storage.test_1", "enabled_rw",
      "false", "", "true", "true", true, true, false);
}

TEST_F(AconfigdTest, flag_local_override) {
  auto request_msgs = StorageRequestMessages();
  add_new_storage_message(request_msgs, temp_package_map_, temp_flag_map_, temp_flag_val_);
  add_reset_storage_message(request_msgs);
  add_flag_override_message(
      request_msgs, "com.android.aconfig.storage.test_1", "disabled_rw", "true", true);
  add_flag_query_message(
      request_msgs, "com.android.aconfig.storage.test_1", "disabled_rw");
  add_flag_override_message(
      request_msgs, "com.android.aconfig.storage.test_1", "disabled_rw", "false", true);
  add_flag_query_message(
      request_msgs, "com.android.aconfig.storage.test_1", "disabled_rw");
  auto return_msgs = send_message(request_msgs);
  ASSERT_TRUE(return_msgs.ok()) << return_msgs.error();
  verify_new_storage_return_message(return_msgs->msgs(0));
  verify_reset_storage_message(return_msgs->msgs(1));
  verify_flag_override_return_message(return_msgs->msgs(2));
  verify_flag_query_return_message(
      return_msgs->msgs(3), "com.android.aconfig.storage.test_1", "disabled_rw",
      "", "true", "false", "false", true, false, true);
  verify_flag_override_return_message(return_msgs->msgs(4));
  verify_flag_query_return_message(
      return_msgs->msgs(5), "com.android.aconfig.storage.test_1", "disabled_rw",
      "", "false", "false", "false", true, false, true);
}

TEST_F(AconfigdTest, local_override_survive_update) {
  auto request_msgs = StorageRequestMessages();
  add_new_storage_message(request_msgs, temp_package_map_, temp_flag_map_, temp_flag_val_);
  add_reset_storage_message(request_msgs);
  add_flag_override_message(
      request_msgs, "com.android.aconfig.storage.test_1", "disabled_rw", "true", true);
  add_flag_query_message(
      request_msgs, "com.android.aconfig.storage.test_1", "disabled_rw");
  add_new_storage_message(request_msgs, temp_package_map_, temp_flag_map_, another_temp_flag_val_);
  add_flag_query_message(
      request_msgs, "com.android.aconfig.storage.test_1", "disabled_rw");
  auto return_msgs = send_message(request_msgs);
  ASSERT_TRUE(return_msgs.ok()) << return_msgs.error();
  verify_new_storage_return_message(return_msgs->msgs(0));
  verify_reset_storage_message(return_msgs->msgs(1));
  verify_flag_override_return_message(return_msgs->msgs(2));
  verify_flag_query_return_message(
      return_msgs->msgs(3), "com.android.aconfig.storage.test_1", "disabled_rw",
      "", "true", "false", "false", true, false, true);
  verify_new_storage_return_message(return_msgs->msgs(4), true);
  verify_flag_query_return_message(
      return_msgs->msgs(5), "com.android.aconfig.storage.test_1", "disabled_rw",
      "", "true", "false", "false", true, false, true);
}

TEST_F(AconfigdTest, single_local_override_remove) {
  auto request_msgs = StorageRequestMessages();
  add_new_storage_message(request_msgs, temp_package_map_, temp_flag_map_, temp_flag_val_);
  add_reset_storage_message(request_msgs);
  add_flag_override_message(
      request_msgs, "com.android.aconfig.storage.test_1", "disabled_rw", "true", true);
  add_flag_query_message(
      request_msgs, "com.android.aconfig.storage.test_1", "disabled_rw");
  add_flag_local_override_remove_message(
      request_msgs, "com.android.aconfig.storage.test_1", "disabled_rw", false);
  add_flag_query_message(
      request_msgs, "com.android.aconfig.storage.test_1", "disabled_rw");
  auto return_msgs = send_message(request_msgs);
  ASSERT_TRUE(return_msgs.ok()) << return_msgs.error();
  verify_new_storage_return_message(return_msgs->msgs(0));
  verify_reset_storage_message(return_msgs->msgs(1));
  verify_flag_override_return_message(return_msgs->msgs(2));
  verify_flag_query_return_message(
      return_msgs->msgs(3), "com.android.aconfig.storage.test_1", "disabled_rw",
      "", "true", "false", "false", true, false, true);
  verify_local_override_remove_return_message(return_msgs->msgs(4));
  verify_flag_query_return_message(
      return_msgs->msgs(5), "com.android.aconfig.storage.test_1", "disabled_rw",
      "", "", "false", "false", true, false, false);
}

TEST_F(AconfigdTest, multiple_local_override_remove) {
  auto request_msgs = StorageRequestMessages();
  add_new_storage_message(request_msgs, temp_package_map_, temp_flag_map_, temp_flag_val_);
  add_reset_storage_message(request_msgs);
  add_flag_override_message(
      request_msgs, "com.android.aconfig.storage.test_1", "disabled_rw", "true", true);
  add_flag_override_message(
      request_msgs, "com.android.aconfig.storage.test_2", "disabled_rw", "true", true);
  add_flag_query_message(
      request_msgs, "com.android.aconfig.storage.test_1", "disabled_rw");
  add_flag_query_message(
      request_msgs, "com.android.aconfig.storage.test_2", "disabled_rw");
  add_flag_local_override_remove_message(request_msgs, "", "", true);
  add_flag_query_message(
      request_msgs, "com.android.aconfig.storage.test_1", "disabled_rw");
  add_flag_query_message(
      request_msgs, "com.android.aconfig.storage.test_2", "disabled_rw");
  auto return_msgs = send_message(request_msgs);
  ASSERT_TRUE(return_msgs.ok()) << return_msgs.error();
  verify_new_storage_return_message(return_msgs->msgs(0));
  verify_reset_storage_message(return_msgs->msgs(1));
  verify_flag_override_return_message(return_msgs->msgs(2));
  verify_flag_override_return_message(return_msgs->msgs(3));
  verify_flag_query_return_message(
      return_msgs->msgs(4), "com.android.aconfig.storage.test_1", "disabled_rw",
      "", "true", "false", "false", true, false, true);
  verify_flag_query_return_message(
      return_msgs->msgs(5), "com.android.aconfig.storage.test_2", "disabled_rw",
      "", "true", "false", "false", true, false, true);
  verify_local_override_remove_return_message(return_msgs->msgs(6));
  verify_flag_query_return_message(
      return_msgs->msgs(7), "com.android.aconfig.storage.test_1", "disabled_rw",
      "", "", "false", "false", true, false, false);
  verify_flag_query_return_message(
      return_msgs->msgs(8), "com.android.aconfig.storage.test_2", "disabled_rw",
      "", "", "false", "false", true, false, false);
}

TEST_F(AconfigdTest, readonly_flag_override) {
  auto request_msgs = StorageRequestMessages();
  add_new_storage_message(request_msgs, temp_package_map_, temp_flag_map_, temp_flag_val_);
  add_flag_override_message(
      request_msgs, "com.android.aconfig.storage.test_1", "enabled_ro", "false", false);
  add_flag_override_message(
      request_msgs, "com.android.aconfig.storage.test_1", "enabled_ro", "false", true);
  auto return_msgs = send_message(request_msgs);
  ASSERT_TRUE(return_msgs.ok()) << return_msgs.error();
  verify_new_storage_return_message(return_msgs->msgs(0));
  verify_error_message(return_msgs->msgs(1), "Cannot update read only flag");
  verify_error_message(return_msgs->msgs(2), "Cannot update read only flag");
}

TEST_F(AconfigdTest, nonexist_flag_override) {
  auto request_msgs = StorageRequestMessages();
  add_new_storage_message(request_msgs, temp_package_map_, temp_flag_map_, temp_flag_val_);
  add_flag_override_message(
      request_msgs, "unknown", "enabled_rw", "true", false);
  add_flag_override_message(
      request_msgs, "com.android.aconfig.storage.test_1", "unknown", "true", false);
  auto return_msgs = send_message(request_msgs);
  ASSERT_TRUE(return_msgs.ok()) << return_msgs.error();
  verify_new_storage_return_message(return_msgs->msgs(0));
  verify_error_message(return_msgs->msgs(1), "Failed to find owning container");
  verify_error_message(return_msgs->msgs(2), "Flag does not exist");
}

TEST_F(AconfigdTest, nonexist_flag_query) {
  auto request_msgs = StorageRequestMessages();
  add_new_storage_message(request_msgs, temp_package_map_, temp_flag_map_, temp_flag_val_);
  add_flag_query_message(
      request_msgs, "unknown", "enabled_rw");
  add_flag_query_message(
      request_msgs, "com.android.aconfig.storage.test_1", "unknown");
  auto return_msgs = send_message(request_msgs);
  ASSERT_TRUE(return_msgs.ok()) << return_msgs.error();
  verify_new_storage_return_message(return_msgs->msgs(0));
  verify_error_message(return_msgs->msgs(1), "Failed to find owning container");
  verify_error_message(return_msgs->msgs(2), "Flag does not exist");
}

TEST_F(AconfigdTest, storage_reset) {
  auto request_msgs = StorageRequestMessages();
  add_new_storage_message(request_msgs, temp_package_map_, temp_flag_map_, temp_flag_val_);
  add_reset_storage_message(request_msgs);
  add_flag_override_message(
      request_msgs, "com.android.aconfig.storage.test_1", "enabled_rw", "false", false);
  add_flag_override_message(
      request_msgs, "com.android.aconfig.storage.test_2", "disabled_rw", "true", true);
  add_reset_storage_message(request_msgs);
  add_flag_query_message(
      request_msgs, "com.android.aconfig.storage.test_1", "enabled_rw");
  add_flag_query_message(
      request_msgs, "com.android.aconfig.storage.test_2", "disabled_rw");
  auto return_msgs = send_message(request_msgs);
  ASSERT_TRUE(return_msgs.ok()) << return_msgs.error();
  verify_new_storage_return_message(return_msgs->msgs(0));
  verify_reset_storage_message(return_msgs->msgs(1));
  verify_flag_override_return_message(return_msgs->msgs(2));
  verify_flag_override_return_message(return_msgs->msgs(3));
  verify_reset_storage_message(return_msgs->msgs(4));
  verify_flag_query_return_message(
      return_msgs->msgs(5), "com.android.aconfig.storage.test_1", "enabled_rw",
      "", "", "true", "true", true, false, false);
  verify_flag_query_return_message(
      return_msgs->msgs(6), "com.android.aconfig.storage.test_2", "disabled_rw",
      "", "", "false", "false", true, false, false);
}

TEST_F(AconfigdTest, storage_list_package) {
  auto request_msgs = StorageRequestMessages();
  add_new_storage_message(request_msgs, temp_package_map_, temp_flag_map_, temp_flag_val_);
  add_reset_storage_message(request_msgs);
  add_flag_override_message(
      request_msgs, "com.android.aconfig.storage.test_1", "disabled_rw", "true", false);
  add_flag_override_message(
      request_msgs, "com.android.aconfig.storage.test_1", "enabled_rw", "false", true);
  add_list_package_storage_message(request_msgs, "com.android.aconfig.storage.test_1");
  auto return_msgs = send_message(request_msgs);
  ASSERT_TRUE(return_msgs.ok()) << return_msgs.error();
  verify_new_storage_return_message(return_msgs->msgs(0));
  verify_reset_storage_message(return_msgs->msgs(1));
  verify_flag_override_return_message(return_msgs->msgs(2));
  verify_flag_override_return_message(return_msgs->msgs(3));

  const auto& list_return_msg = return_msgs->msgs(4);
  ASSERT_TRUE(list_return_msg.has_list_storage_message())
      << list_return_msg.error_message();
  auto flags_msg = list_return_msg.list_storage_message();
  ASSERT_EQ(flags_msg.flags_size(), 3);
  verify_flag_query_return_message(
      flags_msg.flags(0), "com.android.aconfig.storage.test_1", "disabled_rw",
      "true", "", "false", "false", true, true, false);
  verify_flag_query_return_message(
      flags_msg.flags(1), "com.android.aconfig.storage.test_1", "enabled_ro",
      "", "", "true", "true", false, false, false);
  verify_flag_query_return_message(
      flags_msg.flags(2), "com.android.aconfig.storage.test_1", "enabled_rw",
      "", "false", "true", "true", true, false, true);
}

TEST_F(AconfigdTest, storage_list_non_exist_package) {
  auto request_msgs = StorageRequestMessages();
  add_new_storage_message(request_msgs, temp_package_map_, temp_flag_map_, temp_flag_val_);
  add_list_package_storage_message(request_msgs, "unknown");
  auto return_msgs = send_message(request_msgs);
  ASSERT_TRUE(return_msgs.ok()) << return_msgs.error();
  verify_new_storage_return_message(return_msgs->msgs(0));
  verify_error_message(return_msgs->msgs(1), "container not found");
}

TEST_F(AconfigdTest, storage_list_container) {
  auto request_msgs = StorageRequestMessages();
  add_new_storage_message(request_msgs, temp_package_map_, temp_flag_map_, temp_flag_val_);
  add_reset_storage_message(request_msgs);
  add_flag_override_message(
      request_msgs, "com.android.aconfig.storage.test_1", "disabled_rw", "true", false);
  add_flag_override_message(
      request_msgs, "com.android.aconfig.storage.test_2", "disabled_rw", "false", true);
  add_list_container_storage_message(request_msgs, "mockup");
  auto return_msgs = send_message(request_msgs);
  ASSERT_TRUE(return_msgs.ok()) << return_msgs.error();
  verify_new_storage_return_message(return_msgs->msgs(0));
  verify_reset_storage_message(return_msgs->msgs(1));
  verify_flag_override_return_message(return_msgs->msgs(2));
  verify_flag_override_return_message(return_msgs->msgs(3));

  const auto& list_return_msg = return_msgs->msgs(4);
  ASSERT_TRUE(list_return_msg.has_list_storage_message())
      << list_return_msg.error_message();
  auto flags_msg = list_return_msg.list_storage_message();
  ASSERT_EQ(flags_msg.flags_size(), 8);
  verify_flag_query_return_message(
      flags_msg.flags(0), "com.android.aconfig.storage.test_1", "disabled_rw",
      "true", "", "false", "false", true, true, false);
  verify_flag_query_return_message(
      flags_msg.flags(1), "com.android.aconfig.storage.test_1", "enabled_ro",
      "", "", "true", "true", false, false, false);
  verify_flag_query_return_message(
      flags_msg.flags(2), "com.android.aconfig.storage.test_1", "enabled_rw",
      "", "", "true", "true", true, false, false);
  verify_flag_query_return_message(
      flags_msg.flags(3), "com.android.aconfig.storage.test_2", "disabled_rw",
      "", "false", "false", "false", true, false, true);
  verify_flag_query_return_message(
      flags_msg.flags(4), "com.android.aconfig.storage.test_2", "enabled_fixed_ro",
      "", "", "true", "true", false, false, false);
  verify_flag_query_return_message(
      flags_msg.flags(5), "com.android.aconfig.storage.test_2", "enabled_ro",
      "", "", "true", "true", false, false, false);
  verify_flag_query_return_message(
      flags_msg.flags(6), "com.android.aconfig.storage.test_4", "enabled_fixed_ro",
      "", "", "true", "true", false, false, false);
  verify_flag_query_return_message(
      flags_msg.flags(7), "com.android.aconfig.storage.test_4", "enabled_rw",
      "", "", "true", "true", true, false, false);
}

TEST_F(AconfigdTest, storage_list_non_exist_container) {
  auto request_msgs = StorageRequestMessages();
  add_new_storage_message(request_msgs, temp_package_map_, temp_flag_map_, temp_flag_val_);
  add_list_container_storage_message(request_msgs, "unknown");
  auto return_msgs = send_message(request_msgs);
  ASSERT_TRUE(return_msgs.ok()) << return_msgs.error();
  verify_new_storage_return_message(return_msgs->msgs(0));
  verify_error_message(return_msgs->msgs(1), "Missing storage files object");
}

} // namespace aconfigd
} // namespace android
