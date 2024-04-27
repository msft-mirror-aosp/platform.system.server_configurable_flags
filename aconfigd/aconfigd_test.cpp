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

    auto result = TEMP_FAILURE_RETRY(
        send(*sock_fd, message_string.c_str(), message_string.size(), 0));
    if (result != static_cast<long>(message_string.size())) {
      return ErrnoError() << "send() failed";
    }

    char buffer[kBufferSize] = {};
    auto num_bytes = TEMP_FAILURE_RETRY(recv(*sock_fd, buffer, sizeof(buffer), 0));
    if (num_bytes < 0) {
      return ErrnoError() << "recv() failed";
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
                               const std::string& flag_value_file) {
    auto* message = messages.add_msgs();
    auto* msg = message->mutable_new_storage_message();
    auto test_dir = base::GetExecutableDirectory();
    msg->set_container("mockup");
    msg->set_package_map(test_dir + "/tests/package.map");
    msg->set_flag_map(test_dir + "/tests/flag.map");
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

  void verify_new_storage_return_message(const StorageReturnMessage& msg) {
    ASSERT_TRUE(msg.has_new_storage_message()) << msg.error_message();
    auto message = msg.new_storage_message();
    ASSERT_TRUE(message.storage_updated());
  }

  void verify_flag_override_return_message(const StorageReturnMessage& msg) {
    ASSERT_TRUE(msg.has_flag_override_message()) << msg.error_message();
  }

  void verify_flag_query_return_message(const StorageReturnMessage& msg,
                                        const std::string& flag_value,
                                        const std::string& local_value,
                                        bool is_readwrite,
                                        bool has_server_override,
                                        bool has_local_override) {
    ASSERT_TRUE(msg.has_flag_query_message()) << msg.error_message();
    auto message = msg.flag_query_message();
    ASSERT_EQ(message.server_flag_value(), flag_value);
    ASSERT_EQ(message.local_flag_value(), local_value);
    ASSERT_EQ(message.is_readwrite(), is_readwrite);
    ASSERT_EQ(message.has_server_override(), has_server_override);
    ASSERT_EQ(message.has_local_override(), has_local_override);
  }

  void verify_local_override_remove_return_message(const StorageReturnMessage& msg) {
    ASSERT_TRUE(msg.has_remove_local_override_message()) << msg.error_message();
  }

  void verify_error_message(const StorageReturnMessage& msg,
                            const std::string& errmsg) {
    ASSERT_TRUE(msg.has_error_message());
    ASSERT_TRUE(msg.error_message().find(errmsg) != std::string::npos);
  }

  // setup test suites
  static void SetUpTestSuite() {
    // create a flag val file for each test point. make sure that these temp flag
    // value file timestamp are different, so that it will trigger a storage update.
    auto test_dir = base::GetExecutableDirectory();
    for (int i=0; i<10; ++i) {
      std::this_thread::sleep_for(std::chrono::milliseconds{10});
      auto temp_value_file = copy_to_temp_file(test_dir + "/tests/flag.val");
      ASSERT_TRUE(temp_value_file.ok());
      temp_flag_vals_.push_back(*temp_value_file);
    }
  }

  static std::vector<std::string> temp_flag_vals_;

}; // class AconfigdTest

std::vector<std::string> AconfigdTest::temp_flag_vals_;

TEST_F(AconfigdTest, add_new_storage) {
  auto request_msgs = StorageRequestMessages();
  add_new_storage_message(request_msgs, temp_flag_vals_[0]);

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

TEST_F(AconfigdTest, flag_server_override) {
  auto request_msgs = StorageRequestMessages();
  add_new_storage_message(request_msgs, temp_flag_vals_[1]);
  add_flag_override_message(
      request_msgs, "com.android.aconfig.storage.test_1", "enabled_rw", "true", false);
  add_flag_query_message(
      request_msgs, "com.android.aconfig.storage.test_1", "enabled_rw");
  add_flag_override_message(
      request_msgs, "com.android.aconfig.storage.test_1", "enabled_rw", "false", false);
  add_flag_query_message(
      request_msgs, "com.android.aconfig.storage.test_1", "enabled_rw");
  auto return_msgs = send_message(request_msgs);
  ASSERT_TRUE(return_msgs.ok()) << return_msgs.error();
  verify_new_storage_return_message(return_msgs->msgs(0));
  verify_flag_override_return_message(return_msgs->msgs(1));
  verify_flag_query_return_message(return_msgs->msgs(2), "true", "", true, true, false);
  verify_flag_override_return_message(return_msgs->msgs(3));
  verify_flag_query_return_message(return_msgs->msgs(4), "false", "", true, true, false);
}

TEST_F(AconfigdTest, flag_local_override) {
  auto request_msgs = StorageRequestMessages();
  add_new_storage_message(request_msgs, temp_flag_vals_[2]);
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
  verify_flag_override_return_message(return_msgs->msgs(1));
  verify_flag_query_return_message(return_msgs->msgs(2), "false", "true", true, false, true);
  verify_flag_override_return_message(return_msgs->msgs(3));
  verify_flag_query_return_message(return_msgs->msgs(4), "false", "false", true, false, true);
}

TEST_F(AconfigdTest, single_local_override_remove) {
  auto request_msgs = StorageRequestMessages();
  add_new_storage_message(request_msgs, temp_flag_vals_[3]);
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
  verify_flag_override_return_message(return_msgs->msgs(1));
  verify_flag_query_return_message(return_msgs->msgs(2), "false", "true", true, false, true);
  verify_local_override_remove_return_message(return_msgs->msgs(3));
  verify_flag_query_return_message(return_msgs->msgs(4), "false", "", true, false, false);
}

TEST_F(AconfigdTest, multiple_local_override_remove) {
  auto request_msgs = StorageRequestMessages();
  add_new_storage_message(request_msgs, temp_flag_vals_[4]);
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
  verify_flag_override_return_message(return_msgs->msgs(1));
  verify_flag_override_return_message(return_msgs->msgs(2));
  verify_flag_query_return_message(return_msgs->msgs(3), "false", "true", true, false, true);
  verify_flag_query_return_message(return_msgs->msgs(4), "false", "true", true, false, true);
  verify_local_override_remove_return_message(return_msgs->msgs(5));
  verify_flag_query_return_message(return_msgs->msgs(6), "false", "", true, false, false);
  verify_flag_query_return_message(return_msgs->msgs(7), "false", "", true, false, false);
}

TEST_F(AconfigdTest, readonly_flag_override) {
  auto request_msgs = StorageRequestMessages();
  add_new_storage_message(request_msgs, temp_flag_vals_[5]);
  add_flag_override_message(
      request_msgs, "com.android.aconfig.storage.test_1", "enabled_ro", "false", false);
  add_flag_override_message(
      request_msgs, "com.android.aconfig.storage.test_1", "enabled_ro", "false", true);
  auto return_msgs = send_message(request_msgs);
  ASSERT_TRUE(return_msgs.ok()) << return_msgs.error();
  verify_new_storage_return_message(return_msgs->msgs(0));
  verify_error_message(
      return_msgs->msgs(1),
      "Cannot update read only flag com.android.aconfig.storage.test_1/enabled_ro");
  verify_error_message(
      return_msgs->msgs(2),
      "Cannot update read only flag com.android.aconfig.storage.test_1/enabled_ro");
}

TEST_F(AconfigdTest, nonexist_flag_override) {
  auto request_msgs = StorageRequestMessages();
  add_new_storage_message(request_msgs, temp_flag_vals_[6]);
  add_flag_override_message(
      request_msgs, "unknown", "enabled_rw", "true", false);
  add_flag_override_message(
      request_msgs, "com.android.aconfig.storage.test_1", "unknown", "true", false);
  auto return_msgs = send_message(request_msgs);
  ASSERT_TRUE(return_msgs.ok()) << return_msgs.error();
  verify_new_storage_return_message(return_msgs->msgs(0));
  verify_error_message(return_msgs->msgs(1), "Failed to find package unknown");
  verify_error_message(return_msgs->msgs(2), "Failed to find flag unknown");
}

TEST_F(AconfigdTest, nonexist_flag_query) {
  auto request_msgs = StorageRequestMessages();
  add_new_storage_message(request_msgs, temp_flag_vals_[7]);
  add_flag_query_message(
      request_msgs, "unknown", "enabled_rw");
  add_flag_query_message(
      request_msgs, "com.android.aconfig.storage.test_1", "unknown");
  auto return_msgs = send_message(request_msgs);
  ASSERT_TRUE(return_msgs.ok()) << return_msgs.error();
  verify_new_storage_return_message(return_msgs->msgs(0));
  verify_error_message(return_msgs->msgs(1), "Failed to find package unknown");
  verify_error_message(return_msgs->msgs(2), "Failed to find flag unknown");
}

TEST_F(AconfigdTest, local_override_survive_update) {
  auto request_msgs = StorageRequestMessages();
  add_new_storage_message(request_msgs, temp_flag_vals_[8]);
  add_flag_override_message(
      request_msgs, "com.android.aconfig.storage.test_1", "disabled_rw", "true", true);
  add_flag_query_message(
      request_msgs, "com.android.aconfig.storage.test_1", "disabled_rw");
  add_new_storage_message(request_msgs, temp_flag_vals_[9]);
  add_flag_query_message(
      request_msgs, "com.android.aconfig.storage.test_1", "disabled_rw");
  auto return_msgs = send_message(request_msgs);
  ASSERT_TRUE(return_msgs.ok()) << return_msgs.error();
  verify_new_storage_return_message(return_msgs->msgs(0));
  verify_flag_override_return_message(return_msgs->msgs(1));
  verify_flag_query_return_message(return_msgs->msgs(2), "false", "true", true, false, true);
  verify_new_storage_return_message(return_msgs->msgs(3));
  verify_flag_query_return_message(return_msgs->msgs(4), "false", "true", true, false, true);
}

} // namespace aconfigd
} // namespace android
