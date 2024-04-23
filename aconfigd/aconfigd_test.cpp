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

  return return_messages;
}

base::Result<StorageReturnMessages> send_new_storage_message() {
  auto messages = StorageRequestMessages{};
  auto* message = messages.add_msgs();
  auto* msg = message->mutable_new_storage_message();
  auto test_dir = base::GetExecutableDirectory();
  msg->set_container("mockup");
  msg->set_package_map(test_dir + "/tests/package.map");
  msg->set_flag_map(test_dir + "/tests/flag.map");
  msg->set_flag_value(test_dir + "/tests/flag.val");
  return send_message(messages);
}

base::Result<StorageReturnMessages> send_flag_override_message(const std::string& package,
                                                               const std::string& flag,
                                                               const std::string& value,
                                                               bool is_local) {
  auto messages = StorageRequestMessages{};
  auto* message = messages.add_msgs();
  auto* msg = message->mutable_flag_override_message();
  msg->set_package_name(package);
  msg->set_flag_name(flag);
  msg->set_flag_value(value);
  msg->set_is_local(is_local);
  return send_message(messages);
}

base::Result<StorageReturnMessages> send_flag_query_message(const std::string& package,
                                                            const std::string& flag) {
  auto messages = StorageRequestMessages{};
  auto* message = messages.add_msgs();
  auto* msg = message->mutable_flag_query_message();
  msg->set_package_name(package);
  msg->set_flag_name(flag);
  return send_message(messages);
}

TEST(aconfigd_socket, new_storage_message) {
  auto new_storage_result = send_new_storage_message();
  ASSERT_TRUE(new_storage_result.ok()) << new_storage_result.error();
  ASSERT_EQ(new_storage_result->msgs_size(), 1);
  auto return_message = new_storage_result->msgs(0);
  ASSERT_TRUE(return_message.has_new_storage_message());

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

TEST(aconfigd_socket, flag_server_override_message) {
  auto new_storage_result = send_new_storage_message();
  ASSERT_TRUE(new_storage_result.ok()) << new_storage_result.error();
  ASSERT_EQ(new_storage_result->msgs_size(), 1);
  auto return_message = new_storage_result->msgs(0);
  ASSERT_TRUE(return_message.has_new_storage_message());

  auto flag_override_result = send_flag_override_message(
      "com.android.aconfig.storage.test_1", "enabled_rw", "true", false);
  ASSERT_TRUE(flag_override_result.ok()) << flag_override_result.error();
  ASSERT_EQ(flag_override_result->msgs_size(), 1);
  return_message = flag_override_result->msgs(0);
  ASSERT_TRUE(return_message.has_flag_override_message())
      << return_message.error_message();

  auto flag_query_result = send_flag_query_message(
      "com.android.aconfig.storage.test_1", "enabled_rw");
  ASSERT_TRUE(flag_query_result.ok()) << flag_query_result.error();
  ASSERT_EQ(flag_query_result->msgs_size(), 1);
  return_message = flag_query_result->msgs(0);
  ASSERT_TRUE(return_message.has_flag_query_message());
  auto query = return_message.flag_query_message();
  ASSERT_EQ(query.server_flag_value(), "true");
  ASSERT_EQ(query.local_flag_value(), "");
  ASSERT_EQ(query.is_readwrite(), true);
  ASSERT_EQ(query.has_server_override(), true);
  ASSERT_EQ(query.has_local_override(), false);

  flag_override_result = send_flag_override_message(
      "com.android.aconfig.storage.test_1", "enabled_rw", "false", false);
  ASSERT_TRUE(flag_override_result.ok()) << flag_override_result.error();
  ASSERT_EQ(flag_override_result->msgs_size(), 1);
  return_message = flag_override_result->msgs(0);
  ASSERT_TRUE(return_message.has_flag_override_message());

  flag_query_result = send_flag_query_message(
      "com.android.aconfig.storage.test_1", "enabled_rw");
  ASSERT_TRUE(flag_query_result.ok()) << flag_query_result.error();
  ASSERT_EQ(flag_query_result->msgs_size(), 1);
  return_message = flag_query_result->msgs(0);
  ASSERT_TRUE(return_message.has_flag_query_message());
  query = return_message.flag_query_message();
  ASSERT_EQ(query.server_flag_value(), "false");
  ASSERT_EQ(query.local_flag_value(), "");
  ASSERT_EQ(query.is_readwrite(), true);
  ASSERT_EQ(query.has_server_override(), true);
  ASSERT_EQ(query.has_local_override(), false);
}

TEST(aconfigd_socket, flag_local_override_message) {
  auto new_storage_result = send_new_storage_message();
  ASSERT_TRUE(new_storage_result.ok()) << new_storage_result.error();
  ASSERT_EQ(new_storage_result->msgs_size(), 1);
  auto return_message = new_storage_result->msgs(0);
  ASSERT_TRUE(return_message.has_new_storage_message());

  auto flag_override_result = send_flag_override_message(
      "com.android.aconfig.storage.test_1", "disabled_rw", "true", true);
  ASSERT_TRUE(flag_override_result.ok()) << flag_override_result.error();
  ASSERT_EQ(flag_override_result->msgs_size(), 1);
  return_message = flag_override_result->msgs(0);
  ASSERT_TRUE(return_message.has_flag_override_message())
      << return_message.error_message();

  auto flag_query_result = send_flag_query_message(
      "com.android.aconfig.storage.test_1", "disabled_rw");
  ASSERT_TRUE(flag_query_result.ok()) << flag_query_result.error();
  ASSERT_EQ(flag_query_result->msgs_size(), 1);
  return_message = flag_query_result->msgs(0);
  ASSERT_TRUE(return_message.has_flag_query_message());
  auto query = return_message.flag_query_message();
  ASSERT_EQ(query.server_flag_value(), "false");
  ASSERT_EQ(query.local_flag_value(), "true");
  ASSERT_EQ(query.is_readwrite(), true);
  ASSERT_EQ(query.has_server_override(), false);
  ASSERT_EQ(query.has_local_override(), true);

  flag_override_result = send_flag_override_message(
      "com.android.aconfig.storage.test_1", "disabled_rw", "false", true);
  ASSERT_TRUE(flag_override_result.ok()) << flag_override_result.error();
  ASSERT_EQ(flag_override_result->msgs_size(), 1);
  return_message = flag_override_result->msgs(0);
  ASSERT_TRUE(return_message.has_flag_override_message());

  flag_query_result = send_flag_query_message(
      "com.android.aconfig.storage.test_1", "disabled_rw");
  ASSERT_TRUE(flag_query_result.ok()) << flag_query_result.error();
  ASSERT_EQ(flag_query_result->msgs_size(), 1);
  return_message = flag_query_result->msgs(0);
  ASSERT_TRUE(return_message.has_flag_query_message());
  query = return_message.flag_query_message();
  ASSERT_EQ(query.server_flag_value(), "false");
  ASSERT_EQ(query.local_flag_value(), "false");
  ASSERT_EQ(query.is_readwrite(), true);
  ASSERT_EQ(query.has_server_override(), false);
  ASSERT_EQ(query.has_local_override(), true);
}

TEST(aconfigd_socket, nonexist_flag_override_message) {
  auto new_storage_result = send_new_storage_message();
  ASSERT_TRUE(new_storage_result.ok()) << new_storage_result.error();
  ASSERT_EQ(new_storage_result->msgs_size(), 1);
  auto return_message = new_storage_result->msgs(0);
  ASSERT_TRUE(return_message.has_new_storage_message());

  auto flag_override_result = send_flag_override_message(
      "unknown", "enabled_rw", "true", false);
  ASSERT_TRUE(flag_override_result.ok()) << flag_override_result.error();
  ASSERT_EQ(flag_override_result->msgs_size(), 1);
  return_message = flag_override_result->msgs(0);
  ASSERT_TRUE(return_message.has_error_message());
  auto errmsg = return_message.error_message();
  ASSERT_TRUE(errmsg.find("Failed to find package unknown") != std::string::npos);

  flag_override_result = send_flag_override_message(
      "com.android.aconfig.storage.test_1", "unknown", "true", false);
  ASSERT_TRUE(flag_override_result.ok()) << flag_override_result.error();
  ASSERT_EQ(flag_override_result->msgs_size(), 1);
  return_message = flag_override_result->msgs(0);
  ASSERT_TRUE(return_message.has_error_message());
  errmsg = return_message.error_message();
  ASSERT_TRUE(errmsg.find("Failed to find flag unknown") != std::string::npos);
}

TEST(aconfigd_socket, nonexist_flag_query_message) {
  auto new_storage_result = send_new_storage_message();
  ASSERT_TRUE(new_storage_result.ok()) << new_storage_result.error();
  ASSERT_EQ(new_storage_result->msgs_size(), 1);
  auto return_message = new_storage_result->msgs(0);
  ASSERT_TRUE(return_message.has_new_storage_message());

  auto flag_query_result = send_flag_query_message(
      "unknown", "enabled_rw");
  ASSERT_TRUE(flag_query_result.ok()) << flag_query_result.error();
  ASSERT_EQ(flag_query_result->msgs_size(), 1);
  return_message = flag_query_result->msgs(0);
  ASSERT_TRUE(return_message.has_error_message());
  auto query = return_message.flag_query_message();
  auto errmsg = return_message.error_message();
  ASSERT_TRUE(errmsg.find("Failed to find package unknown") != std::string::npos);

 flag_query_result = send_flag_query_message(
      "com.android.aconfig.storage.test_1", "unknown");
  ASSERT_TRUE(flag_query_result.ok()) << flag_query_result.error();
  ASSERT_EQ(flag_query_result->msgs_size(), 1);
  return_message = flag_query_result->msgs(0);
  ASSERT_TRUE(return_message.has_error_message());
  query = return_message.flag_query_message();
  errmsg = return_message.error_message();
  ASSERT_TRUE(errmsg.find("Failed to find flag unknown") != std::string::npos);
}

} // namespace aconfigd
} // namespace android
