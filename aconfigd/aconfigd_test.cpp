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

TEST(aconfigd_socket, new_storage_message) {
  auto sock_fd = connect_aconfigd_socket();
  ASSERT_TRUE(sock_fd.ok()) << strerror(errno);

  auto message = StorageMessage{};
  auto msg = message.mutable_new_storage_message();
  auto test_dir = base::GetExecutableDirectory();
  msg->set_container("test");
  msg->set_package_map(test_dir + "/tests/package.map");
  msg->set_flag_map(test_dir + "/tests/flag.map");
  msg->set_flag_value(test_dir + "/tests/flag.val");

  auto message_string = std::string();
  ASSERT_TRUE(message.SerializeToString(&message_string));

  auto result = TEMP_FAILURE_RETRY(
      send(*sock_fd, message_string.c_str(), message_string.size(), 0));
  ASSERT_EQ(result, static_cast<long>(message_string.size())) << strerror(errno);

  auto pb_file = "/metadata/aconfig/available_storage_file_records.pb";
  auto records_pb = storage_records_pb();
  auto content = std::string();
  ASSERT_TRUE(base::ReadFileToString(pb_file, &content)) << strerror(errno);
  ASSERT_TRUE(records_pb.ParseFromString(content)) << strerror(errno);

  bool found = false;
  for (auto& entry : records_pb.files()) {
    if (entry.container() == "test") {
      found = true;
      break;
    }
  }
  ASSERT_TRUE(found);
}

} // namespace aconfigd
} // namespace android
