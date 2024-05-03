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

#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>
#include <sys/un.h>

#include "com_android_aconfig_new_storage.h"
#include "aconfigd.h"
#include "aconfigd_util.h"

using namespace android::aconfigd;
using namespace android::base;

static int aconfigd_init() {
  auto init_result = InitializeInMemoryStorageRecords();
  if (!init_result.ok()) {
    LOG(ERROR) << "Failed to initialize persistent storage records in memory: "
               << init_result.error();
    return 1;
  }

  // TODO: remove this check once b/330134027 is fixed. This is temporary as android
  // on chrome os vm does not have /metadata partition at the moment.
  DIR* dir = opendir("/metadata/aconfig");
  if (!dir) {
    return {};
  }
  closedir(dir);

  // clear boot dir to start fresh at each boot
  auto remove_result = RemoveFilesInDir("/metadata/aconfig/boot");
  if (!remove_result.ok()) {
    LOG(ERROR) <<"failed to clear boot dir: " << remove_result.error();
    return 1;
  }

  auto plat_result = InitializePlatformStorage();
  if (!plat_result.ok()) {
    LOG(ERROR) << "failed to initialize storage records: " << plat_result.error();
    return 1;
  }

  return 0;
}

/// receive storage requests from socket
static Result<StorageRequestMessages> receiveMessage(int client_fd) {
  unsigned char size_buffer[4] = {};
  auto num_bytes = TEMP_FAILURE_RETRY(
      recv(client_fd, size_buffer, 4, 0));
  if (num_bytes < 0) {
    return ErrnoError() << "failed to read number of bytes from aconfigd socket";
  } else if (num_bytes != 4) {
    return Error() << "expecting 4 bytes from aconfigd socket, received " << num_bytes;
  }
  uint32_t payload_size = uint32_t(
      size_buffer[0]<<24 | size_buffer[1]<<16 | size_buffer[2]<<8 | size_buffer[3]);

  char payload_buffer[payload_size];
  num_bytes = TEMP_FAILURE_RETRY(
      recv(client_fd, payload_buffer, payload_size, 0));
  if (num_bytes < 0) {
    return ErrnoError() << "failed to read payload from aconfigd socket";
  } else if (num_bytes != payload_size) {
    return Error() << "expecting " << payload_size
                   << " bytes of payload from aconfigd socket, received " << num_bytes;
  }
  auto msg = std::string(payload_buffer, num_bytes);

  auto requests = StorageRequestMessages{};
  if (!requests.ParseFromString(msg)) {
      return Error() << "Could not parse message from aconfig storage init socket";
  }
  return requests;
}

/// send return acknowledgement
static Result<void> sendMessage(int client_fd, const StorageReturnMessages& msg) {
  auto content = std::string();
  if (!msg.SerializeToString(&content)) {
    return Error() << "failed to serialize return messages to string";
  }

  unsigned char bytes[4];
  uint32_t msg_size = content.size();
  bytes[0] = (msg_size >> 24) & 0xFF;
  bytes[1] = (msg_size >> 16) & 0xFF;
  bytes[2] = (msg_size >> 8) & 0xFF;
  bytes[3] = (msg_size >> 0) & 0xFF;

  auto num_bytes = TEMP_FAILURE_RETRY(send(client_fd, bytes, 4, 0));
  if (num_bytes < 0) {
    return ErrnoError() << "send() failed for return msg size";
  } else if (num_bytes != 4) {
    return Error() << "send() failed for return msg size, sent " << num_bytes
                   << " bytes expect 4 bytes";
  }

  num_bytes = TEMP_FAILURE_RETRY(send(client_fd, content.c_str(), content.size(), 0));
  if (num_bytes < 0) {
    return ErrnoError() << "send() failed for return msg";
  } else if (num_bytes != content.size()) {
    return Error() << "send() failed for return msg, sent " << num_bytes
                   << " bytes expect " << content.size() << " bytes";
  }

  return {};
}

static int aconfigd_start() {
  auto init_result = InitializeInMemoryStorageRecords();
  if (!init_result.ok()) {
    LOG(ERROR) << "Failed to initialize persistent storage records in memory: "
               << init_result.error();
    return 1;
  }

  auto aconfigd_fd = android::base::unique_fd(android_get_control_socket(kAconfigdSocket));
  if (aconfigd_fd == -1) {
    PLOG(ERROR) << "failed to get aconfigd socket";
    return 1;
  }

  if (listen(aconfigd_fd, 8) < 0) {
    PLOG(ERROR) << "failed to listen to socket";
    return 1;
  };

  auto addr = sockaddr_un();
  addr.sun_family = AF_UNIX;
  auto path = std::string("/dev/socket/") + kAconfigdSocket;
  strlcpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path));
  socklen_t addr_len = sizeof(addr);

  while(true) {
    LOG(INFO) << "start accepting client requests";
    auto client_fd = android::base::unique_fd(accept4(
        aconfigd_fd, reinterpret_cast<sockaddr*>(&addr), &addr_len, SOCK_CLOEXEC));
    if (client_fd == -1) {
      PLOG(ERROR) << "failed to establish connection";
      continue;
    }
    LOG(INFO) << "received client requests";

    auto requests = receiveMessage(client_fd.get());
    if (!requests.ok()) {
      LOG(ERROR) << requests.error();
      continue;
    }

    auto return_messages = StorageReturnMessages();
    for (auto& request : requests->msgs()) {
      auto* return_msg = return_messages.add_msgs();
      HandleSocketRequest(request, *return_msg);
    }

    auto result = sendMessage(client_fd.get(), return_messages);
    if (!result.ok()) {
      LOG(ERROR) << result.error();
    }
  }

  return 1;
}

int main(int argc, char** argv) {
  if (!com::android::aconfig_new_storage::enable_aconfig_storage_daemon()) {
    return 0;
  }

  android::base::InitLogging(argv, &android::base::KernelLogger);

  if (argc > 2 || (argc == 2 && strcmp("--initialize", argv[1]) != 0)) {
    LOG(ERROR) << "invalid aconfigd command";
    return 1;
  }

  if (argc == 2 && strcmp("--initialize", argv[1]) == 0) {
    return aconfigd_init();
  }

  return aconfigd_start();
}
