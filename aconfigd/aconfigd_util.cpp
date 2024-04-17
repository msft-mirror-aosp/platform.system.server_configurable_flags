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

#include <memory>
#include <vector>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <android-base/file.h>
#include <sys/sendfile.h>
#include <fts.h>

#include "aconfigd_util.h"

using namespace android::base;

namespace android {
namespace aconfigd {

/// Remove all files in a dir
Result<void> RemoveFilesInDir(const std::string& dir) {
  auto dir_cstr = std::unique_ptr<char[]>(new char[dir.length() + 1]);
  strcpy(dir_cstr.get(), dir.c_str());
  char* path[2] {dir_cstr.get(), nullptr};

  FTS* file_system = fts_open(path, FTS_NOCHDIR, 0);
  if (!file_system) {
    return ErrnoError() << "fts_open() failed";
  }

  auto to_delete = std::vector<std::string>();
  FTSENT* node = nullptr;
  while ((node = fts_read(file_system))){
    if (node->fts_info & FTS_F) {
      to_delete.emplace_back(std::string(node->fts_path));
    }
  }

  for (const auto& file : to_delete) {
    if (unlink(file.c_str()) == -1) {
      return ErrnoError() << "unlink() failed for " << file;
    }
  }

  return {};
}

/// Copy file
Result<void> CopyFile(const std::string& src, const std::string& dst, mode_t mode) {
  android::base::unique_fd src_fd(
      TEMP_FAILURE_RETRY(open(src.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)));
  if (src_fd == -1) {
    return ErrnoError() << "open() failed for " << src;
  }

  android::base::unique_fd dst_fd(TEMP_FAILURE_RETRY(
      open(dst.c_str(), O_WRONLY | O_CREAT | O_NOFOLLOW | O_TRUNC | O_CLOEXEC, 0644)));
  if (dst_fd == -1) {
    return ErrnoError() << "open() failed for " << dst;
  }

  struct stat st;
  if (fstat(src_fd.get(), &st) == -1) {
    return ErrnoError() << "fstat() failed";
  }
  auto len = st.st_size;

  if (sendfile(dst_fd, src_fd, nullptr, len) == -1) {
    return ErrnoError() << "sendfile() failed";
  }

  if (chmod(dst.c_str(), mode) == -1) {
    return ErrnoError() << "chmod() failed";
  }

  return {};
}

/// Get a file's timestamp
Result<int> GetFileTimeStamp(const std::string& file) {
  struct stat st;
  int result = stat(file.c_str(), &st);
  if (result == -1) {
    return ErrnoError() << "stat() failed";
  }
  return static_cast<int>(st.st_mtim.tv_sec);
}

bool FileExists(const std::string& file) {
  struct stat st;
  return stat(file.c_str(), &st) == 0 ? true : false;
}

/// Read persistent aconfig storage records pb file
Result<aconfig_storage_metadata::storage_files> ReadStorageRecordsPb(
    const std::string& pb_file) {
  auto records = aconfig_storage_metadata::storage_files();
  if (FileExists(pb_file)) {
    auto content = std::string();
    if (!ReadFileToString(pb_file, &content)) {
      return ErrnoError() << "ReadFileToString failed";
    }

    if (!records.ParseFromString(content)) {
      return ErrnoError() << "Unable to parse storage records protobuf";
    }
  }
  return records;
}

/// Write aconfig storage records protobuf to file
Result<void> WriteStorageRecordsPbToFile(
    const aconfig_storage_metadata::storage_files& records_pb,
    const std::string& file_name) {
  auto content = std::string();
  if (!records_pb.SerializeToString(&content)) {
    return ErrnoError() << "Unable to serialize storage records protobuf";
  }

  if (!WriteStringToFile(content, file_name)) {
    return ErrnoError() << "WriteStringToFile failed";
  }

  if (chmod(file_name.c_str(), 0644) == -1) {
    return ErrnoError() << "chmod() failed";
  };

  return {};
}

} // namespace aconfig
} // namespace android
