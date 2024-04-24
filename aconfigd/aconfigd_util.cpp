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
#include <sys/sendfile.h>
#include <fts.h>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>

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

bool FileNonZeroSize(const std::string& file) {
  struct stat st;
  return stat(file.c_str(), &st) == 0 ? st.st_size > 0 : false;
}

} // namespace aconfig
} // namespace android
