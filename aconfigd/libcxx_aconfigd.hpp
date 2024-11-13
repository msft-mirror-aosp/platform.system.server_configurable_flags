#pragma once

#include "include/aconfigd.h"
#include "rust/cxx.h"

namespace aconfigdwrapper {

struct CppVoidResult;
struct CppStringResult;
enum class CppResultStatus : uint8_t;

class CppAconfigd {
 public:
  CppAconfigd(const std::string& aconfigd_root_dir,
              const std::string& storage_records);
  CppVoidResult initialize_platform_storage() const;
  CppVoidResult initialize_mainline_storage() const;
  CppVoidResult initialize_in_memory_storage_records() const;
  CppStringResult handle_socket_request(
      const std::string& messages_string) const;

 private:
  class impl;
  std::shared_ptr<impl> impl;
};

std::unique_ptr<CppAconfigd> new_cpp_aconfigd(const std::string& str1,
                                              const std::string& str2);
}  // namespace aconfigdwrapper
