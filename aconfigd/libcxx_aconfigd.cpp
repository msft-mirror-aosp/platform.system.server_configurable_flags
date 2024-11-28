#include "libcxx_aconfigd.hpp"

#include <stdexcept>

#include "com_android_aconfig_new_storage.h"
#include "include/aconfigd.h"
#include "lib.rs.h"
#include "rust/cxx.h"

namespace aconfigdwrapper {

class CppAconfigd::impl {
  friend CppAconfigd;

 public:
  impl(const std::string& root_dir, const std::string& storage_records)
      : m_aconfigd(std::make_unique<android::aconfigd::Aconfigd>(
            root_dir, storage_records))

  {}

 private:
  std::unique_ptr<android::aconfigd::Aconfigd> m_aconfigd;
};

CppAconfigd::CppAconfigd(const std::string& str1, const std::string& str2)
    : impl(new class CppAconfigd::impl(str1, str2)) {}

CppVoidResult CppAconfigd::initialize_platform_storage() const {
  auto init_result = impl->m_aconfigd->InitializePlatformStorage();

  CppVoidResult result;
  if (!init_result.ok()) {
    result.error_message = init_result.error().message();
    result.status = CppResultStatus::Err;
  } else {
    result.status = CppResultStatus::Ok;
  }
  return result;
}

CppVoidResult CppAconfigd::initialize_mainline_storage() const {
  auto init_result = impl->m_aconfigd->InitializeMainlineStorage();

  CppVoidResult result;
  if (!init_result.ok()) {
    result.error_message = init_result.error().message();
    result.status = CppResultStatus::Err;
  } else {
    result.status = CppResultStatus::Ok;
  }
  return result;
}

CppVoidResult CppAconfigd::initialize_in_memory_storage_records() const {
  auto init_result = impl->m_aconfigd->InitializeInMemoryStorageRecords();

  CppVoidResult result;
  if (!init_result.ok()) {
    result.error_message = init_result.error().message();
    result.status = CppResultStatus::Err;
  } else {
    result.status = CppResultStatus::Ok;
  }
  return result;
}

CppStringResult CppAconfigd::handle_socket_request(
    const std::string& messages_string) const {
  auto request_messages = android::aconfigd::StorageRequestMessages{};
  request_messages.ParseFromString(messages_string);

  auto return_messages = android::aconfigd::StorageReturnMessages();
  for (auto& request : request_messages.msgs()) {
    auto* return_msg = return_messages.add_msgs();
    auto result = impl->m_aconfigd->HandleSocketRequest(request, *return_msg);
    if (!result.ok()) {
      auto* errmsg = return_msg->mutable_error_message();
      *errmsg = result.error().message();
    }
  }

  auto content = std::string();
  return_messages.SerializeToString(&content);

  CppStringResult result;
  result.data = std::make_unique<std::string>(content);
  result.status = CppResultStatus::Ok;
  return result;
}

std::unique_ptr<CppAconfigd> new_cpp_aconfigd(const std::string& str1,
                                              const std::string& str2) {
  return std::make_unique<CppAconfigd>(str1, str2);
}

}  // namespace aconfigdwrapper
