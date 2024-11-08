//! Library for interacting with aconfigd.
use crate::ffi::{CppAconfigd, CppResultStatus, CppStringResult, CppVoidResult};
use cxx::{let_cxx_string, CxxString, UniquePtr};
use std::error::Error;
use std::fmt;

/// Wrapper for interacting with aconfigd.
pub struct Aconfigd {
    cpp_aconfigd: UniquePtr<CppAconfigd>,
}

impl Aconfigd {
    /// Create a new Aconfigd.
    pub fn new(root_dir: &str, persist_storage_records: &str) -> Self {
        let_cxx_string!(root_dir_ = root_dir);
        let_cxx_string!(persist_storage_records_ = persist_storage_records);
        Self { cpp_aconfigd: ffi::new_cpp_aconfigd(&root_dir_, &persist_storage_records_) }
    }

    /// Create persistent storage files for platform partition.
    pub fn initialize_platform_storage(&self) -> Result<(), CppAconfigdError> {
        self.cpp_aconfigd.initialize_platform_storage().into()
    }

    /// Create persistent storage files for mainline modules.
    pub fn initialize_mainline_storage(&self) -> Result<(), CppAconfigdError> {
        self.cpp_aconfigd.initialize_mainline_storage().into()
    }

    /// Read storage records into memory.
    pub fn initialize_in_memory_storage_records(&self) -> Result<(), CppAconfigdError> {
        self.cpp_aconfigd.initialize_in_memory_storage_records().into()
    }

    /// Process a `StorageRequestMessages`, and return the bytes of a `StorageReturnMessages`.
    ///
    /// `messages_bytes` should contain the serialized bytes of a `StorageRequestMessages`.
    pub fn handle_socket_request(
        &self,
        messages_bytes: &[u8],
    ) -> Result<Vec<u8>, CppAconfigdError> {
        let_cxx_string!(messages_string_ = messages_bytes);
        let res: Result<UniquePtr<CxxString>, CppAconfigdError> =
            self.cpp_aconfigd.handle_socket_request(&messages_string_).into();
        res.map(|s| s.as_bytes().to_vec())
    }
}

/// Represents an error in the C++ aconfigd.
///
/// The C++ aconfigd uses the C++ Result type. Result errors are mapped
/// to this type.
#[derive(Debug)]
pub struct CppAconfigdError {
    msg: String,
}

impl CppAconfigdError {
    pub fn new(msg: &str) -> Self {
        Self { msg: msg.to_string() }
    }
}

impl fmt::Display for CppAconfigdError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "CppAconfigd error: {}", self.msg)
    }
}

impl Error for CppAconfigdError {}

#[cxx::bridge(namespace = "aconfigdwrapper")]
mod ffi {
    enum CppResultStatus {
        Ok,
        Err,
    }

    struct CppVoidResult {
        error_message: String,
        status: CppResultStatus,
    }

    struct CppStringResult {
        data: UniquePtr<CxxString>,
        error_message: String,
        status: CppResultStatus,
    }

    unsafe extern "C++" {
        include!("libcxx_aconfigd.hpp");

        type CppAconfigd;

        fn new_cpp_aconfigd(str1: &CxxString, str2: &CxxString) -> UniquePtr<CppAconfigd>;
        fn initialize_platform_storage(&self) -> CppVoidResult;
        fn initialize_mainline_storage(&self) -> CppVoidResult;

        fn initialize_in_memory_storage_records(&self) -> CppVoidResult;
        fn handle_socket_request(&self, message_string: &CxxString) -> CppStringResult;
    }
}

impl Into<Result<(), CppAconfigdError>> for CppVoidResult {
    fn into(self) -> Result<(), CppAconfigdError> {
        match self.status {
            CppResultStatus::Ok => Ok(()),
            CppResultStatus::Err => Err(CppAconfigdError::new(&self.error_message)),
            _ => Err(CppAconfigdError::new("unknown status")),
        }
    }
}

impl Into<Result<UniquePtr<CxxString>, CppAconfigdError>> for CppStringResult {
    fn into(self) -> Result<UniquePtr<CxxString>, CppAconfigdError> {
        match self.status {
            CppResultStatus::Ok => Ok(self.data),
            CppResultStatus::Err => Err(CppAconfigdError::new(&self.error_message)),
            _ => Err(CppAconfigdError::new("unknown status")),
        }
    }
}
