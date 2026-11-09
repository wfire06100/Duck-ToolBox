//! Qualcomm KeymasterUtils ABI observed in the supplied arm64 client. Object layout
//! and symbols vary with firmware; existence checks cannot establish ABI compatibility.
//! Calls run in a disposable subprocess so vendor output and crashes stay isolated.

use std::{ffi::c_void, fs, mem::MaybeUninit, path::Path};

use anyhow::{Context, Result};
use libloading::Library;

use crate::{
    error::DeviceRkpError,
    protocol::{BUFFER_SIZE, response_payload},
    status::LIBRARY_PATH,
};

type Constructor = unsafe extern "C" fn(*mut c_void, i32);
type Destructor = unsafe extern "C" fn(*mut c_void);
type SendCommand = unsafe extern "C" fn(*mut c_void, *mut c_void, u32, *mut c_void, u32) -> i32;

// The reference client allocates 0x40 bytes for this vendor class. Keep allocation
// aligned and never inspect its fields; only its constructor/destructor may own them.
#[repr(C, align(16))]
struct VendorObject([MaybeUninit<u8>; 0x40]);

struct Session {
    object: Box<VendorObject>,
    destructor: Destructor,
    send: SendCommand,
    _library: Library,
}

impl Session {
    fn open() -> Result<Self> {
        // SAFETY: only this adapter resolves the fixed vendor ABI. It is called only
        // on Android arm64 and in an isolated worker; unsupported firmware may fail.
        let library: Library = unsafe {
            libloading::os::unix::Library::open(
                Some(LIBRARY_PATH),
                libc::RTLD_NOW | libc::RTLD_LOCAL,
            )
        }
        .context("load KeymasterUtils")?
        .into();
        let constructor = *unsafe {
            library.get::<Constructor>(
                b"_ZN14keymasterutils14KeymasterUtilsC1E26keymaster_security_level_t\0",
            )
        }
        .context("resolve KeymasterUtils constructor")?;
        let destructor =
            *unsafe { library.get::<Destructor>(b"_ZN14keymasterutils14KeymasterUtilsD1Ev\0") }
                .context("resolve KeymasterUtils destructor")?;
        let send = *unsafe {
            library.get::<SendCommand>(b"_ZN14keymasterutils14KeymasterUtils8send_cmdEPvjS1_j\0")
        }
        .context("resolve KeymasterUtils send_cmd")?;
        let mut object = Box::new(VendorObject([MaybeUninit::new(0); 0x40]));
        // SAFETY: aligned writable storage stays at a stable address until Drop.
        // security_level 1 is TRUSTED_ENVIRONMENT in the observed vendor interface.
        unsafe { constructor(object.as_mut() as *mut VendorObject as *mut c_void, 1) };
        Ok(Self {
            object,
            destructor,
            send,
            _library: library,
        })
    }

    fn request(&mut self, request: &[u8], dump_dir: Option<&Path>) -> Result<Vec<u8>> {
        let command = request
            .get(..4)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .map(u32::from_le_bytes)
            .unwrap_or(0);
        let mut request = request.to_vec();
        if let Some(directory) = dump_dir {
            // The exchange directory is a private 0700 temporary directory created by
            // the worker. Writing both sides makes firmware-specific TA framing debuggable.
            let _ = fs::write(directory.join("request.bin"), &request);
        }
        // A nonzero status sentinel prevents untouched response storage looking valid.
        let mut response = vec![0; BUFFER_SIZE];
        response[..4].copy_from_slice(&i32::MIN.to_le_bytes());
        // SAFETY: live class instance and disjoint writable buffers remain valid for
        // the synchronous call. Both sizes fit u32 and match their allocations.
        let status = unsafe {
            (self.send)(
                self.object.as_mut() as *mut VendorObject as *mut c_void,
                request.as_mut_ptr().cast(),
                request.len() as u32,
                response.as_mut_ptr().cast(),
                response.len() as u32,
            )
        };
        if let Some(directory) = dump_dir {
            let _ = fs::write(directory.join("response.bin"), &response);
        }
        if status != 0 {
            return Err(DeviceRkpError::Transport(format!(
                "send_cmd returned {status} for command 0x{command:04x}, request length {}",
                request.len()
            ))
            .into());
        }
        let response_status = i32::from_le_bytes(
            response[..4]
                .try_into()
                .expect("response buffer is at least four bytes"),
        );
        if response_status != 0 {
            let detail = format!(
                "command 0x{command:04x}, request length {}, response prefix {}",
                request.len(),
                hex_prefix(&response)
            );
            return Err(DeviceRkpError::RejectedWithDetail {
                status: response_status,
                detail,
            }
            .into());
        }
        response_payload(&response)
    }
}

fn hex_prefix(response: &[u8]) -> String {
    response
        .iter()
        .take(32)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: destructor runs once while both the object and library are live.
        unsafe { (self.destructor)(self.object.as_mut() as *mut VendorObject as *mut c_void) };
    }
}

pub(crate) fn request(bytes: &[u8], dump_dir: Option<&Path>) -> Result<Vec<u8>> {
    Session::open()?.request(bytes, dump_dir)
}
