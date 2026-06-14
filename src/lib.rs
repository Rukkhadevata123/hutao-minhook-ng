mod config;
mod game;
mod hooks;
mod hutao_seh;
mod runtime;
mod scanner;

use std::ffi::c_void;
use std::ptr;
use windows_sys::Win32::Foundation::{HMODULE, TRUE};
use windows_sys::Win32::System::LibraryLoader::DisableThreadLibraryCalls;
use windows_sys::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};
use windows_sys::Win32::System::Threading::CreateThread;
use windows_sys::core::BOOL;

/// # Safety
/// Called by the Windows loader. `hinst` and `reason` must be the values supplied
/// for this DLL load event.
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "system" fn DllMain(hinst: HMODULE, reason: u32, _reserved: *mut c_void) -> BOOL {
    unsafe {
        match reason {
            DLL_PROCESS_ATTACH => {
                DisableThreadLibraryCalls(hinst);
                CreateThread(
                    ptr::null(),
                    0,
                    Some(runtime::run),
                    hinst,
                    0,
                    ptr::null_mut(),
                );
            }
            DLL_PROCESS_DETACH => {
                hooks::uninstall();
            }
            _ => {}
        }
        TRUE
    }
}
