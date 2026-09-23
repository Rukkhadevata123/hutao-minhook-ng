use std::ptr;
use windows_sys::Win32::{
    Foundation::ERROR_SUCCESS,
    System::Registry::{
        HKEY_CURRENT_USER, KEY_SET_VALUE, REG_DWORD, REG_OPTION_NON_VOLATILE, RegCloseKey,
        RegCreateKeyExW, RegSetValueExW,
    },
};

pub fn enable() -> Result<(), u32> {
    let key_path: Vec<u16> = "Software\\miHoYo\\原神\0".encode_utf16().collect();
    let value_name: Vec<u16> = "WINDOWS_HDR_ON_h3132281285\0".encode_utf16().collect();
    let mut key = ptr::null_mut();

    unsafe {
        let status = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            key_path.as_ptr(),
            0,
            ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            ptr::null(),
            &mut key,
            ptr::null_mut(),
        );
        if status != ERROR_SUCCESS {
            return Err(status);
        }

        let enabled = 1u32.to_le_bytes();
        let status = RegSetValueExW(
            key,
            value_name.as_ptr(),
            0,
            REG_DWORD,
            enabled.as_ptr(),
            enabled.len() as u32,
        );
        RegCloseKey(key);

        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(status)
        }
    }
}
