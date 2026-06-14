use std::ffi::c_void;

#[repr(C)]
pub struct Il2CppObject {
    pub klass: *mut c_void,
    pub monitor: *mut c_void,
}

#[repr(C)]
pub struct Il2CppString {
    pub object: Il2CppObject,
    pub length: i32,
    pub chars: [u16; 32],
}
