use crate::hooks::signatures::GameFunction;
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

static ORIGINALS: [AtomicPtr<c_void>; GameFunction::COUNT] =
    [const { AtomicPtr::new(ptr::null_mut()) }; GameFunction::COUNT];
static HELPERS: [AtomicPtr<c_void>; GameFunction::COUNT] =
    [const { AtomicPtr::new(ptr::null_mut()) }; GameFunction::COUNT];
static GAME_UPDATE_READY: AtomicBool = AtomicBool::new(false);

#[derive(Default)]
pub struct HookBindings {
    originals: Vec<(GameFunction, *mut c_void)>,
    helpers: Vec<(GameFunction, *mut c_void)>,
}

impl HookBindings {
    pub fn set_original(&mut self, function: GameFunction, ptr: *mut c_void) {
        self.originals.push((function, ptr));
    }

    pub fn set_helper(&mut self, function: GameFunction, ptr: *mut c_void) {
        self.helpers.push((function, ptr));
    }
}

pub fn publish(bindings: HookBindings) {
    clear();

    for (function, ptr) in bindings.originals {
        ORIGINALS[function.as_index()].store(ptr, Ordering::Relaxed);
    }

    for (function, ptr) in bindings.helpers {
        HELPERS[function.as_index()].store(ptr, Ordering::Relaxed);
    }
}

pub fn clear() {
    for original in ORIGINALS.iter() {
        original.store(ptr::null_mut(), Ordering::Relaxed);
    }

    for helper in HELPERS.iter() {
        helper.store(ptr::null_mut(), Ordering::Relaxed);
    }

    GAME_UPDATE_READY.store(false, Ordering::Relaxed);
}

pub fn original(function: GameFunction) -> *mut c_void {
    ORIGINALS[function.as_index()].load(Ordering::Relaxed)
}

pub fn helper(function: GameFunction) -> *mut c_void {
    HELPERS[function.as_index()].load(Ordering::Relaxed)
}

pub fn mark_game_update_ready() {
    GAME_UPDATE_READY.store(true, Ordering::Relaxed);
}

pub fn is_game_update_ready() -> bool {
    GAME_UPDATE_READY.load(Ordering::Relaxed)
}
