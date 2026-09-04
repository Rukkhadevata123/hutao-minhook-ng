use crate::{
    hooks::{features::GameContext, signatures::GameFunction::*, state},
    logger, scanner,
};
use std::{
    ffi::c_void,
    ptr,
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};
use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect};

const CALL_REL32: u8 = 0xE8;
const REL32_DISPLACEMENT: usize = 1;
const CALL_REL32_LEN: usize = 5;

const MOSAIC_CALL_PATCH: [u8; CALL_REL32_LEN] = [0xB8, 0x00, 0x00, 0x00, 0x00];

const SCAN_WINDOW: usize = 0x800;

struct CallSitePatch {
    addr: usize,
    original: [u8; CALL_REL32_LEN],
    patched: AtomicBool,
}

impl CallSitePatch {
    fn set(&self, enabled: bool) {
        if self.patched.load(Ordering::Relaxed) == enabled {
            return;
        }
        let bytes = if enabled {
            &MOSAIC_CALL_PATCH
        } else {
            &self.original
        };
        if unsafe { write_bytes(self.addr as *mut u8, bytes) } {
            self.patched.store(enabled, Ordering::Relaxed);
        }
    }
}

static PATCH: OnceLock<Option<CallSitePatch>> = OnceLock::new();

fn locate() -> Option<CallSitePatch> {
    let entry = state::helper(PlayerDiveMosaic);
    let effect = state::helper(DisplayEffect);
    if entry.is_null() || effect.is_null() {
        return None;
    }
    let call = find_mosaic_effect_call(entry, effect)?;
    logger::debug!("dive_mosaic: patch call={:p}", call);

    let mut original = [0u8; CALL_REL32_LEN];
    unsafe { ptr::copy_nonoverlapping(call as *const u8, original.as_mut_ptr(), CALL_REL32_LEN) };
    Some(CallSitePatch {
        addr: call as usize,
        original,
        patched: AtomicBool::new(false),
    })
}

fn find_mosaic_effect_call(entry: *mut c_void, effect: *mut c_void) -> Option<*mut c_void> {
    let base = entry as *const u8;
    let mut last = None;
    for i in 0..SCAN_WINDOW.saturating_sub(CALL_REL32_LEN) {
        let call = unsafe { base.add(i) };
        if unsafe { *call } != CALL_REL32 {
            continue;
        }
        let target = scanner::resolve_relative_address(
            call as *mut c_void,
            REL32_DISPLACEMENT,
            CALL_REL32_LEN,
        );
        if target == effect {
            last = Some(call as *mut c_void);
        }
    }
    last
}

unsafe fn write_bytes(addr: *mut u8, bytes: &[u8; CALL_REL32_LEN]) -> bool {
    let mut old_protect = 0u32;
    if unsafe {
        VirtualProtect(
            addr as _,
            CALL_REL32_LEN,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
    } == 0
    {
        return false;
    }
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), addr, CALL_REL32_LEN) };
    let _ = unsafe { VirtualProtect(addr as _, CALL_REL32_LEN, old_protect, &mut old_protect) };
    true
}

pub(crate) unsafe fn update_dive_mosaic(ctx: &mut GameContext<'_>) {
    let patch = PATCH.get_or_init(locate);
    if let Some(patch) = patch {
        patch.set(ctx.config.enable_dive_mosaic_override);
    }
}
