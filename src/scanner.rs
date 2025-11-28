use crate::hutao_seh::try_seh;
use std::ffi::c_void;
use std::ptr;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::SystemInformation::*;

/// Represents a memory region that is safe to scan.
struct RegionInfo {
    base: *mut c_void,
    size: usize,
}

fn is_readable_or_executable(protect: u32) -> bool {
    protect == PAGE_EXECUTE_READ
        || protect == PAGE_EXECUTE_READWRITE
        || protect == PAGE_EXECUTE_WRITECOPY
        || protect == PAGE_EXECUTE
        || protect == PAGE_READONLY
        || protect == PAGE_READWRITE
        || protect == PAGE_WRITECOPY
}

/// Retrieves all committed and readable memory regions in the process.
fn get_memory_regions() -> Vec<RegionInfo> {
    let mut regions = Vec::new();
    unsafe {
        let mut sys_info: SYSTEM_INFO = std::mem::zeroed();
        GetSystemInfo(&mut sys_info);

        let mut start = sys_info.lpMinimumApplicationAddress as usize;
        let end = sys_info.lpMaximumApplicationAddress as usize;

        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();

        while start < end {
            if VirtualQuery(
                start as *const c_void,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            ) == 0
            {
                break;
            }

            if mbi.State == MEM_COMMIT && is_readable_or_executable(mbi.Protect) {
                regions.push(RegionInfo {
                    base: mbi.BaseAddress,
                    size: mbi.RegionSize,
                });
            }

            start += mbi.RegionSize;
        }
    }
    regions
}

/// Parses a pattern string (e.g., "E8 ? ? ? ? 48") into a vector of bytes and masks.
/// None represents a wildcard (?).
fn parse_pattern(pattern: &str) -> Vec<Option<u8>> {
    pattern
        .split_whitespace()
        .map(|s| {
            if s == "?" || s == "??" {
                None
            } else {
                u8::from_str_radix(s, 16).ok()
                // This is equivalent to just using .ok() though
            }
        })
        .collect()
}

/// Scans a specific memory region for the pattern.
/// Wrapped in SEH to handle potential access violations safely.
fn scan_region(
    region_base: *mut c_void,
    region_size: usize,
    pattern: &[Option<u8>],
) -> Option<*mut c_void> {
    let pattern_len = pattern.len();
    if region_size < pattern_len {
        return None;
    }

    // Use try_seh to catch Access Violations during memory read
    let result = try_seh(|| unsafe {
        let base = region_base as *const u8;
        let end = region_size - pattern_len;

        for i in 0..=end {
            let mut found = true;
            for (j, &byte_pattern) in pattern.iter().enumerate() {
                if let Some(b) = byte_pattern
                    && *base.add(i + j) != b
                {
                    found = false;
                    break;
                }
            }
            if found {
                return Some(base.add(i) as *mut c_void);
            }
        }
        None
    });

    match result {
        Ok(Some(addr)) => Some(addr),
        Ok(None) => None,
        Err(_) => {
            // Access Violation occurred in this region, skip it
            None
        }
    }
}

/// Main entry point for pattern scanning.
/// Scans all valid memory regions for the given pattern string.
pub fn scan(pattern: &str) -> *mut c_void {
    let parsed_pattern = parse_pattern(pattern);
    let regions = get_memory_regions();

    for region in regions {
        if let Some(addr) = scan_region(region.base, region.size, &parsed_pattern) {
            return addr;
        }
    }

    ptr::null_mut()
}

/// Resolves a relative address (common in x64 JMP/CALL instructions).
///
/// # Arguments
/// * `instruction_addr` - The address of the instruction (e.g., the start of E8 ...)
/// * `offset` - The offset to the relative displacement value (usually 1 for E8/E9)
/// * `instruction_size` - The total size of the instruction (usually 5 for E8/E9)
pub fn resolve_relative_address(
    instruction_addr: *mut c_void,
    offset: usize,
    instruction_size: usize,
) -> *mut c_void {
    if instruction_addr.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        let instr_addr_val = instruction_addr as usize;
        let relative_offset_ptr = (instr_addr_val + offset) as *const i32;

        // Read the 32-bit relative offset
        let relative_offset = *relative_offset_ptr;

        // Target = Instruction Address + Instruction Size + Relative Offset
        let target_addr =
            (instr_addr_val + instruction_size).wrapping_add(relative_offset as usize);

        target_addr as *mut c_void
    }
}
