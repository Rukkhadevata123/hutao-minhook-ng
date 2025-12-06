use crate::hutao_seh::try_seh;
use std::collections::HashSet;
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
                size_of::<MEMORY_BASIC_INFORMATION>(),
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
) -> Vec<*mut c_void> {
    let pattern_len = pattern.len();
    if region_size < pattern_len {
        return Vec::new();
    }

    // Use try_seh to catch Access Violations during memory read
    let result = try_seh(|| unsafe {
        let mut results: Vec<*mut c_void> = Vec::new();
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
                results.push(base.add(i) as *mut c_void);
            }
        }
        results
    });

    result.unwrap_or_else(|_| {
        // Access Violation occurred in this region, skip it
        Vec::new()
    })
}

/// Scans all valid memory regions for the given pattern string up to `limit` matches.
/// Returns a Vec of found addresses (maybe empty).
pub fn scan_limit(pattern: &str, limit: usize) -> Vec<*mut c_void> {
    let parsed_pattern = parse_pattern(pattern);
    let regions = get_memory_regions();

    let mut all = Vec::new();
    for region in regions {
        let mut found = scan_region(region.base, region.size, &parsed_pattern);
        for addr in found.drain(..) {
            all.push(addr);
            if all.len() >= limit {
                return all;
            }
        }
    }
    all
}

/// Helper that tries to read offsets from config first (key under [Offsets]).
/// If none present, scans for all matches of `pattern`, resolves relative
/// addresses `resolve_times` times (0 = no resolve), writes found offsets
/// back to config (comma-separated hex) and returns the first found address
/// or null if none.
pub fn get_or_scan(key: &str, pattern: &str, resolve_times: u8) -> *mut c_void {
    // Try read from config first
    let cfg_addrs = crate::config::load_offsets(key);
    if !cfg_addrs.is_empty() {
        return cfg_addrs[0] as *mut c_void;
    }

    // Scan for matches but limit to 10 to avoid floods
    let matches = scan_limit(pattern, 10);
    let mut resolved_vec: Vec<usize> = Vec::new();
    let mut seen: HashSet<usize> = HashSet::new();

    for m in matches.iter() {
        let mut addr = *m;
        if addr.is_null() {
            continue;
        }

        // Resolve relative addresses requested times
        for _ in 0..resolve_times {
            addr = resolve_relative_address(addr, 1, 5);
            if addr.is_null() {
                break;
            }
        }
        if addr.is_null() {
            continue;
        }

        let addr_usize = addr as usize;
        if !seen.insert(addr_usize) {
            continue; // skip duplicates
        }

        resolved_vec.push(addr_usize);
        if resolved_vec.len() >= 10 {
            break;
        }
    }

    if !resolved_vec.is_empty() {
        // Persist found offsets to config so next run uses them
        let _ = crate::config::write_offsets(key, &resolved_vec);
        return resolved_vec[0] as *mut c_void;
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

/// Macro to declare a let-bound scanner variable using the variable name as the config key.
#[macro_export]
macro_rules! scan_key {
    ($name:ident, $pattern:expr) => {
        let $name = $crate::scanner::get_or_scan(stringify!($name), $pattern, 0);
    };
    ($name:ident, $pattern:expr, $resolve:expr) => {
        let $name = crate::scanner::get_or_scan(stringify!($name), $pattern, $resolve);
    };
}
