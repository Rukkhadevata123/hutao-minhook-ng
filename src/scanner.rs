use crate::hutao_seh::try_seh;
use std::collections::HashSet;
use std::ffi::c_void;
use std::ptr;
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;

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

/// Helper to get the Main Module's (exe) Base Address and SizeOfImage
fn get_main_module_range() -> (usize, usize) {
    unsafe {
        let base = GetModuleHandleW(ptr::null()) as usize;
        if base == 0 {
            return (0, 0);
        }
        let dos_header = base as *const IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != 0x5A4D {
            // Not MZ
            return (0, 0);
        }
        let nt_headers = (base + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        if (*nt_headers).Signature != 0x00004550 {
            // Not PE
            return (0, 0);
        }
        let size = (*nt_headers).OptionalHeader.SizeOfImage as usize;
        (base, size)
    }
}

/// Retrieves all committed and readable memory regions WITHIN the main module.
fn get_memory_regions() -> Vec<RegionInfo> {
    let mut regions = Vec::new();
    unsafe {
        let (module_base, module_size) = get_main_module_range();
        if module_base == 0 || module_size == 0 {
            return regions;
        }

        let mut start = module_base;
        let end = module_base + module_size;

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

            // Only include regions that are committed, readable/executable, AND inside our module range
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

/// Optimized pattern structure
struct Pattern {
    bytes: Vec<u8>,
    mask: Vec<u8>,
    // Offset of the first non-wildcard byte to use for fast scanning
    anchor_offset: Option<usize>,
}

/// Parses a pattern string into a structure optimized for scanning.
/// "AA ? BB" -> bytes: [0xAA, 0x00, 0xBB], mask: [0xFF, 0x00, 0xFF]
fn parse_pattern(pattern: &str) -> Pattern {
    let mut bytes = Vec::new();
    let mut mask = Vec::new();
    let mut anchor_offset = None;

    for (i, s) in pattern.split_whitespace().enumerate() {
        if s == "?" || s == "??" {
            bytes.push(0);
            mask.push(0); // 0x00 means wildcard
        } else {
            let b = u8::from_str_radix(s, 16).unwrap_or(0);
            bytes.push(b);
            mask.push(0xFF); // 0xFF means exact match

            // Record the first non-wildcard byte index
            if anchor_offset.is_none() {
                anchor_offset = Some(i);
            }
        }
    }

    Pattern {
        bytes,
        mask,
        anchor_offset,
    }
}

/// Scans a specific memory region using an optimized algorithm.
/// 1. Uses memchr to find the first non-wildcard byte (very fast).
/// 2. Verifies the rest of the pattern only when the anchor is found.
fn scan_region(
    region_base: *mut c_void,
    region_size: usize,
    pattern: &Pattern,
) -> Vec<*mut c_void> {
    let pattern_len = pattern.bytes.len();
    if region_size < pattern_len {
        return Vec::new();
    }

    // Use try_seh to catch Access Violations
    let result = try_seh(|| unsafe {
        let mut results: Vec<*mut c_void> = Vec::new();
        let base_ptr = region_base as *const u8;
        // Convert the entire region to a slice for safe Rust iteration
        let region_slice = std::slice::from_raw_parts(base_ptr, region_size);

        match pattern.anchor_offset {
            Some(anchor_idx) => {
                // Optimized Path: We have a solid byte to search for.
                let anchor_byte = pattern.bytes[anchor_idx];
                let mut offset = 0;

                // Search loop
                while let Some(pos) = region_slice[offset..]
                    .iter()
                    .position(|&b| b == anchor_byte)
                {
                    let current_match_pos = offset + pos;

                    // Calculate where the pattern would start if this anchor matches
                    // Be careful with underflow (usize)
                    if current_match_pos >= anchor_idx {
                        let start_candidate = current_match_pos - anchor_idx;

                        // Check bounds
                        if start_candidate + pattern_len <= region_size {
                            // Verify the full pattern
                            let mut is_match = true;
                            // We can skip the anchor_idx since we just found it
                            for i in 0..pattern_len {
                                if i == anchor_idx {
                                    continue;
                                }

                                let mem_byte = *base_ptr.add(start_candidate + i);
                                let pat_byte = pattern.bytes[i];
                                let mask_byte = pattern.mask[i];

                                // (mem & mask) == (pat & mask) logic
                                // Since pat_byte is already 0 where mask is 0, we can just do:
                                if (mem_byte & mask_byte) != pat_byte {
                                    is_match = false;
                                    break;
                                }
                            }

                            if is_match {
                                results.push(base_ptr.add(start_candidate) as *mut c_void);
                            }
                        }
                    }

                    // Move past this match to continue searching
                    offset = current_match_pos + 1;
                    if offset >= region_size {
                        break;
                    }
                }
            }
            None => {
                // Degenerate case: Pattern is ALL wildcards ("? ? ?").
                // Just return everything? Or just the first one?
                // Usually this implies a bad config, but we'll do a naive scan.
                if pattern_len <= region_size {
                    for i in 0..=(region_size - pattern_len) {
                        results.push(base_ptr.add(i) as *mut c_void);
                    }
                }
            }
        }
        results
    });

    result.unwrap_or_else(|_| Vec::new())
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
        let $name = $crate::scanner::get_or_scan(stringify!($name), $pattern, $resolve);
    };
}
