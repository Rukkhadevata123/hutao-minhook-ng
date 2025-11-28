mod hutao_seh;

use hutao_seh::try_seh;

#[unsafe(no_mangle)]
pub extern "C" fn test_seh_execution() {
    println!("Preparing to test SEH...");

    // 使用 try_seh 包装可能崩溃的代码
    let result = try_seh(|| {
        println!("Inside SEH protected block. Triggering exception...");
        
        // 故意触发访问违规 (Access Violation) 异常
        // 在 Rust 中解引用空指针是未定义行为，但在 Windows SEH 上下文中通常会触发异常
        unsafe {
            let ptr = std::ptr::null::<i32>();
            *ptr
        }
    });

    match result {
        Ok(val) => println!("Function returned normally: {}", val),
        Err(code) => println!("Caught exception! Code: 0x{:X}", code),
    }
}