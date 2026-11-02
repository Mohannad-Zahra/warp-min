use crate::elevate::*;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Threading::WaitForSingleObject;

#[test]
fn test_is_elevated_runs_without_panic() {
    let _ = is_elevated();
}

#[test]
fn test_shutdown_event_lifecycle() {
    let pid = std::process::id();
    let handle = create_shutdown_event(pid).expect("create shutdown event");
    assert_ne!(handle, 0);

    let signaled = signal_shutdown_event(pid);
    assert!(signaled, "Signaling shutdown event must succeed");

    let wait_res = unsafe { WaitForSingleObject(handle, 0) };
    assert_eq!(
        wait_res,
        windows_sys::Win32::Foundation::WAIT_OBJECT_0,
        "Event must be signaled"
    );

    unsafe {
        CloseHandle(handle);
    }
}

#[test]
fn test_quote_win_arg() {
    assert_eq!(quote_win_arg("simple"), "simple");
    assert_eq!(quote_win_arg("with space"), "\"with space\"");
    assert_eq!(quote_win_arg("quote\"test"), "\"quote\\\"test\"");
    assert_eq!(quote_win_arg("with space\\"), "\"with space\\\\\"");
    assert_eq!(quote_win_arg(""), "\"\"");
}

#[test]
fn test_sddl_string_descriptor_parsing() {
    let pid = std::process::id();
    let res = create_shutdown_event(pid);
    assert!(res.is_ok());
    if let Ok(handle) = res {
        unsafe {
            CloseHandle(handle);
        }
    }
}
