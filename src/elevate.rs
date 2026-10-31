use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use std::sync::atomic::{AtomicIsize, AtomicU32, Ordering};
use windows_sys::Win32::Foundation::{BOOL, CloseHandle, HANDLE};
use windows_sys::Win32::Security::{
    GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows_sys::Win32::System::Console::{
    GetConsoleProcessList, GetConsoleWindow, SetConsoleCtrlHandler,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, GetExitCodeProcess, GetProcessId, INFINITE, OpenEventW,
    OpenProcessToken, SetEvent, TerminateProcess, WaitForSingleObject,
};
use windows_sys::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows_sys::Win32::UI::WindowsAndMessaging::{SW_HIDE, SW_SHOWNORMAL, ShowWindow};

#[link(name = "advapi32")]
unsafe extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        stringsecuritydescriptor: *const u16,
        stringsecuritydescriptorrevision: u32,
        securitydescriptor: *mut *mut std::ffi::c_void,
        securitydescriptorsize: *mut u32,
    ) -> BOOL;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(hmem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
}

static CHILD_PROCESS_HANDLE: AtomicIsize = AtomicIsize::new(0);
static CHILD_PROCESS_PID: AtomicU32 = AtomicU32::new(0);

/// Create a Windows Named Event with SDDL "D:(A;;GA;;;AU)S:(ML;;NW;;;ME)" allowing
/// Authenticated Users across Medium and High integrity levels to synchronize and signal.
pub fn create_shutdown_event(
    pid: u32,
) -> Result<HANDLE, Box<dyn std::error::Error + Send + Sync>> {
    // SDDL: DACL allows Generic All to Authenticated Users (AU).
    // SACL specifies Mandatory Label Medium Integrity (ME) with No-Write-Up (NW)
    // so an unelevated Medium-Integrity parent can open and signal this event created by a High-Integrity child.
    let sddl_with_mic: Vec<u16> = "D:(A;;GA;;;AU)S:(ML;;NW;;;ME)\0".encode_utf16().collect();
    let mut p_sd: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut sd_size: u32 = 0;

    let mut ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_with_mic.as_ptr(),
            1, // SDDL_REVISION_1
            &mut p_sd,
            &mut sd_size,
        )
    };
    if ok == 0 {
        // Fallback to base SDDL if SACL is unsupported
        let sddl_base: Vec<u16> = "D:(A;;GA;;;AU)\0".encode_utf16().collect();
        ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_base.as_ptr(),
                1,
                &mut p_sd,
                &mut sd_size,
            )
        };
    }
    if ok == 0 {
        return Err(format!(
            "Failed to parse SDDL: {}",
            std::io::Error::last_os_error()
        )
        .into());
    }

    let sa = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: p_sd,
        bInheritHandle: 0,
    };

    let global_name: Vec<u16> = format!("Global\\WARP_MIN_SHUTDOWN_{}\0", pid)
        .encode_utf16()
        .collect();

    let mut handle = unsafe { CreateEventW(&sa, 1, 0, global_name.as_ptr()) };

    // If Global\ fails (e.g. non-elevated unit test without SeCreateGlobalPrivilege), fallback to Local\
    if handle == 0 {
        let local_name: Vec<u16> = format!("Local\\WARP_MIN_SHUTDOWN_{}\0", pid)
            .encode_utf16()
            .collect();
        handle = unsafe { CreateEventW(&sa, 1, 0, local_name.as_ptr()) };
    }

    if !p_sd.is_null() {
        unsafe {
            LocalFree(p_sd);
        }
    }

    if handle == 0 {
        return Err(format!(
            "Failed to create shutdown event: {}",
            std::io::Error::last_os_error()
        )
        .into());
    }

    Ok(handle)
}

/// Signals the shutdown event Global\WARP_MIN_SHUTDOWN_<pid> (or Local\ fallback).
pub fn signal_shutdown_event(pid: u32) -> bool {
    let global_name: Vec<u16> = format!("Global\\WARP_MIN_SHUTDOWN_{}\0", pid)
        .encode_utf16()
        .collect();
    // 0x0002 = EVENT_MODIFY_STATE, 0x00100000 = SYNCHRONIZE
    let mut handle = unsafe { OpenEventW(0x0002 | 0x00100000, 0, global_name.as_ptr()) };
    if handle == 0 {
        handle = unsafe { OpenEventW(0x0002, 0, global_name.as_ptr()) };
    }
    if handle == 0 {
        let local_name: Vec<u16> = format!("Local\\WARP_MIN_SHUTDOWN_{}\0", pid)
            .encode_utf16()
            .collect();
        handle = unsafe { OpenEventW(0x0002 | 0x00100000, 0, local_name.as_ptr()) };
        if handle == 0 {
            handle = unsafe { OpenEventW(0x0002, 0, local_name.as_ptr()) };
        }
    }

    if handle != 0 {
        let res = unsafe { SetEvent(handle) };
        unsafe {
            CloseHandle(handle);
        }
        res != 0
    } else {
        false
    }
}

unsafe extern "system" fn parent_ctrl_handler(_ctrl_type: u32) -> BOOL {
    let handle = CHILD_PROCESS_HANDLE.load(Ordering::SeqCst) as HANDLE;
    let pid = CHILD_PROCESS_PID.load(Ordering::SeqCst);
    if handle != 0 {
        if pid != 0 {
            let mut signaled = false;
            for _ in 0..15 {
                if signal_shutdown_event(pid) {
                    signaled = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            if signaled {
                crate::log_info!(
                    "[*] Sent shutdown IPC event to child process (PID {}). Waiting up to 5s for clean route restoration...",
                    pid
                );
            } else {
                crate::log_warn!(
                    "[-] Could not open shutdown IPC event for child PID {}. Waiting up to 5s before fallback TerminateProcess...",
                    pid
                );
            }
        }
        // Wait up to 5 seconds for child to terminate cleanly and restore routing tables
        let wait_res = unsafe { WaitForSingleObject(handle, 5000) };
        if wait_res != windows_sys::Win32::Foundation::WAIT_OBJECT_0 {
            crate::log_warn!(
                "[-] Child process did not exit within 5s; issuing fallback TerminateProcess."
            );
            unsafe {
                TerminateProcess(handle, 1);
            }
        }
    }
    1
}

/// Check if the current process is running with elevated (Administrator) privileges.
pub fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size = mem::size_of::<TOKEN_ELEVATION>() as u32;

        let success = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            size,
            &mut size,
        );

        CloseHandle(token);

        success != 0 && elevation.TokenIsElevated != 0
    }
}

/// Relaunches the current executable with elevated Administrator privileges using Windows UAC ("runas").
/// Waits for the elevated child process to finish and forwards its exit code.
pub fn relaunch_elevated() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let current_exe = std::env::current_exe()?;
    let current_dir = std::env::current_dir()?;

    // Collect existing arguments and ensure --elevated is added so the child won't loop
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if !args.iter().any(|a| a == "--elevated") {
        args.push("--elevated".to_string());
    }

    let args_string = args
        .iter()
        .map(|arg| {
            if arg.contains(' ') || arg.contains('\t') || arg.contains('"') {
                format!("\"{}\"", arg.replace('"', "\\\""))
            } else {
                arg.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    let exe_w: Vec<u16> = current_exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let verb_w: Vec<u16> = std::ffi::OsStr::new("runas")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let args_w: Vec<u16> = std::ffi::OsStr::new(&args_string)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let dir_w: Vec<u16> = current_dir
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut sei: SHELLEXECUTEINFOW = unsafe { mem::zeroed() };
    sei.cbSize = mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = verb_w.as_ptr();
    sei.lpFile = exe_w.as_ptr();
    sei.lpParameters = if args_string.is_empty() {
        ptr::null()
    } else {
        args_w.as_ptr()
    };
    sei.lpDirectory = dir_w.as_ptr();
    sei.nShow = SW_SHOWNORMAL;

    crate::log_info!(
        "[*] Elevating with administrator privileges for Option B (Wintun TUN mode)..."
    );

    let ok = unsafe { ShellExecuteExW(&mut sei) };
    if ok == 0 {
        let err = std::io::Error::last_os_error();
        // 1223 is ERROR_CANCELLED (user clicked "No" on UAC prompt)
        if err.raw_os_error() == Some(1223) {
            return Err("UAC elevation request was canceled by the user.".into());
        }
        return Err(format!("Failed to launch elevated process: {}", err).into());
    }

    if sei.hProcess != 0 {
        let child_pid = unsafe { GetProcessId(sei.hProcess) };
        CHILD_PROCESS_HANDLE.store(sei.hProcess as isize, Ordering::SeqCst);
        CHILD_PROCESS_PID.store(child_pid, Ordering::SeqCst);

        unsafe {
            SetConsoleCtrlHandler(Some(parent_ctrl_handler), 1);

            // If the user launched this executable via Explorer double-click,
            // this process is the only one in the console (GetConsoleProcessList == 1).
            // Hide the parent console window so the user doesn't get two command prompt windows.
            let mut pids = [0u32; 2];
            let count = GetConsoleProcessList(pids.as_mut_ptr(), 2);
            if count == 1 {
                let hwnd = GetConsoleWindow();
                if hwnd != 0 {
                    ShowWindow(hwnd, SW_HIDE);
                }
            } else {
                crate::log_info!(
                    "[+] Elevated process launched (PID {}). Waiting for session to terminate...",
                    child_pid
                );
            }

            WaitForSingleObject(sei.hProcess, INFINITE);
            let mut exit_code: u32 = 0;
            GetExitCodeProcess(sei.hProcess, &mut exit_code);
            CloseHandle(sei.hProcess);
            std::process::exit(exit_code as i32);
        }
    } else {
        std::process::exit(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_sddl_string_descriptor_parsing() {
        let sddl_with_mic: Vec<u16> = "D:(A;;GA;;;AU)S:(ML;;NW;;;ME)\0".encode_utf16().collect();
        let mut p_sd: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut sd_size: u32 = 0;

        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_with_mic.as_ptr(),
                1,
                &mut p_sd,
                &mut sd_size,
            )
        };
        assert_ne!(ok, 0, "SDDL with Medium Mandatory Label must parse successfully");
        if !p_sd.is_null() {
            unsafe {
                LocalFree(p_sd);
            }
        }
    }
}
