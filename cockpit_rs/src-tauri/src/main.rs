#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(windows)]
struct SingleInstanceMutex(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl SingleInstanceMutex {
    fn acquire() -> Option<Self> {
        use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS};
        use windows_sys::Win32::System::Threading::CreateMutexW;

        let name: Vec<u16> = "Local\\OpenVikingCockpitRsMutex\0".encode_utf16().collect();
        unsafe {
            let handle = CreateMutexW(std::ptr::null(), 1, name.as_ptr());
            if handle.is_null() {
                return None;
            }
            if GetLastError() == ERROR_ALREADY_EXISTS {
                CloseHandle(handle);
                return None;
            }
            Some(Self(handle))
        }
    }
}

#[cfg(windows)]
impl Drop for SingleInstanceMutex {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
}

#[cfg(windows)]
fn activate_existing_window() {
    use std::ptr::null;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        FindWindowW, IsIconic, SetForegroundWindow, ShowWindow, SW_RESTORE, SW_SHOW,
    };

    let title: Vec<u16> = "OpenViking Cockpit\0".encode_utf16().collect();
    unsafe {
        let hwnd = FindWindowW(null(), title.as_ptr());
        if !hwnd.is_null() {
            ShowWindow(hwnd, SW_SHOW);
            if IsIconic(hwnd) != 0 {
                ShowWindow(hwnd, SW_RESTORE);
            }
            SetForegroundWindow(hwnd);
        }
    }
}

fn main() {
    #[cfg(windows)]
    let _instance_guard = match SingleInstanceMutex::acquire() {
        Some(g) => g,
        None => {
            activate_existing_window();
            return;
        }
    };

    openviking_cockpit_lib::run();
}
