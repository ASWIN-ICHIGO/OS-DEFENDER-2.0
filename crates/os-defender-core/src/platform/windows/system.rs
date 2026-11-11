use anyhow::Result;

pub struct WindowsSystemInfo;

impl WindowsSystemInfo {
    pub fn machine_id() -> Result<String> {
        // Read MachineGuid from registry
        use windows::Win32::System::Registry::{
            RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ,
            REG_VALUE_TYPE,
        };
        use windows::core::HSTRING;

        let subkey = HSTRING::from(r"SOFTWARE\Microsoft\Cryptography");
        let value_name = HSTRING::from("MachineGuid");

        unsafe {
            let mut hkey = Default::default();
            let open_err = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                &subkey,
                0,
                KEY_READ,
                &mut hkey,
            );
            if open_err.0 != 0 {
                anyhow::bail!("cannot open registry key: {}", open_err.0);
            }

            let mut buf_size: u32 = 256;
            let mut buffer = vec![0u16; buf_size as usize / 2];
            let mut kind = REG_VALUE_TYPE::default();

            let query_err = RegQueryValueExW(
                hkey,
                &value_name,
                None,
                Some(&mut kind),
                Some(buffer.as_mut_ptr().cast()),
                Some(&mut buf_size),
            );
            if query_err.0 != 0 {
                anyhow::bail!("cannot read MachineGuid: {}", query_err.0);
            }

            let len = (buf_size as usize / 2).saturating_sub(1); // strip null terminator
            let guid = String::from_utf16_lossy(&buffer[..len]);
            Ok(guid)
        }
    }

    pub fn hostname() -> Result<String> {
        use windows::core::PWSTR;
        use windows::Win32::System::SystemInformation::GetComputerNameExW;
        use windows::Win32::System::SystemInformation::ComputerNameDnsHostname;

        unsafe {
            let mut size: u32 = 0;
            let _ = GetComputerNameExW(ComputerNameDnsHostname, PWSTR::null(), &mut size);
            let mut buffer = vec![0u16; size as usize];
            let err = GetComputerNameExW(
                ComputerNameDnsHostname,
                PWSTR(buffer.as_mut_ptr()),
                &mut size,
            );
            if let Err(e) = err {
                anyhow::bail!("GetComputerNameExW: {e}");
            }

            Ok(String::from_utf16_lossy(&buffer[..size as usize]))
        }
    }

    pub fn os_version() -> String {
        // Basic version info — in production use RtlGetVersion
        "Windows".to_string()
    }
}
