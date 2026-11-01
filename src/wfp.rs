use std::ptr;
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

/// Static GUID identifying the WARP-MIN High-Priority WFP Sublayer:
/// {e94c8e7e-399a-4c28-bb71-12502693fa2b}
const WARP_MIN_SUBLAYER_GUID: GUID = GUID {
    data1: 0xe94c8e7e,
    data2: 0x399a,
    data3: 0x4c28,
    data4: [0xbb, 0x71, 0x12, 0x50, 0x26, 0x93, 0xfa, 0x2b],
};

const RPC_C_AUTHN_WINNT: u32 = 10;

/// RAII wrapper for a dynamic Windows Filtering Platform (WFP) engine session.
/// Automatically destroys all installed sublayers and permit filters upon drop or process termination.
pub struct WfpPermitSession {
    engine_handle: HANDLE,
}

unsafe impl Send for WfpPermitSession {}
unsafe impl Sync for WfpPermitSession {}

impl WfpPermitSession {
    /// Opens a dynamic WFP engine session, registers a maximum-priority sublayer (weight 0xFFFF / 65535),
    /// and installs "Hard Permit" rules (FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT) on ALE_AUTH_CONNECT_V4
    /// and ALE_AUTH_RECV_ACCEPT_V4 scoped specifically to the WARP-Gool interface LUID.
    ///
    /// Under WFP filter arbitration rules, this permanently clears the FWPS_RIGHT_ACTION_WRITE permission
    /// on all packets traversing WARP-Gool, completely neutralizing lower-priority block rules
    /// (such as ProtonVPN's "ProtonVPN block IPv4" kill-switch rule at weight 1001) without altering
    /// or compromising ProtonVPN's leak protection on any other network interface.
    pub fn install_tun_permit(if_luid: u64) -> Result<Self, u32> {
        unsafe {
            let mut engine_handle: HANDLE = 0;
            let mut session: FWPM_SESSION0 = std::mem::zeroed();
            session.flags = FWPM_SESSION_FLAG_DYNAMIC;

            let ret = FwpmEngineOpen0(
                ptr::null(),
                RPC_C_AUTHN_WINNT,
                ptr::null_mut(),
                &session,
                &mut engine_handle,
            );
            if ret != 0 {
                return Err(ret);
            }

            // 1. Add WARP-MIN Sublayer with maximum weight (0xFFFF = 65535)
            // ProtonVPN's sublayer has weight 1001. A sublayer weight of 65535 guarantees our sublayer
            // evaluates FIRST before ProtonVPN or third-party firewall rules.
            let mut sublayer: FWPM_SUBLAYER0 = std::mem::zeroed();
            sublayer.subLayerKey = WARP_MIN_SUBLAYER_GUID;
            let sublayer_name: Vec<u16> = "WARP-MIN TUN Egress Sublayer\0".encode_utf16().collect();
            sublayer.displayData.name = sublayer_name.as_ptr() as *mut u16;
            sublayer.weight = 0xFFFF; // 65535 > ProtonVPN 1001

            let sublayer_ret = FwpmSubLayerAdd0(engine_handle, &sublayer, ptr::null_mut());
            // 0 = Success, 5010 (ERROR_OBJECT_ALREADY_EXISTS) or 183 is acceptable
            if sublayer_ret != 0 && sublayer_ret != 5010 && sublayer_ret != 183 {
                FwpmEngineClose0(engine_handle);
                return Err(sublayer_ret);
            }

            // 2. Prepare Condition: FWPM_CONDITION_IP_LOCAL_INTERFACE == if_luid
            let mut luid_val = if_luid;
            let mut cond_val: FWP_CONDITION_VALUE0 = std::mem::zeroed();
            cond_val.r#type = FWP_UINT64;
            cond_val.Anonymous.uint64 = &mut luid_val as *mut u64;

            let mut cond: FWPM_FILTER_CONDITION0 = std::mem::zeroed();
            cond.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
            cond.matchType = FWP_MATCH_EQUAL;
            cond.conditionValue = cond_val;

            // 3. Install Outbound Hard Permit (FWPM_LAYER_ALE_AUTH_CONNECT_V4)
            // Setting FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT strips FWPS_RIGHT_ACTION_WRITE,
            // preventing lower-priority sublayers (e.g. ProtonVPN's catch-all block filter 146120)
            // from overriding this permit.
            let filter_name_out: Vec<u16> =
                "WARP-MIN Permit Outbound IPv4 on TUN\0".encode_utf16().collect();
            let mut filter_out: FWPM_FILTER0 = std::mem::zeroed();
            filter_out.subLayerKey = WARP_MIN_SUBLAYER_GUID;
            filter_out.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
            filter_out.displayData.name = filter_name_out.as_ptr() as *mut u16;
            filter_out.action.r#type = FWP_ACTION_PERMIT;
            filter_out.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
            filter_out.weight.r#type = FWP_UINT8;
            filter_out.weight.Anonymous.uint8 = 15;
            filter_out.numFilterConditions = 1;
            filter_out.filterCondition = &mut cond;

            let mut filter_id_out: u64 = 0;
            let filter_ret_out =
                FwpmFilterAdd0(engine_handle, &filter_out, ptr::null_mut(), &mut filter_id_out);
            if filter_ret_out != 0 && filter_ret_out != 5010 && filter_ret_out != 183 {
                FwpmEngineClose0(engine_handle);
                return Err(filter_ret_out);
            }

            // 4. Install Inbound Hard Permit (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4)
            let filter_name_in: Vec<u16> =
                "WARP-MIN Permit Inbound IPv4 on TUN\0".encode_utf16().collect();
            let mut filter_in: FWPM_FILTER0 = std::mem::zeroed();
            filter_in.subLayerKey = WARP_MIN_SUBLAYER_GUID;
            filter_in.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
            filter_in.displayData.name = filter_name_in.as_ptr() as *mut u16;
            filter_in.action.r#type = FWP_ACTION_PERMIT;
            filter_in.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
            filter_in.weight.r#type = FWP_UINT8;
            filter_in.weight.Anonymous.uint8 = 15;
            filter_in.numFilterConditions = 1;
            filter_in.filterCondition = &mut cond;

            let mut filter_id_in: u64 = 0;
            let filter_ret_in =
                FwpmFilterAdd0(engine_handle, &filter_in, ptr::null_mut(), &mut filter_id_in);
            if filter_ret_in != 0 && filter_ret_in != 5010 && filter_ret_in != 183 {
                FwpmEngineClose0(engine_handle);
                return Err(filter_ret_in);
            }

            crate::log_info!(
                "[+] Installed WFP Hard-Permit filters (SubLayer Weight 65535, LUID {}) -> Co-existence guaranteed with commercial VPN kill-switches.",
                if_luid
            );

            Ok(Self { engine_handle })
        }
    }
}

impl Drop for WfpPermitSession {
    fn drop(&mut self) {
        if self.engine_handle != 0 {
            unsafe {
                FwpmEngineClose0(self.engine_handle);
            }
            self.engine_handle = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wfp_sublayer_guid_format() {
        assert_eq!(WARP_MIN_SUBLAYER_GUID.data1, 0xe94c8e7e);
        assert_eq!(WARP_MIN_SUBLAYER_GUID.data2, 0x399a);
        assert_eq!(WARP_MIN_SUBLAYER_GUID.data3, 0x4c28);
    }

    #[test]
    fn test_wfp_install_on_invalid_luid_non_elevated() {
        // Calling install_tun_permit without admin rights returns an error code without panicking
        let res = WfpPermitSession::install_tun_permit(123456789);
        // Will either succeed (if running elevated) or fail with ERROR_ACCESS_DENIED (5)
        println!("test_wfp_install_on_invalid_luid result: {:?}", res.is_ok());
    }
}
