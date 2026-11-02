use crate::wfp::*;

#[test]
fn test_wfp_sublayer_guid_format() {
    assert_eq!(WARP_MIN_SUBLAYER_GUID.data1, 0xe94c8e7e);
    assert_eq!(WARP_MIN_SUBLAYER_GUID.data2, 0x399a);
    assert_eq!(WARP_MIN_SUBLAYER_GUID.data3, 0x4c28);
}

#[test]
fn test_wfp_install_on_invalid_luid_non_elevated() {
    // Calling install_tun_permit returns a Result without panicking
    let res = WfpPermitSession::install_tun_permit(123456789);
    println!("test_wfp_install_on_invalid_luid result: {:?}", res.is_ok());
}
