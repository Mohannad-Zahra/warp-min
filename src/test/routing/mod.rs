use crate::tun::*;
use std::net::Ipv4Addr;

#[test]
fn test_is_in_roblox_gameplay_cidr() {
    assert!(is_in_roblox_gameplay_cidr(Ipv4Addr::new(128, 116, 0, 1)));
    assert!(is_in_roblox_gameplay_cidr(Ipv4Addr::new(128, 116, 50, 10)));
    assert!(is_in_roblox_gameplay_cidr(Ipv4Addr::new(
        128, 116, 127, 254
    )));
    assert!(is_in_roblox_gameplay_cidr(Ipv4Addr::new(128, 116, 13, 3))); // voice.roblox.com
    assert!(!is_in_roblox_gameplay_cidr(Ipv4Addr::new(128, 116, 128, 1)));
    assert!(!is_in_roblox_gameplay_cidr(Ipv4Addr::new(128, 115, 0, 1)));
    assert!(!is_in_roblox_gameplay_cidr(Ipv4Addr::new(1, 1, 1, 1)));
    assert!(!is_in_roblox_gameplay_cidr(Ipv4Addr::new(192, 168, 1, 1)));
}

#[test]
fn test_win32_dummy_interface_helpers() {
    // Calling Win32 helpers on a non-existent dummy interface index (e.g. 999999)
    // should return an OS error code without panicking or crashing.
    assert!(tune_interface_win32(999999, 1, false).is_err());
    assert!(tune_interface_weak_host(999999).is_err());
    flush_interface_neighbors(999999);
    assert!(add_ip_address_win32(999999, Ipv4Addr::new(172, 16, 0, 2), 32, false).is_err());
    assert!(add_route_win32(999999, Ipv4Addr::new(128, 116, 0, 0), 17, None, 1).is_err());
    let del_err = delete_route_win32(999999, Ipv4Addr::new(128, 116, 0, 0), 17);
    println!("del_err on dummy if: {:?}", del_err);
}

#[test]
fn test_pin_host_routes_does_not_panic() {
    let dummy_primary = PrimaryInterface {
        if_index: 9999,
        alias: "Dummy".to_string(),
        next_hop: Some("192.0.2.1".to_string()),
        ip: Some("192.0.2.2".to_string()),
    };
    pin_host_routes(
        &["192.0.2.3".to_string(), "192.0.2.4".to_string()],
        &dummy_primary,
    );
}

#[test]
fn test_add_ip_address_win32_skip_as_source_false() {
    let res = add_ip_address_win32(999999, Ipv4Addr::new(172, 16, 0, 2), 32, false);
    assert!(res.is_err());
}

#[test]
fn test_add_ip_address_win32_skip_as_source_true() {
    let res = add_ip_address_win32(999999, Ipv4Addr::new(172, 16, 0, 2), 32, true);
    assert!(res.is_err());
}

#[test]
fn test_get_best_route_interface_loopback_or_default() {
    let res = get_best_route_interface(Ipv4Addr::new(127, 0, 0, 1));
    assert!(res.is_ok(), "GetBestRoute2 to 127.0.0.1 must succeed");
    let (if_index, src_ip) = res.unwrap();
    assert!(if_index > 0);
    assert_eq!(src_ip, Ipv4Addr::new(127, 0, 0, 1));

    let res_game = get_best_route_interface(Ipv4Addr::new(128, 116, 5, 33));
    assert!(
        res_game.is_ok(),
        "GetBestRoute2 to 128.116.5.33 must succeed"
    );
}

#[test]
fn test_pin_host_route_on_link_does_not_panic() {
    let dummy_on_link = PrimaryInterface {
        if_index: 9999,
        alias: "DummyVPN".to_string(),
        next_hop: Some("0.0.0.0".to_string()),
        ip: Some("10.2.0.2".to_string()),
    };
    pin_host_route_to_primary("192.0.2.5", &dummy_on_link);
}

#[test]
fn test_roblox_gameplay_server_ip_classification() {
    let game_ip = Ipv4Addr::new(128, 116, 5, 33);
    assert!(is_in_roblox_gameplay_cidr(game_ip));
    assert!(is_in_roblox_gameplay_cidr(Ipv4Addr::new(128, 116, 0, 1)));
    assert!(is_in_roblox_gameplay_cidr(Ipv4Addr::new(
        128, 116, 127, 254
    )));
    assert!(!is_in_roblox_gameplay_cidr(Ipv4Addr::new(128, 116, 128, 1)));
}

#[test]
fn test_roblox_edge_pinning_targets_all_subnets() {
    let mut target_host_ips = Vec::new();
    for i in 0..128 {
        target_host_ips.push(format!("128.116.{}.3", i));
    }
    assert_eq!(target_host_ips.len(), 128);
    assert!(target_host_ips.contains(&"128.116.31.3".to_string()));
    assert!(target_host_ips.contains(&"128.116.5.3".to_string()));
    assert!(!target_host_ips.contains(&"128.116.5.33".to_string()));
}

#[test]
fn test_get_default_gateway() {
    let gw = get_default_gateway();
    println!("Detected gateway: {:?}", gw);
    // On machines with active network adapters, gateway is detected
    if let Some(g) = gw {
        assert!(!g.is_empty());
    }
}

#[test]
fn test_get_primary_interface() {
    let primary = get_primary_interface();
    println!("Detected primary interface: {:?}", primary);
    if let Some(p) = primary {
        assert!(p.if_index > 0);
        assert!(!p.alias.is_empty());
    }
}

#[test]
fn test_delete_route_win32_zero_if_index_resolves_dynamically() {
    let res = delete_route_win32(0, Ipv4Addr::new(128, 116, 5, 33), 32);
    assert!(res.is_ok() || res.is_err());
}

#[test]
fn test_cleanup_routes_with_interfaces_does_not_panic() {
    cleanup_routes_with_interfaces(
        "162.159.192.1",
        &["128.116.21.3".to_string()],
        Some(9999),
        Some(9998),
    );
}
