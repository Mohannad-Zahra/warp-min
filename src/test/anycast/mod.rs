use crate::*;
use std::net::{Ipv4Addr, SocketAddr};

#[test]
fn test_align_hop2_endpoint() {
    let ep_a: SocketAddr = "162.159.192.1:500".parse().unwrap();
    let ep_b = align_hop2_endpoint(ep_a);
    assert_eq!(*ep_b.ip(), Ipv4Addr::new(188, 114, 97, 3));
    assert_eq!(ep_b.port(), 2408);

    let ep_a2: SocketAddr = "188.114.97.2:2408".parse().unwrap();
    let ep_b2 = align_hop2_endpoint(ep_a2);
    assert_eq!(*ep_b2.ip(), Ipv4Addr::new(162, 159, 192, 1));
    assert_eq!(ep_b2.port(), 2408);

    // Fallback when Hop 1 is on 188.114.96.1
    let ep_a3: SocketAddr = "188.114.96.1:500".parse().unwrap();
    let ep_b3 = align_hop2_endpoint(ep_a3);
    assert_eq!(*ep_b3.ip(), Ipv4Addr::new(162, 159, 192, 1));
    assert_eq!(ep_b3.port(), 2408);
}

#[test]
fn test_get_hop2_candidates() {
    let candidates = get_hop2_candidates();
    assert!(candidates.len() >= 5);
    assert_eq!(candidates[0], "188.114.97.3:2408".parse().unwrap());
    assert!(candidates.contains(&"188.114.96.1:2408".parse().unwrap()));
}

#[test]
fn test_get_anycast_candidates() {
    let candidates = get_anycast_candidates();
    assert!(
        candidates.len() >= 30,
        "Should have a robust candidate pool"
    );
    assert!(
        candidates
            .iter()
            .any(|c| c.ip() == Ipv4Addr::new(162, 159, 192, 1) && c.port() == 500)
    );
    assert!(candidates.iter().any(|c| c.port() == 500));
    assert!(candidates.iter().any(|c| c.port() == 1701));
    assert!(candidates.iter().any(|c| c.port() == 4500));
    assert!(candidates.iter().any(|c| c.port() == 2408));
}
