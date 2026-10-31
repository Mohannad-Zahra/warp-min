use crate::dns::{build_dns_query, parse_dns_response};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{
    Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState,
};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpCidr, Ipv4Address, Ipv4Cidr};
use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, mpsc, oneshot};

static EPHEMERAL_PORT: AtomicU16 = AtomicU16::new(10000);

struct ChannelDevice {
    caps: DeviceCapabilities,
    rx_queue: VecDeque<Vec<u8>>,
    to_tunnel_tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl Device for ChannelDevice {
    type RxToken<'a> = ChannelRxToken;
    type TxToken<'a> = ChannelTxToken;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Some(packet) = self.rx_queue.pop_front() {
            Some((
                ChannelRxToken(packet),
                ChannelTxToken(self.to_tunnel_tx.clone()),
            ))
        } else {
            None
        }
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(ChannelTxToken(self.to_tunnel_tx.clone()))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.caps.clone()
    }
}

struct ChannelRxToken(Vec<u8>);
impl RxToken for ChannelRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct ChannelTxToken(mpsc::UnboundedSender<Vec<u8>>);
impl TxToken for ChannelTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let res = f(&mut buf);
        let _ = self.0.send(buf);
        res
    }
}

struct NetstackConnection {
    handle: SocketHandle,
    data_from_client_rx: mpsc::Receiver<Vec<u8>>,
    data_to_client_tx: mpsc::Sender<Vec<u8>>,
    connect_resp_tx: Option<oneshot::Sender<Result<(), String>>>,
    created_at: std::time::Instant,
    pending_send: Option<(Vec<u8>, usize)>,
}

enum NetstackCmd {
    Connect {
        target: SocketAddrV4,
        from_client_rx: mpsc::Receiver<Vec<u8>>,
        to_client_tx: mpsc::Sender<Vec<u8>>,
        resp_tx: oneshot::Sender<Result<(), String>>,
    },
}

pub struct NetstackHandle {
    cmd_tx: mpsc::Sender<NetstackCmd>,
    notify: Arc<Notify>,
}

impl NetstackHandle {
    pub async fn connect(
        &self,
        target: SocketAddrV4,
    ) -> Result<(mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>), String> {
        let (from_client_tx, from_client_rx) = mpsc::channel(64);
        let (to_client_tx, to_client_rx) = mpsc::channel(64);
        let (resp_tx, resp_rx) = oneshot::channel();

        self.cmd_tx
            .send(NetstackCmd::Connect {
                target,
                from_client_rx,
                to_client_tx,
                resp_tx,
            })
            .await
            .map_err(|e| e.to_string())?;

        self.notify.notify_one();

        resp_rx.await.map_err(|e| e.to_string())??;
        Ok((from_client_tx, to_client_rx))
    }
}

pub fn spawn_netstack(
    local_ipv4: Ipv4Addr,
    mut from_tunnel_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    to_tunnel_tx: mpsc::UnboundedSender<Vec<u8>>,
) -> NetstackHandle {
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<NetstackCmd>(64);
    let notify = Arc::new(Notify::new());
    let notify_clone = notify.clone();

    tokio::spawn(async move {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1200;

        let mut dev = ChannelDevice {
            caps,
            rx_queue: VecDeque::new(),
            to_tunnel_tx,
        };

        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut iface = Interface::new(config, &mut dev, SmolInstant::now());

        let octets = local_ipv4.octets();
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::Ipv4(Ipv4Cidr::new(
                    Ipv4Address::new(octets[0], octets[1], octets[2], octets[3]),
                    32,
                )))
                .unwrap();
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 0))
            .unwrap();

        let mut sockets = SocketSet::new(vec![]);
        let mut connections: HashMap<usize, NetstackConnection> = HashMap::new();
        let mut next_conn_id: usize = 1;

        let mut interval = tokio::time::interval(Duration::from_millis(2));

        loop {
            tokio::select! {
                _ = interval.tick() => {},
                _ = notify_clone.notified() => {},
                Some(packet) = from_tunnel_rx.recv() => {
                    dev.rx_queue.push_back(packet);
                },
                Some(cmd) = cmd_rx.recv() => {
                    match cmd {
                        NetstackCmd::Connect { target, from_client_rx, to_client_tx, resp_tx } => {
                            let rx_buf = TcpSocketBuffer::new(vec![0; 262144]);
                            let tx_buf = TcpSocketBuffer::new(vec![0; 262144]);
                            let mut socket = TcpSocket::new(rx_buf, tx_buf);

                            let local_port = EPHEMERAL_PORT.fetch_add(1, Ordering::Relaxed);
                            if local_port > 60000 {
                                EPHEMERAL_PORT.store(10000, Ordering::Relaxed);
                            }

                            let dst_octets = target.ip().octets();
                            let dst_addr = Ipv4Address::new(dst_octets[0], dst_octets[1], dst_octets[2], dst_octets[3]);
                            let src_addr = Ipv4Address::new(octets[0], octets[1], octets[2], octets[3]);

                            eprintln!("[NETSTACK] Initiating connection to target={}, local_port={}", target, local_port);
                            if let Err(e) = socket.connect(
                                iface.context(),
                                (dst_addr, target.port()),
                                (src_addr, local_port),
                            ) {
                                eprintln!("[-] Socket connect error: {:?}", e);
                                let _ = resp_tx.send(Err(format!("Socket connect failed: {:?}", e)));
                                continue;
                            }

                            let handle = sockets.add(socket);
                            let conn_id = next_conn_id;
                            next_conn_id += 1;

                            connections.insert(conn_id, NetstackConnection {
                                handle,
                                data_from_client_rx: from_client_rx,
                                data_to_client_tx: to_client_tx,
                                connect_resp_tx: Some(resp_tx),
                                created_at: std::time::Instant::now(),
                                pending_send: None,
                            });

                        }
                    }
                }
            }

            // Drain any pending tunnel packets
            while let Ok(pkt) = from_tunnel_rx.try_recv() {
                dev.rx_queue.push_back(pkt);
            }

            // Poll interface
            iface.poll(SmolInstant::now(), &mut dev, &mut sockets);

            // Handle active connections
            let mut conns_to_remove = Vec::new();

            for (&conn_id, conn) in connections.iter_mut() {
                let socket = sockets.get_mut::<TcpSocket>(conn.handle);

                // Check connection establishment
                if let Some(resp_tx) = conn.connect_resp_tx.take() {
                    match socket.state() {
                        TcpState::Established => {
                            eprintln!("[NETSTACK] Conn {} Established!", conn_id);
                            let _ = resp_tx.send(Ok(()));
                        }
                        TcpState::Closed => {
                            eprintln!("[NETSTACK] Conn {} Closed/Rejected!", conn_id);
                            let _ = resp_tx.send(Err("Connection rejected".to_string()));
                            conns_to_remove.push(conn_id);
                            continue;
                        }
                        st => {
                            if conn.created_at.elapsed() > Duration::from_secs(10) {
                                eprintln!(
                                    "[NETSTACK] Conn {} Timed out in state {:?}",
                                    conn_id, st
                                );
                                let _ = resp_tx.send(Err("Connection timed out".to_string()));
                                conns_to_remove.push(conn_id);
                                continue;
                            }
                            conn.connect_resp_tx = Some(resp_tx);
                        }
                    }
                }

                // Transfer data from client to socket with partial write preservation
                while socket.can_send() {
                    if let Some((pending, offset)) = &mut conn.pending_send {
                        match socket.send_slice(&pending[*offset..]) {
                            Ok(n) if n > 0 => {
                                *offset += n;
                                if *offset >= pending.len() {
                                    conn.pending_send = None;
                                }
                            }
                            _ => break,
                        }
                    } else {
                        match conn.data_from_client_rx.try_recv() {
                            Ok(data) => match socket.send_slice(&data) {
                                Ok(n) if n < data.len() => {
                                    conn.pending_send = Some((data, n));
                                    break;
                                }
                                Ok(_) => {}
                                Err(_) => {
                                    conn.pending_send = Some((data, 0));
                                    break;
                                }
                            },
                            Err(mpsc::error::TryRecvError::Empty) => break,
                            Err(mpsc::error::TryRecvError::Disconnected) => {
                                conns_to_remove.push(conn_id);
                                break;
                            }
                        }
                    }
                }

                // Transfer data from socket to client
                if socket.can_recv() {
                    let mut buf = [0u8; 8192];
                    if let Ok(n) = socket.recv_slice(&mut buf)
                        && n > 0
                        && conn.data_to_client_tx.try_send(buf[..n].to_vec()).is_err()
                    {
                        conns_to_remove.push(conn_id);
                        continue;
                    }
                }

                // If socket is closed, remove
                if socket.state() == TcpState::Closed {
                    conns_to_remove.push(conn_id);
                }
            }

            for conn_id in conns_to_remove {
                if let Some(conn) = connections.remove(&conn_id) {
                    sockets.remove(conn.handle);
                }
            }
        }
    });

    NetstackHandle { cmd_tx, notify }
}

pub async fn run_socks5_server(
    bind_addr: &str,
    netstack: Arc<NetstackHandle>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut attempts = 0;
    let listener = loop {
        match TcpListener::bind(bind_addr).await {
            Ok(l) => break l,
            Err(_e) if attempts < 30 => {
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => return Err(e.into()),
        }
    };
    println!("[+] SOCKS5 proxy listening on {}", bind_addr);

    loop {
        let (stream, _peer_addr) = listener.accept().await?;
        let netstack = netstack.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_socks5_client(stream, netstack).await {
                eprintln!("[-] SOCKS5 client error: {}", e);
            }
        });
    }
}

async fn handle_socks5_client(
    mut stream: TcpStream,
    netstack: Arc<NetstackHandle>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = [0u8; 258];

    // Read version identifier/method selection message
    stream.read_exact(&mut buf[..2]).await?;
    let version = buf[0];
    if version != 5 {
        return Err("Unsupported SOCKS version".into());
    }
    let nmethods = buf[1] as usize;
    stream.read_exact(&mut buf[..nmethods]).await?;

    // Respond: NO AUTHENTICATION REQUIRED (0x00)
    stream.write_all(&[0x05, 0x00]).await?;

    // Read request
    stream.read_exact(&mut buf[..4]).await?;
    let cmd = buf[1];
    if cmd != 1 {
        // Only CONNECT supported
        stream
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Err("Unsupported SOCKS command".into());
    }

    let atyp = buf[3];
    let target_addr: SocketAddrV4 = match atyp {
        1 => {
            // IPv4
            let mut addr_bytes = [0u8; 6];
            stream.read_exact(&mut addr_bytes).await?;
            let ip = Ipv4Addr::new(addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]);
            let port = u16::from_be_bytes([addr_bytes[4], addr_bytes[5]]);
            eprintln!("[SOCKS] IPv4 target: {}:{}", ip, port);
            SocketAddrV4::new(ip, port)
        }
        3 => {
            // Domain name
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let domain_len = len_buf[0] as usize;
            let mut domain_buf = vec![0u8; domain_len + 2];
            stream.read_exact(&mut domain_buf).await?;
            let domain_str = String::from_utf8_lossy(&domain_buf[..domain_len]);
            let port = u16::from_be_bytes([domain_buf[domain_len], domain_buf[domain_len + 1]]);
            eprintln!("[SOCKS] Domain target: {}:{}", domain_str, port);

            let resolved_ip = if let Ok(ip) = domain_str.parse::<Ipv4Addr>() {
                ip
            } else {
                match resolve_domain(&domain_str).await {
                    Ok(ip) => {
                        eprintln!("[SOCKS] Domain {} resolved to {}", domain_str, ip);
                        ip
                    }
                    Err(e) => {
                        eprintln!("[-] Domain resolution failed for {}: {}", domain_str, e);
                        stream
                            .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                            .await?;
                        return Err(e);
                    }
                }
            };
            SocketAddrV4::new(resolved_ip, port)
        }
        _ => {
            // Address type not supported
            stream
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Err("Unsupported address type".into());
        }
    };

    // Connect through netstack
    eprintln!("[SOCKS] Calling netstack.connect to {}", target_addr);
    match netstack.connect(target_addr).await {
        Ok((client_tx, mut client_rx)) => {
            eprintln!("[SOCKS] netstack connected successfully to {}", target_addr);
            // Success response
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;

            let (mut stream_rx, mut stream_tx) = stream.into_split();
            let notify = netstack.notify.clone();

            let upload_task = tokio::spawn(async move {
                let mut read_buf = [0u8; 8192];
                loop {
                    match stream_rx.read(&mut read_buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if client_tx.send(read_buf[..n].to_vec()).await.is_err() {
                                break;
                            }
                            notify.notify_one();
                        }
                        Err(_) => break,
                    }
                }
            });

            let download_task = tokio::spawn(async move {
                while let Some(data) = client_rx.recv().await {
                    if stream_tx.write_all(&data).await.is_err() {
                        break;
                    }
                }
            });

            tokio::select! {
                _ = upload_task => {},
                _ = download_task => {},
            }

            Ok(())
        }
        Err(e) => {
            stream
                .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            Err(e.into())
        }
    }
}

static DNS_CACHE: std::sync::LazyLock<
    std::sync::RwLock<HashMap<String, (Ipv4Addr, std::time::Instant)>>,
> = std::sync::LazyLock::new(|| std::sync::RwLock::new(HashMap::new()));

pub async fn resolve_domain(
    domain: &str,
) -> Result<Ipv4Addr, Box<dyn std::error::Error + Send + Sync>> {
    let ips = resolve_domain_ips(domain).await?;
    ips.first()
        .copied()
        .ok_or_else(|| format!("No IPv4 address resolved for {}", domain).into())
}

pub async fn resolve_domain_ips(
    domain: &str,
) -> Result<Vec<Ipv4Addr>, Box<dyn std::error::Error + Send + Sync>> {
    // Check in-memory DNS cache (TTL: 300s)
    if let Ok(cache) = DNS_CACHE.read()
        && let Some((ip, cached_at)) = cache.get(domain)
        && cached_at.elapsed() < Duration::from_secs(300)
    {
        return Ok(vec![*ip]);
    }

    let ips = resolve_domain_ips_uncached(domain).await?;

    if let Some(&first_ip) = ips.first()
        && let Ok(mut cache) = DNS_CACHE.write()
    {
        cache.insert(domain.to_string(), (first_ip, std::time::Instant::now()));
    }

    Ok(ips)
}

async fn resolve_domain_ips_uncached(
    domain: &str,
) -> Result<Vec<Ipv4Addr>, Box<dyn std::error::Error + Send + Sync>> {
    let mut results = Vec::new();

    // 1. Primary: Encrypted DNS-over-HTTPS (DoH) via Cloudflare 1.1.1.1
    // Connects directly to 1.1.1.1:443 over TLS 1.3 with zero plain DNS exposure to local ISP DPI.
    let doh_url = format!("https://1.1.1.1/dns-query?name={}&type=A", domain);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(2000))
        .build()?;

    if let Ok(resp) = client
        .get(&doh_url)
        .header("Accept", "application/dns-json")
        .send()
        .await
        && resp.status().is_success()
        && let Ok(json) = resp.json::<serde_json::Value>().await
        && let Some(answers) = json.get("Answer").and_then(|a| a.as_array())
    {
        for ans in answers {
            let is_a_type = ans.get("type").and_then(|t| t.as_u64()) == Some(1);
            if is_a_type
                && let Some(data) = ans.get("data").and_then(|d| d.as_str())
                && let Ok(ip) = data.parse::<Ipv4Addr>()
                && !results.contains(&ip)
            {
                results.push(ip);
            }
        }
    }

    if !results.is_empty() {
        return Ok(results);
    }

    // 2. Secondary: Raw UDP DNS query to 1.1.1.1:53
    let query = build_dns_query(domain, 1234);
    if let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        let _ = socket.send_to(&query, "1.1.1.1:53").await;
        let mut resp_buf = [0u8; 512];
        let sleep = tokio::time::sleep(Duration::from_millis(800));
        tokio::pin!(sleep);

        tokio::select! {
            res = socket.recv_from(&mut resp_buf) => {
                if let Ok((n, _)) = res
                    && let Some(ip) = parse_dns_response(&resp_buf[..n]) {
                        results.push(ip);
                        return Ok(results);
                    }
            }
            _ = &mut sleep => {}
        }
    }

    // 3. Fallback to host resolver if external lookups fail
    if let Ok(addrs) = tokio::net::lookup_host(format!("{}:80", domain)).await {
        for addr in addrs {
            if let SocketAddr::V4(v4) = addr
                && !results.contains(v4.ip())
            {
                results.push(*v4.ip());
            }
        }
    }

    if !results.is_empty() {
        Ok(results)
    } else {
        Err(format!("Failed to resolve domain {}", domain).into())
    }
}
