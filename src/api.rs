use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::Duration;
use x25519_dalek::{PublicKey, StaticSecret};

const CF_API_ENDPOINT: &str = "https://api.cloudflareclient.com/v0a4005/reg";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarpAccount {
    pub id: String,
    pub token: String,
    pub private_key: String,
    pub public_key: String,
    pub peer_public_key: String,
    pub peer_endpoint: String,
    pub local_ipv4: String,
    pub local_ipv6: String,
    pub reserved: [u8; 3],
}

#[derive(Serialize)]
struct RegRequest<'a> {
    install_id: &'a str,
    fcm_token: &'a str,
    tos: String,
    key: String,
    #[serde(rename = "type")]
    device_type: &'a str,
    model: &'a str,
    locale: &'a str,
    warp_enabled: bool,
}

#[derive(Deserialize)]
struct RegResponse {
    id: Option<String>,
    token: Option<String>,
    config: Option<RegConfig>,
}

#[derive(Deserialize)]
struct RegConfig {
    peers: Option<Vec<RegPeer>>,
    interface: Option<RegInterface>,
    client_id: Option<String>,
}

#[derive(Deserialize)]
struct RegPeer {
    public_key: String,
    endpoint: Option<RegEndpoint>,
}

#[derive(Deserialize)]
struct RegEndpoint {
    v4: Option<String>,
    #[allow(dead_code)]
    v6: Option<String>,
    host: Option<String>,
}

#[derive(Deserialize)]
struct RegInterface {
    addresses: Option<RegAddresses>,
}

#[derive(Deserialize)]
struct RegAddresses {
    v4: Option<String>,
    #[allow(dead_code)]
    v6: Option<String>,
}

pub struct KeyPair {
    #[allow(dead_code)]
    pub secret: StaticSecret,
    #[allow(dead_code)]
    pub public: PublicKey,
    pub private_b64: String,
    pub public_b64: String,
}

pub fn generate_keypair() -> KeyPair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let private_bytes = secret.to_bytes();
    let public_bytes = public.to_bytes();
    let private_b64 = BASE64_STANDARD.encode(private_bytes);
    let public_b64 = BASE64_STANDARD.encode(public_bytes);
    KeyPair {
        secret,
        public,
        private_b64,
        public_b64,
    }
}

pub async fn register_account(
    cache_file: Option<&str>,
) -> Result<WarpAccount, Box<dyn std::error::Error + Send + Sync>> {
    register_account_with_proxy(cache_file, None, false).await
}

pub async fn register_account_with_proxy(
    cache_file: Option<&str>,
    proxy_addr: Option<&str>,
    force_new: bool,
) -> Result<WarpAccount, Box<dyn std::error::Error + Send + Sync>> {
    if !force_new
        && let Some(path) = cache_file
        && Path::new(path).exists()
        && let Ok(data) = fs::read_to_string(path)
        && let Ok(account) = serde_json::from_str::<WarpAccount>(&data)
    {
        println!("[*] Loaded existing WARP identity from {}", path);
        return Ok(account);
    }

    let keypair = generate_keypair();
    let now = chrono_timestamp();

    let reg_req = RegRequest {
        install_id: "",
        fcm_token: "",
        tos: now,
        key: keypair.public_b64.clone(),
        device_type: "Android",
        model: "PC",
        locale: "en_US",
        warp_enabled: true,
    };
    let json_body = serde_json::to_string(&reg_req)?;

    let resp_text = if let Some(proxy) = proxy_addr {
        println!(
            "[*] Registering new WARP identity through SOCKS5 proxy ({}) via curl...",
            proxy
        );
        let mut child = std::process::Command::new("curl.exe")
            .args([
                "-s",
                "--socks5-hostname",
                proxy,
                "-H",
                "Content-Type: application/json; charset=UTF-8",
                "-H",
                "User-Agent: okhttp/3.12.1",
                "-H",
                "CF-Client-Version: a-6.30-3596",
                "-X",
                "POST",
                "--data-binary",
                "@-",
                CF_API_ENDPOINT,
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin.write_all(json_body.as_bytes())?;
        }
        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err("Failed to execute curl for registration".into());
        }
        let body_str = String::from_utf8_lossy(&output.stdout).to_string();
        if body_str.contains("\"success\":false") {
            return Err(format!("Cloudflare registration failed: {}", body_str).into());
        }
        body_str
    } else {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;

        let resp = client
            .post(CF_API_ENDPOINT)
            .header("Content-Type", "application/json; charset=UTF-8")
            .header("User-Agent", "okhttp/3.12.1")
            .header("CF-Client-Version", "a-6.30-3596")
            .json(&reg_req)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(format!(
                "Cloudflare registration failed with status {}: {}",
                status, text
            )
            .into());
        }
        resp.text().await?
    };

    let reg_resp: RegResponse = serde_json::from_str(&resp_text)?;
    let id = reg_resp.id.ok_or("Missing id in response")?;
    let token = reg_resp.token.unwrap_or_default();
    let config = reg_resp.config.ok_or("Missing config in response")?;

    let peer = config
        .peers
        .and_then(|mut p| {
            if !p.is_empty() {
                Some(p.remove(0))
            } else {
                None
            }
        })
        .ok_or("Missing peer in response")?;
    let peer_public_key = peer.public_key;
    let peer_endpoint = peer
        .endpoint
        .and_then(|e| e.v4.or(e.host))
        .unwrap_or_else(|| "162.159.192.1:2408".to_string());

    let iface = config.interface.ok_or("Missing interface in response")?;
    let addrs = iface.addresses.ok_or("Missing addresses in response")?;
    let local_ipv4 = addrs.v4.unwrap_or_else(|| "172.16.0.2/32".to_string());
    let local_ipv6 = addrs.v6.unwrap_or_default();

    let mut reserved = [0u8; 3];
    if let Some(cid) = config.client_id
        && let Ok(bytes) = BASE64_STANDARD.decode(cid.trim())
        && bytes.len() >= 3
    {
        reserved.copy_from_slice(&bytes[..3]);
    }

    let account = WarpAccount {
        id,
        token,
        private_key: keypair.private_b64,
        public_key: keypair.public_b64,
        peer_public_key,
        peer_endpoint,
        local_ipv4,
        local_ipv6,
        reserved,
    };

    if let Some(path) = cache_file
        && let Ok(json_str) = serde_json::to_string_pretty(&account)
    {
        let _ = fs::write(path, json_str);
    }

    println!(
        "[+] Successfully registered WARP identity (Client IP: {})",
        account.local_ipv4
    );
    Ok(account)
}

fn chrono_timestamp() -> String {
    // Generate ISO 8601 timestamp string
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    // Approximate UTC time formatting
    let days = secs / 86400;
    let rem_secs = secs % 86400;
    let hours = rem_secs / 3600;
    let minutes = (rem_secs % 3600) / 60;
    let seconds = rem_secs % 60;

    // Approximate year/month/day
    let mut year = 1970;
    let mut day_count = days;
    loop {
        let leap = if (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) {
            1
        } else {
            0
        };
        let days_in_year = 365 + leap;
        if day_count < days_in_year {
            let days_in_months = [31, 28 + leap, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
            for (month, &dim) in (1..).zip(days_in_months.iter()) {
                if day_count < dim {
                    return format!(
                        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                        year,
                        month,
                        day_count + 1,
                        hours,
                        minutes,
                        seconds
                    );
                }
                day_count -= dim;
            }
            return format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                year, 12, 31, hours, minutes, seconds
            );
        }
        day_count -= days_in_year;
        year += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let keypair = generate_keypair();
        assert!(!keypair.private_b64.is_empty());
        assert!(!keypair.public_b64.is_empty());

        let priv_bytes = BASE64_STANDARD
            .decode(&keypair.private_b64)
            .expect("valid base64 private");
        let pub_bytes = BASE64_STANDARD
            .decode(&keypair.public_b64)
            .expect("valid base64 public");

        assert_eq!(priv_bytes.len(), 32);
        assert_eq!(pub_bytes.len(), 32);
    }

    #[test]
    fn test_chrono_timestamp_format() {
        let ts = chrono_timestamp();
        assert_eq!(ts.len(), 20);
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[10..11], "T");

        let year: u32 = ts[0..4].parse().expect("valid year");
        assert!(year >= 2024);

        let month: u32 = ts[5..7].parse().expect("valid month");
        assert!((1..=12).contains(&month));

        let day: u32 = ts[8..10].parse().expect("valid day");
        assert!((1..=31).contains(&day));
    }

    #[test]
    fn test_warp_account_serialization() {
        let account = WarpAccount {
            id: "test-id".to_string(),
            token: "test-token".to_string(),
            private_key: "priv_key".to_string(),
            public_key: "pub_key".to_string(),
            peer_public_key: "peer_pub_key".to_string(),
            peer_endpoint: "162.159.192.1:2408".to_string(),
            local_ipv4: "172.16.0.2".to_string(),
            local_ipv6: "2606:4700:110:8f81:8594:648:143e:522d".to_string(),
            reserved: [1, 2, 3],
        };
        let serialized = serde_json::to_string(&account).expect("serialize");
        let deserialized: WarpAccount = serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(deserialized.id, "test-id");
        assert_eq!(deserialized.reserved, [1, 2, 3]);
    }
}
