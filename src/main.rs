use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use native_tls::TlsConnector as NativeTlsConnector;
use rand::seq::SliceRandom;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_native_tls::TlsConnector as TokioTlsConnector;

const IP_RESOLVER: &str = "speed.cloudflare.com";
const PATH_HOME: &str = "/";
const PATH_META: &str = "/meta";
const PROXY_FILE: &str = "Data/hasil_proxy_IP.txt";
const OUTPUT_AZ: &str = "Data/alive-amass.txt";
const OUTPUT_PRIORITY: &str = "Data/Country-ALIVE-amass.txt";
const MAX_CONCURRENT: usize = 1000;
const TIMEOUT_SECONDS: u64 = 6;
const PRIORITY_COUNTRIES: [&str; 4] = ["ID", "MY", "SG", "HK"];

const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 12; Redmi Note 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone14,6; U; CPU iPhone OS 15_4 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/19E241 Safari/602.1",
    "Mozilla/5.0 (iPhone14,3; U; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/19A346 Safari/602.1",
    "Mozilla/5.0 (Linux; Android 6.0.1; SGP771 Build/32.2.A.0.253; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/52.0.2743.98 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 5.1; AFTS Build/LMY47O) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/41.99900.2250.0242 Safari/537.36"
];

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Clone)]
struct ProxyEntry {
    ip: String,
    port: u16,
    country: String,
    org: String,
}

#[derive(Debug, Clone)]
struct CookieJar {
    cookies: Vec<String>,
}

impl CookieJar {
    fn new() -> Self {
        Self { cookies: Vec::new() }
    }

    fn add_from_headers(&mut self, headers: &str) {
        for line in headers.lines() {
            let line_lower = line.to_lowercase();
            if line_lower.starts_with("set-cookie:") {
                let cookie = line[11..].trim();
                if let Some(cookie_value) = cookie.split(';').next() {
                    self.cookies.push(cookie_value.to_string());
                }
            }
        }
    }

    fn to_header(&self) -> String {
        if self.cookies.is_empty() {
            String::new()
        } else {
            format!("Cookie: {}\r\n", self.cookies.join("; "))
        }
    }
}

fn get_random_user_agent() -> &'static str {
    let mut rng = rand::thread_rng();
    USER_AGENTS.choose(&mut rng).unwrap_or(&USER_AGENTS[0])
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("==========================================");
    println!("    CLOUDFLARE PROXY SCANNER (RANDOM UA)");
    println!("==========================================");

    for output_file in &[OUTPUT_AZ, OUTPUT_PRIORITY] {
        if let Some(parent) = Path::new(output_file).parent() {
            fs::create_dir_all(parent)?;
        }
        File::create(output_file)?;
    }

    let proxies = match read_proxy_file(PROXY_FILE) {
        Ok(proxies) => proxies,
        Err(e) => {
            eprintln!("✗ Error reading proxy file: {}", e);
            return Err(e.into());
        }
    };

    println!("✓ Loaded {} proxies", proxies.len());
    println!("\n[1/3] Getting original IP info...");

    let original_ip_data = match get_original_ip_info().await {
        Ok(data) => data,
        Err(_) => get_ip_from_alternative_api().await.map_err(|_| "Failed to get original IP")?,
    };

    let original_ip = original_ip_data.get("clientIp")
        .and_then(|v| v.as_str())
        .ok_or("Failed to extract IP")?
        .to_string();

    println!("✓ Original IP: {}", original_ip);

    let active_proxies = Arc::new(Mutex::new(Vec::new()));
    let counter = Arc::new(Mutex::new((0u32, proxies.len())));

    println!("\n[2/3] Scanning proxies ({} concurrent)...", MAX_CONCURRENT);

    let tasks = futures::stream::iter(
        proxies.into_iter().map(|proxy_line| {
            let original_ip = original_ip.clone();
            let active_proxies = Arc::clone(&active_proxies);
            let counter = Arc::clone(&counter);
            
            async move {
                process_proxy_with_session(proxy_line, &original_ip, &active_proxies).await;
                
                let mut counter_lock = counter.lock().unwrap();
                counter_lock.0 += 1;
                if counter_lock.0 % 2000 == 0 || counter_lock.0 == counter_lock.1 as u32 {
                     println!("  Progress: {}/{} - Live: {}", 
                           counter_lock.0, counter_lock.1,
                           active_proxies.lock().unwrap().len());
                }
            }
        })
    ).buffer_unordered(MAX_CONCURRENT).collect::<Vec<()>>();

    tasks.await;

    println!("\n[3/3] Processing results...");
    
    let active_proxies_locked = active_proxies.lock().unwrap();
    
    if !active_proxies_locked.is_empty() {
        let unique_proxies = remove_duplicates(active_proxies_locked.clone());
        println!("✓ Found {} unique active proxies", unique_proxies.len());

        let mut az_sorted = unique_proxies.clone();
        let mut priority_sorted = unique_proxies;

        sort_az_countries(&mut az_sorted);
        save_proxies_to_file(&az_sorted, OUTPUT_AZ)?;

        sort_priority_countries(&mut priority_sorted);
        save_proxies_to_file(&priority_sorted, OUTPUT_PRIORITY)?;

        print_sorting_summary(&priority_sorted);
    } else {
        println!("✗ No active proxies found");
    }
    
    Ok(())
}

fn read_proxy_file(file_path: &str) -> io::Result<Vec<String>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut proxies = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            proxies.push(trimmed.to_string());
        }
    }
    Ok(proxies)
}

async fn get_original_ip_info() -> Result<Value> {
    let mut cookie_jar = CookieJar::new();
    make_request(IP_RESOLVER, PATH_HOME, None, &mut cookie_jar, false).await?;
    let (_, meta_body) = make_request(IP_RESOLVER, PATH_META, None, &mut cookie_jar, true).await?;
    parse_json_response(&meta_body)
}

async fn get_ip_from_alternative_api() -> Result<Value> {
    let client = reqwest::Client::new();
    let response = client
        .get("https://ipinfo.io/json")
        .header("User-Agent", get_random_user_agent())
        .timeout(Duration::from_secs(10))
        .send()
        .await?;
    
    let json_data: Value = response.json().await?;
    let mut result = serde_json::Map::new();
    
    if let Some(ip) = json_data.get("ip") { result.insert("clientIp".to_string(), ip.clone()); }
    if let Some(c) = json_data.get("country") { result.insert("country".to_string(), c.clone()); }
    if let Some(o) = json_data.get("org") { result.insert("asOrganization".to_string(), o.clone()); }
    
    Ok(Value::Object(result))
}

async fn make_request(
    host: &str,
    path: &str,
    proxy: Option<(&str, u16)>,
    cookie_jar: &mut CookieJar,
    is_meta_request: bool,
) -> Result<(String, String)> {
    tokio::time::timeout(Duration::from_secs(TIMEOUT_SECONDS), async {
        let mut headers = Vec::new();
        headers.push(format!("Host: {}", host));
        headers.push(format!("User-Agent: {}", get_random_user_agent()));
        headers.push("Accept: */*".to_string());
        headers.push("Accept-Encoding: identity".to_string());
        headers.push("Connection: close".to_string());
        
        let cookie_header = cookie_jar.to_header();
        if !cookie_header.is_empty() {
            headers.push(cookie_header);
        }
        
        if is_meta_request {
            headers.push("Referer: https://speed.cloudflare.com/".to_string());
            headers.push("Sec-Fetch-Site: same-origin".to_string());
        }
        
        let request = format!("GET {} HTTP/1.1\r\n{}\r\n\r\n", path, headers.join("\r\n"));

        let stream = if let Some((proxy_ip, proxy_port)) = proxy {
            TcpStream::connect(format!("{}:{}", proxy_ip, proxy_port)).await?
        } else {
            TcpStream::connect(format!("{}:443", host)).await?
        };

        let connector = NativeTlsConnector::builder().danger_accept_invalid_certs(false).build()?;
        let mut tls_stream = TokioTlsConnector::from(connector).connect(host, stream).await?;

        tls_stream.write_all(request.as_bytes()).await?;

        let mut response = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            let n = tls_stream.read(&mut buffer).await?;
            if n == 0 { break; }
            response.extend_from_slice(&buffer[..n]);
        }

        let response_str = String::from_utf8_lossy(&response).to_string();
        if let Some(header_end) = response_str.find("\r\n\r\n") {
            let headers_part = &response_str[..header_end];
            let body = response_str[header_end + 4..].to_string();
            cookie_jar.add_from_headers(headers_part);
            Ok((headers_part.to_string(), body))
        } else {
            Ok(("".to_string(), response_str))
        }
    })
    .await
    // FIX: Menggunakan Box::from() agar tipe data eksplisit dan tidak ambigu
    .map_err(|_| Box::<dyn std::error::Error + Send + Sync>::from("Request timeout"))?
}

fn parse_json_response(response_body: &str) -> Result<Value> {
    let trimmed = response_body.trim();
    if trimmed.is_empty() { return Err("Empty response".into()); }
    
    if let Ok(json) = serde_json::from_str::<Value>(trimmed) {
        if json.get("clientIp").is_some() { return Ok(json); }
    }
    
    if let (Some(start), Some(end)) = (trimmed.find('{'), trimmed.rfind('}')) {
        if end > start {
            if let Ok(json) = serde_json::from_str::<Value>(&trimmed[start..=end]) {
                if json.get("clientIp").is_some() { return Ok(json); }
            }
        }
    }
    Err("No valid JSON found".into())
}

fn clean_org_name(org_name: &str) -> String {
    org_name.chars()
        .filter(|c| c.is_alphanumeric() || c.is_whitespace() || ",.-".contains(*c))
        .collect()
}

async fn process_proxy_with_session(
    proxy_line: String,
    original_ip: &str,
    active_proxies: &Arc<Mutex<Vec<ProxyEntry>>>,
) {
    let (ip, port_str) = if let Some(idx) = proxy_line.find(|c| c == ':' || c == ',') {
        (&proxy_line[..idx], &proxy_line[idx+1..])
    } else { return };

    let port_num = match port_str.trim().parse::<u16>() {
        Ok(p) => p,
        Err(_) => return,
    };

    let mut cookie_jar = CookieJar::new();
    if make_request(IP_RESOLVER, PATH_HOME, Some((ip, port_num)), &mut cookie_jar, false).await.is_err() {
        return;
    }
    
    if let Ok((_, body)) = make_request(IP_RESOLVER, PATH_META, Some((ip, port_num)), &mut cookie_jar, true).await {
        if let Ok(data) = parse_json_response(&body) {
            if let Some(Value::String(proxy_ip)) = data.get("clientIp") {
                if proxy_ip != original_ip {
                    let country = data.get("country").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string();
                    let org = data.get("asOrganization").and_then(|v| v.as_str()).map(clean_org_name).unwrap_or_else(|| "Unknown".to_string());
                    
                    active_proxies.lock().unwrap().push(ProxyEntry {
                        ip: ip.to_string(),
                        port: port_num,
                        country,
                        org,
                    });
                }
            }
        }
    }
}

fn remove_duplicates(proxies: Vec<ProxyEntry>) -> Vec<ProxyEntry> {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    proxies.into_iter().filter(|p| seen.insert(format!("{}:{}", p.ip, p.port))).collect()
}

fn sort_priority_countries(proxies: &mut [ProxyEntry]) {
    proxies.sort_by(|a, b| {
        let p_a = PRIORITY_COUNTRIES.iter().position(|&c| c == a.country);
        let p_b = PRIORITY_COUNTRIES.iter().position(|&c| c == b.country);
        match (p_a, p_b) {
            (Some(ia), Some(ib)) => ia.cmp(&ib),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.country.cmp(&b.country),
        }
    });
}

fn sort_az_countries(proxies: &mut [ProxyEntry]) {
    proxies.sort_by(|a, b| a.country.cmp(&b.country));
}

fn save_proxies_to_file(proxies: &[ProxyEntry], filename: &str) -> Result<()> {
    let mut file = File::create(filename)?;
    for proxy in proxies {
        writeln!(file, "{},{},{},{}", proxy.ip, proxy.port, proxy.country, proxy.org)?;
    }
    Ok(())
}

fn print_sorting_summary(proxies: &[ProxyEntry]) {
    use std::collections::HashMap;
    let mut counts: HashMap<String, usize> = HashMap::new();
    for proxy in proxies { *counts.entry(proxy.country.clone()).or_insert(0) += 1; }

    println!("\n=== DISTRIBUTION SUMMARY ===");
    for &c in &PRIORITY_COUNTRIES {
        if let Some(n) = counts.get(c) { println!("  {}: {}", c, n); }
    }
    
    let mut others: Vec<_> = counts.iter().filter(|(k, _)| !PRIORITY_COUNTRIES.contains(&k.as_str())).collect();
    others.sort_by_key(|(k, _)| *k);
    for (k, v) in others { println!("  {}: {}", k, v); }
}
