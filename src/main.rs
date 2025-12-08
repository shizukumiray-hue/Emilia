use std::collections::{HashMap, VecDeque};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use native_tls::TlsConnector as NativeTlsConnector;
use rand::seq::SliceRandom;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_native_tls::TlsConnector as TokioTlsConnector;

const IP_RESOLVER: &str = "speed.cloudflare.com";
const PATH_HOME: &str = "/";
const PATH_META: &str = "/meta";
const PROXY_FILE: &str = "Data/batch_00.txt";
const OUTPUT_AZ: &str = "Data/alive-amass.txt";
const OUTPUT_PRIORITY: &str = "Data/Country-ALIVE-amass.txt";
const MAX_CONCURRENT: usize = 300;
const TIMEOUT_SECONDS: u64 = 20;
const CONNECT_TIMEOUT: u64 = 5;
const TLS_TIMEOUT: u64 = 5;
const HTTP_TIMEOUT: u64 = 10;
const PRIORITY_COUNTRIES: [&str; 4] = ["ID", "MY", "SG", "HK"];

const DEBUG_LEVEL: u8 = 1;

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
    tcp_connect_ms: u128,
    tls_handshake_ms: u128,
    total_ms: u128,
}

#[derive(Debug, Clone, Default)]
struct CookieJar {
    cookies: Vec<String>,
}

impl CookieJar {
    fn new() -> Self {
        Self::default()
    }

    fn add_from_headers(&mut self, headers: &str) {
        for line in headers.lines() {
            let line_lower = line.to_ascii_lowercase();
            if line_lower.starts_with("set-cookie:") {
                let cookie = line[11..].trim();
                if let Some(cookie_value) = cookie.split(';').next() {
                    self.cookies.push(cookie_value.to_string());
                }
            }
        }
    }

    fn to_header(&self) -> Option<String> {
        if self.cookies.is_empty() {
            None
        } else {
            Some(format!("Cookie: {}", self.cookies.join("; ")))
        }
    }
    
    fn clear(&mut self) {
        self.cookies.clear();
    }
}

#[derive(Debug, Default)]
struct DebugStats {
    total_tested: u32,
    successful: u32,
    failed_connect: u32,
    failed_ssl: u32,
    failed_http: u32,
    timeout: u32,
    same_ip: u32,
    invalid_format: u32,
    by_country: HashMap<String, u32>,
    error_log: VecDeque<(String, String)>,
}

impl DebugStats {
    fn new() -> Self {
        Self::default()
    }
    
    fn log_error(&mut self, proxy: &str, error: &str) {
        if self.error_log.len() >= 100 {
            self.error_log.pop_front();
        }
        self.error_log.push_back((proxy.to_string(), error.to_string()));
    }
    
    fn increment_total(&mut self) {
        self.total_tested += 1;
    }
}

fn debug_log(level: u8, message: &str) {
    if DEBUG_LEVEL >= level {
        let timestamp = chrono::Local::now().format("%H:%M:%S");
        let prefix = match level {
            1 => "[INFO]",
            2 => "[DETAIL]",
            3 => "[VERBOSE]",
            _ => "[ERROR]",
        };
        println!("{} {} {}", timestamp, prefix, message);
    }
}

fn get_random_user_agent() -> &'static str {
    let mut rng = rand::thread_rng();
    USER_AGENTS.choose(&mut rng).unwrap_or(&USER_AGENTS[0])
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("==================================================");
    println!("    CLOUDFLARE PROXY SCANNER - FINAL VERSION     ");
    println!("==================================================");

    // Ensure output directories exist
    for output_file in &[OUTPUT_AZ, OUTPUT_PRIORITY] {
        if let Some(parent) = Path::new(output_file).parent() {
            fs::create_dir_all(parent)?;
        }
        File::create(output_file)?;
    }

    // Read proxies
    let proxies = read_proxy_file(PROXY_FILE)?;
    println!("✓ Loaded {} proxies from {}", proxies.len(), PROXY_FILE);
    
    if proxies.is_empty() {
        return Err("No proxies found in file".into());
    }

    // Get original IP
    println!("\n[1/4] Getting original IP info...");
    let original_ip_data = get_original_ip_info().await
        .or_else(|e| {
            debug_log(1, &format!("Cloudflare failed: {}, trying alternative...", e));
            get_ip_from_alternative_api().await
        })?;
    
    let original_ip = original_ip_data.get("clientIp")
        .and_then(|v| v.as_str())
        .ok_or("Failed to extract IP from response")?
        .to_string();
    
    println!("✓ Original IP: {}", original_ip);
    if let Some(country) = original_ip_data.get("country").and_then(|v| v.as_str()) {
        println!("✓ Original Location: {}", country);
    }

    // Prepare for scanning
    println!("\n[2/4] Starting proxy scan ({} concurrent)...", MAX_CONCURRENT);
    let active_proxies = Arc::new(Mutex::new(Vec::new()));
    let debug_stats = Arc::new(Mutex::new(DebugStats::new()));
    
    let start_time = Instant::now();
    let total_proxies = proxies.len();
    
    // Process in smaller batches to avoid memory issues
    let batch_size = 500;
    let total_batches = (total_proxies + batch_size - 1) / batch_size;
    
    for batch_idx in 0..total_batches {
        let start_idx = batch_idx * batch_size;
        let end_idx = std::cmp::min(start_idx + batch_size, total_proxies);
        let batch = &proxies[start_idx..end_idx];
        
        println!("\n=== Batch {}/{} ({} proxies) ===",
            batch_idx + 1,
            total_batches,
            batch.len()
        );
        
        let batch_start = Instant::now();
        
        // Create tasks for this batch
        let tasks = futures::stream::iter(batch.iter().map(|proxy_line| {
            let original_ip = original_ip.clone();
            let active_proxies = Arc::clone(&active_proxies);
            let debug_stats = Arc::clone(&debug_stats);
            
            async move {
                test_proxy(proxy_line, &original_ip, &active_proxies, &debug_stats).await;
            }
        })).buffer_unordered(MAX_CONCURRENT).collect::<Vec<()>>();
        
        tasks.await;
        
        // Print progress
        let elapsed = start_time.elapsed();
        let processed = end_idx;
        let rate = processed as f64 / elapsed.as_secs_f64();
        let remaining = total_proxies - processed;
        let eta_seconds = if rate > 0.0 && remaining > 0 {
            remaining as f64 / rate
        } else {
            0.0
        };
        
        let stats = debug_stats.lock().await;
        let active_count = active_proxies.lock().await.len();
        
        println!("  Progress: {}/{} | Rate: {:.1}/s | ETA: {:.0}s | Live: {}",
            processed, total_proxies, rate, eta_seconds, active_count);
        
        println!("  Batch completed in {:.2?}", batch_start.elapsed());
        
        // Print current stats
        println!("  Current stats: ✅ {} | ❌ {} | ⏱️ {}",
            stats.successful,
            stats.failed_connect + stats.failed_ssl + stats.failed_http + stats.timeout + stats.same_ip + stats.invalid_format,
            stats.timeout
        );
    }

    // Final results
    println!("\n[3/4] Processing results...");
    let total_time = start_time.elapsed();
    
    let (stats, active_proxies_list) = {
        let stats_guard = debug_stats.lock().await;
        let proxies_guard = active_proxies.lock().await;
        (stats_guard.clone(), proxies_guard.clone())
    };
    
    println!("\n=== FINAL RESULTS ===");
    println!("Total time: {:.2?}", total_time);
    println!("Proxies tested: {}", stats.total_tested);
    
    if stats.total_tested > 0 {
        let success_rate = (stats.successful as f64 / stats.total_tested as f64) * 100.0;
        println!("Success rate: {:.2}%", success_rate);
    }
    
    println!("\n=== BREAKDOWN ===");
    println!("✅ Working: {}", stats.successful);
    println!("❌ Failed total: {}", 
        stats.failed_connect + stats.failed_ssl + stats.failed_http + 
        stats.timeout + stats.same_ip + stats.invalid_format);
    println!("  🔌 Connection failed: {}", stats.failed_connect);
    println!("  🔒 SSL/TLS failed: {}", stats.failed_ssl);
    println!("  🌐 HTTP failed: {}", stats.failed_http);
    println!("  ⏱️ Timeout: {}", stats.timeout);
    println!("  🏠 Same IP: {}", stats.same_ip);
    println!("  📝 Invalid format: {}", stats.invalid_format);
    
    if !stats.error_log.is_empty() && DEBUG_LEVEL >= 1 {
        println!("\n=== LAST 5 ERRORS ===");
        for (proxy, error) in stats.error_log.iter().rev().take(5) {
            println!("  {}: {}", proxy, error);
        }
    }
    
    // Save results
    println!("\n[4/4] Saving results...");
    if !active_proxies_list.is_empty() {
        let unique_proxies = remove_duplicates(active_proxies_list);
        println!("✓ Found {} unique active proxies", unique_proxies.len());
        
        if unique_proxies.len() > 10 {
            println!("\n=== TOP 10 FASTEST PROXIES ===");
            let mut fastest = unique_proxies.clone();
            fastest.sort_by(|a, b| a.total_ms.cmp(&b.total_ms));
            for (i, proxy) in fastest.iter().take(10).enumerate() {
                println!("{}. {}:{} - {} ({}ms)", 
                    i + 1, proxy.ip, proxy.port, proxy.country, proxy.total_ms);
            }
        }
        
        // Save priority sorted
        let mut priority_sorted = unique_proxies.clone();
        sort_priority_countries(&mut priority_sorted);
        save_proxies_to_file(&priority_sorted, OUTPUT_PRIORITY)?;
        println!("✓ Saved {} proxies to {}", priority_sorted.len(), OUTPUT_PRIORITY);
        
        // Save alphabetical
        let mut az_sorted = unique_proxies;
        az_sorted.sort_by(|a, b| a.country.cmp(&b.country).then(a.total_ms.cmp(&b.total_ms)));
        save_proxies_to_file(&az_sorted, OUTPUT_AZ)?;
        println!("✓ Saved {} proxies to {}", az_sorted.len(), OUTPUT_AZ);
        
        print_sorting_summary(&priority_sorted);
    } else {
        println!("✗ No active proxies found");
    }
    
    println!("\n✨ Scan completed successfully!");
    Ok(())
}

// ==================== CORE FUNCTIONS ====================

async fn test_proxy(
    proxy_line: &str,
    original_ip: &str,
    active_proxies: &Arc<Mutex<Vec<ProxyEntry>>>,
    debug_stats: &Arc<Mutex<DebugStats>>,
) {
    // Parse proxy line
    let (ip, port) = match parse_proxy_line(proxy_line) {
        Some((ip, port)) => (ip, port),
        None => {
            let mut stats = debug_stats.lock().await;
            stats.invalid_format += 1;
            stats.log_error(proxy_line, "Invalid format");
            return;
        }
    };
    
    // Increment counter
    {
        let mut stats = debug_stats.lock().await;
        stats.increment_total();
    }
    
    let test_start = Instant::now();
    let proxy_addr = format!("{}:{}", ip, port);
    
    // Step 1: TCP Connection
    let tcp_connect_start = Instant::now();
    let stream = match tokio::time::timeout(
        Duration::from_secs(CONNECT_TIMEOUT),
        TcpStream::connect(&proxy_addr)
    ).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            let mut stats = debug_stats.lock().await;
            stats.failed_connect += 1;
            stats.log_error(&proxy_addr, &format!("TCP connect: {}", e));
            return;
        },
        Err(_) => {
            let mut stats = debug_stats.lock().await;
            stats.timeout += 1;
            stats.log_error(&proxy_addr, "TCP timeout");
            return;
        }
    };
    let tcp_connect_ms = tcp_connect_start.elapsed().as_millis();
    
    // Step 2: Send CONNECT request
    let connect_request = format!(
        "CONNECT {}:443 HTTP/1.1\r\n\
         Host: {}:443\r\n\
         User-Agent: {}\r\n\
         Proxy-Connection: Keep-Alive\r\n\
         \r\n",
        IP_RESOLVER, IP_RESOLVER, get_random_user_agent()
    );
    
    if let Err(e) = stream.write_all(connect_request.as_bytes()).await {
        let mut stats = debug_stats.lock().await;
        stats.failed_connect += 1;
        stats.log_error(&proxy_addr, &format!("CONNECT write: {}", e));
        return;
    }
    
    // Step 3: Read CONNECT response
    let mut connect_response = Vec::new();
    let mut buffer = [0u8; 1024];
    
    let read_result = tokio::time::timeout(
        Duration::from_secs(CONNECT_TIMEOUT),
        async {
            loop {
                let n = stream.read(&mut buffer).await?;
                if n == 0 { break; }
                connect_response.extend_from_slice(&buffer[..n]);
                
                // Check for end of headers
                if connect_response.ends_with(b"\r\n\r\n") {
                    break;
                }
                if connect_response.len() > 8192 {
                    break;
                }
            }
            Ok::<_, io::Error>(connect_response)
        }
    ).await;
    
    let connect_response_bytes = match read_result {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => {
            let mut stats = debug_stats.lock().await;
            stats.failed_connect += 1;
            stats.log_error(&proxy_addr, &format!("CONNECT read: {}", e));
            return;
        },
        Err(_) => {
            let mut stats = debug_stats.lock().await;
            stats.timeout += 1;
            stats.log_error(&proxy_addr, "CONNECT timeout");
            return;
        }
    };
    
    // Step 4: Check CONNECT response
    let connect_response_str = String::from_utf8_lossy(&connect_response_bytes);
    if !is_connect_successful(&connect_response_str) {
        let mut stats = debug_stats.lock().await;
        stats.failed_connect += 1;
        let status = connect_response_str.lines().next().unwrap_or("Unknown").to_string();
        stats.log_error(&proxy_addr, &format!("CONNECT failed: {}", status));
        return;
    }
    
    // Step 5: TLS Handshake
    let tls_start = Instant::now();
    let connector = match NativeTlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let mut stats = debug_stats.lock().await;
            stats.failed_ssl += 1;
            stats.log_error(&proxy_addr, &format!("TLS build: {}", e));
            return;
        }
    };
    
    let tls_stream = match tokio::time::timeout(
        Duration::from_secs(TLS_TIMEOUT),
        TokioTlsConnector::from(connector).connect(IP_RESOLVER, stream)
    ).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            let mut stats = debug_stats.lock().await;
            stats.failed_ssl += 1;
            stats.log_error(&proxy_addr, &format!("TLS handshake: {}", e));
            return;
        },
        Err(_) => {
            let mut stats = debug_stats.lock().await;
            stats.timeout += 1;
            stats.log_error(&proxy_addr, "TLS timeout");
            return;
        }
    };
    let tls_handshake_ms = tls_start.elapsed().as_millis();
    
    // Step 6: Get cookies from homepage
    let mut cookie_jar = CookieJar::new();
    let mut tls_stream = tls_stream;
    
    // Try to get cookies, but continue even if it fails
    if let Err(e) = get_homepage_cookies(&mut tls_stream, &mut cookie_jar).await {
        debug_log(3, &format!("Homepage cookie failed for {}: {}, continuing...", proxy_addr, e));
    }
    
    // Step 7: Request meta endpoint
    let request = build_http_request(&cookie_jar);
    
    if let Err(e) = tls_stream.write_all(request.as_bytes()).await {
        let mut stats = debug_stats.lock().await;
        stats.failed_http += 1;
        stats.log_error(&proxy_addr, &format!("HTTP write: {}", e));
        return;
    }
    
    // Step 8: Read response
    let response_bytes = match read_http_response(&mut tls_stream).await {
        Ok(bytes) => bytes,
        Err(e) => {
            let mut stats = debug_stats.lock().await;
            stats.failed_http += 1;
            stats.log_error(&proxy_addr, &format!("HTTP read: {}", e));
            return;
        }
    };
    
    // Step 9: Parse response
    let total_ms = test_start.elapsed().as_millis();
    
    match parse_meta_response(&response_bytes) {
        Ok((Some(proxy_ip), country, org)) => {
            if proxy_ip != original_ip {
                let entry = ProxyEntry {
                    ip: ip.clone(),
                    port,
                    country: country.unwrap_or_else(|| "XX".to_string()),
                    org: org.unwrap_or_else(|| "Unknown".to_string()),
                    tcp_connect_ms,
                    tls_handshake_ms,
                    total_ms,
                };
                
                active_proxies.lock().await.push(entry);
                
                let mut stats = debug_stats.lock().await;
                stats.successful += 1;
                *stats.by_country.entry(entry.country.clone()).or_insert(0) += 1;
                
                debug_log(1, &format!("✅ {}:{} - {}ms via {}", ip, port, total_ms, proxy_ip));
            } else {
                let mut stats = debug_stats.lock().await;
                stats.same_ip += 1;
                debug_log(2, &format!("🏠 {}:{} - Transparent", ip, port));
            }
        },
        Ok((None, _, _)) => {
            let mut stats = debug_stats.lock().await;
            stats.failed_http += 1;
            stats.log_error(&proxy_addr, "No IP in response");
        },
        Err(e) => {
            let mut stats = debug_stats.lock().await;
            stats.failed_http += 1;
            let preview = if response_bytes.len() > 100 {
                String::from_utf8_lossy(&response_bytes[..100]).to_string()
            } else {
                String::from_utf8_lossy(&response_bytes).to_string()
            };
            stats.log_error(&proxy_addr, &format!("Parse error: {} | Preview: {}", e, preview));
        }
    }
}

// ==================== HELPER FUNCTIONS ====================

fn parse_proxy_line(line: &str) -> Option<(String, u16)> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    
    // Remove protocol prefix if present
    let line = if let Some(idx) = line.find("://") {
        &line[idx + 3..]
    } else {
        line
    };
    
    // Handle IPv6 format [::1]:8080
    if line.starts_with('[') {
        if let Some(bracket_end) = line.find(']') {
            let ip = &line[1..bracket_end];
            let after_bracket = &line[bracket_end + 1..];
            if after_bracket.starts_with(':') {
                let port_str = &after_bracket[1..];
                let port_end = port_str.find(|c: char| !c.is_ascii_digit()).unwrap_or(port_str.len());
                if let Ok(port) = port_str[..port_end].parse::<u16>() {
                    return Some((ip.to_string(), port));
                }
            }
        }
        return None;
    }
    
    // Try to find separator
    let separators = [':', ',', ' ', '\t', '|'];
    for sep in separators {
        if let Some(sep_pos) = line.find(sep) {
            let ip = &line[..sep_pos];
            let rest = &line[sep_pos + 1..];
            
            // Find port number
            let port_end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
            if port_end > 0 {
                if let Ok(port) = rest[..port_end].parse::<u16>() {
                    return Some((ip.to_string(), port));
                }
            }
        }
    }
    
    None
}

fn is_connect_successful(response: &str) -> bool {
    response.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .map(|code| code == "200")
        .unwrap_or(false)
}

async fn get_homepage_cookies(tls_stream: &mut tokio_native_tls::TlsStream<TcpStream>, cookie_jar: &mut CookieJar) -> Result<()> {
    let headers = build_headers(cookie_jar, false);
    let request = format!("GET {} HTTP/1.1\r\n{}\r\n\r\n", PATH_HOME, headers.join("\r\n"));
    
    tls_stream.write_all(request.as_bytes()).await?;
    
    let mut response = Vec::new();
    let mut buffer = [0u8; 4096];
    
    loop {
        let n = tls_stream.read(&mut buffer).await?;
        if n == 0 { break; }
        response.extend_from_slice(&buffer[..n]);
        
        // Check if we have complete headers
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        
        if response.len() > 16384 {
            break;
        }
    }
    
    let response_str = String::from_utf8_lossy(&response);
    if let Some(header_end) = response_str.find("\r\n\r\n") {
        let headers = &response_str[..header_end];
        cookie_jar.add_from_headers(headers);
    }
    
    Ok(())
}

fn build_headers(cookie_jar: &CookieJar, is_meta: bool) -> Vec<String> {
    let mut headers = Vec::with_capacity(12);
    
    headers.push(format!("Host: {}", IP_RESOLVER));
    headers.push(format!("User-Agent: {}", get_random_user_agent()));
    headers.push("Accept: */*".to_string());
    headers.push("Accept-Language: en-US,en;q=0.9".to_string());
    headers.push("Accept-Encoding: identity".to_string());
    headers.push("Connection: close".to_string());
    headers.push("Cache-Control: no-cache".to_string());
    headers.push("Pragma: no-cache".to_string());
    
    if let Some(cookie) = cookie_jar.to_header() {
        headers.push(cookie);
    }
    
    if is_meta {
        headers.push("Referer: https://speed.cloudflare.com/".to_string());
        headers.push("Sec-Fetch-Dest: empty".to_string());
        headers.push("Sec-Fetch-Mode: cors".to_string());
        headers.push("Sec-Fetch-Site: same-origin".to_string());
    }
    
    headers
}

fn build_http_request(cookie_jar: &CookieJar) -> String {
    let headers = build_headers(cookie_jar, true);
    format!("GET {} HTTP/1.1\r\n{}\r\n\r\n", PATH_META, headers.join("\r\n"))
}

async fn read_http_response(tls_stream: &mut tokio_native_tls::TlsStream<TcpStream>) -> Result<Vec<u8>> {
    let mut response = Vec::new();
    let mut buffer = [0u8; 8192];
    
    loop {
        let n = match tokio::time::timeout(
            Duration::from_secs(HTTP_TIMEOUT),
            tls_stream.read(&mut buffer)
        ).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Err("Read timeout".into()),
        };
        
        if n == 0 { break; }
        response.extend_from_slice(&buffer[..n]);
        
        if response.len() > 65536 {
            break;
        }
    }
    
    Ok(response)
}

fn parse_meta_response(response_bytes: &[u8]) -> Result<(Option<String>, Option<String>, Option<String>)> {
    let response = std::str::from_utf8(response_bytes)?;
    
    // Find JSON in response
    let json_start = response.find('{');
    let json_end = response.rfind('}');
    
    match (json_start, json_end) {
        (Some(start), Some(end)) if end > start => {
            let json_str = &response[start..=end];
            let json: Value = serde_json::from_str(json_str)?;
            
            let ip = json.get("clientIp").and_then(|v| v.as_str()).map(|s| s.to_string());
            let country = json.get("country").and_then(|v| v.as_str()).map(|s| s.to_string());
            let org = json.get("asOrganization").and_then(|v| v.as_str()).map(clean_org_name);
            
            Ok((ip, country, org))
        }
        _ => Err("No JSON found in response".into())
    }
}

async fn get_original_ip_info() -> Result<Value> {
    debug_log(2, "Getting original IP from Cloudflare...");
    
    let mut cookie_jar = CookieJar::new();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    
    // Get homepage for cookies
    let response = client
        .get(&format!("https://{}{}", IP_RESOLVER, PATH_HOME))
        .header("User-Agent", get_random_user_agent())
        .send()
        .await?;
    
    if let Some(cookies) = response.headers().get_all("set-cookie") {
        for cookie in cookies {
            if let Ok(cookie_str) = cookie.to_str() {
                cookie_jar.add_from_headers(&format!("set-cookie: {}", cookie_str));
            }
        }
    }
    
    // Get meta data
    let response = client
        .get(&format!("https://{}{}", IP_RESOLVER, PATH_META))
        .header("User-Agent", get_random_user_agent())
        .header("Referer", "https://speed.cloudflare.com/")
        .send()
        .await?;
    
    let json: Value = response.json().await?;
    Ok(json)
}

async fn get_ip_from_alternative_api() -> Result<Value> {
    debug_log(2, "Getting IP from alternative API...");
    
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    
    let response = client
        .get("https://ipinfo.io/json")
        .header("User-Agent", get_random_user_agent())
        .send()
        .await?;
    
    let json: Value = response.json().await?;
    let mut result = serde_json::Map::new();
    
    if let Some(ip) = json.get("ip") {
        result.insert("clientIp".to_string(), ip.clone());
    }
    if let Some(country) = json.get("country") {
        result.insert("country".to_string(), country.clone());
    }
    if let Some(org) = json.get("org") {
        result.insert("asOrganization".to_string(), org.clone());
    }
    
    Ok(Value::Object(result))
}

fn read_proxy_file(file_path: &str) -> Result<Vec<String>> {
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

fn clean_org_name(org_name: &str) -> String {
    org_name.chars()
        .filter(|c| c.is_alphanumeric() || c.is_whitespace() || ",.-_".contains(*c))
        .collect()
}

fn remove_duplicates(proxies: Vec<ProxyEntry>) -> Vec<ProxyEntry> {
    use std::collections::HashSet;
    
    let mut seen = HashSet::new();
    let mut unique = Vec::new();
    
    for proxy in proxies {
        let key = format!("{}:{}", proxy.ip, proxy.port);
        if seen.insert(key) {
            unique.push(proxy);
        }
    }
    
    unique
}

fn sort_priority_countries(proxies: &mut [ProxyEntry]) {
    proxies.sort_by(|a, b| {
        let p_a = PRIORITY_COUNTRIES.iter().position(|&c| c == a.country);
        let p_b = PRIORITY_COUNTRIES.iter().position(|&c| c == b.country);
        match (p_a, p_b) {
            (Some(ia), Some(ib)) => ia.cmp(&ib),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.country.cmp(&b.country).then(a.total_ms.cmp(&b.total_ms)),
        }
    });
}

fn save_proxies_to_file(proxies: &[ProxyEntry], filename: &str) -> Result<()> {
    let mut file = File::create(filename)?;
    
    // Write header
    writeln!(file, "ip,port,country,org,tcp_connect_ms,tls_handshake_ms,total_ms")?;
    
    for proxy in proxies {
        let org_escaped = if proxy.org.contains(',') || proxy.org.contains('"') {
            format!("\"{}\"", proxy.org.replace('"', "\"\""))
        } else {
            proxy.org.clone()
        };
        
        writeln!(file, "{},{},{},{},{},{},{}",
            proxy.ip,
            proxy.port,
            proxy.country,
            org_escaped,
            proxy.tcp_connect_ms,
            proxy.tls_handshake_ms,
            proxy.total_ms
        )?;
    }
    
    Ok(())
}

fn print_sorting_summary(proxies: &[ProxyEntry]) {
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut latencies: HashMap<String, Vec<u128>> = HashMap::new();
    
    for proxy in proxies {
        *counts.entry(proxy.country.clone()).or_insert(0) += 1;
        latencies.entry(proxy.country.clone())
            .or_insert_with(Vec::new)
            .push(proxy.total_ms);
    }
    
    println!("\n=== COUNTRY DISTRIBUTION ===");
    
    // Priority countries first
    for &country in &PRIORITY_COUNTRIES {
        if let Some(count) = counts.get(country) {
            let avg_latency = latencies.get(country)
                .map(|vals| vals.iter().sum::<u128>() / vals.len() as u128)
                .unwrap_or(0);
            println!("  {}: {} proxies (avg {}ms)", country, count, avg_latency);
        }
    }
    
    // Other countries
    let mut others: Vec<_> = counts.iter()
        .filter(|(k, _)| !PRIORITY_COUNTRIES.contains(&k.as_str()))
        .collect();
    
    others.sort_by_key(|(k, _)| *k);
    
    if !others.is_empty() {
        println!("\n  Other countries:");
        for (country, count) in others {
            let avg_latency = latencies.get(*country)
                .map(|vals| vals.iter().sum::<u128>() / vals.len() as u128)
                .unwrap_or(0);
            println!("    {}: {} (avg {}ms)", country, count, avg_latency);
        }
    }
}
