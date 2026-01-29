use anyhow::{anyhow, Context, Result};
use headless_chrome::protocol::cdp::Network;
use std::str::FromStr;
use headless_chrome::{Browser, LaunchOptions, Tab};
use log::{error, info};
use rand::Rng;
use rquest::header::{HeaderMap, HeaderValue, ACCEPT, COOKIE};
use rquest::{Client, Proxy};
use rquest_util::Emulation;
use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::fs::{self, File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::sync::Semaphore;
use crate::payloads::{PayloadManager, PayloadConfig};
use crate::tamper::{TamperType, TamperEngine};
use crate::report::{Report, ScanSummary, Finding};
use regex::Regex;

// --- Session Management ---
#[derive(Debug)]
pub struct Session {
    pub client: Client,
    pub proxy: Option<String>,
    #[allow(dead_code)]
    pub user_agent: String,
    // Cookies are handled by the Client's internal store
    #[allow(dead_code)]
    pub created_at: Instant,
}

// --- Configuration Structs ---
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Config {
    pub general: GeneralConfig,
    pub profiles: HashMap<String, String>,
    pub network: NetworkConfig,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct GeneralConfig {
    pub target_url: String,
    pub concurrency: usize,
    pub debug_mode: bool,
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default)]
    pub headers: Vec<String>,
    #[serde(default)]
    pub raw_body: Option<String>,
    pub payload_file: Option<String>,
    #[serde(default)]
    pub tampers: Vec<String>,
    pub report_file: Option<String>,
    pub time_limit: Option<u64>,
}

fn default_method() -> String {
    "GET".to_string()
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct NetworkConfig {
    pub proxies: Vec<String>,
}

// --- Template Engine ---
pub struct TemplateEngine;

impl TemplateEngine {
    pub fn inject(template: &str, payload: &str) -> String {
        let mut result = template.replace("{payload}", payload);
        // Add more placeholders here if needed
        // e.g., {random_id} -> valid uuid
        if result.contains("{random_id}") {
             let uuid = format!("{:x}", rand::random::<u128>());
             result = result.replace("{random_id}", &uuid);
        }
        result
    }
}


// --- Enterprise Logger ---
#[derive(Clone)]
pub struct SpectreLogger {
    file: Arc<Mutex<File>>,
}

impl SpectreLogger {
    pub fn new() -> Result<Self> {
        fs::create_dir_all("logs").context("Failed to create logs directory")?;
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let filename = format!("logs/session_{}.jsonl", timestamp);

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&filename)
            .context(format!("Failed to open log file: {}", filename))?;

        Ok(Self {
            file: Arc::new(Mutex::new(file)),
        })
    }

    pub fn log(&self, worker_id: &str, event: &str, msg: &str, meta: Option<&str>) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let meta_clean = meta.unwrap_or("null");

        let log_line = format!(
            "{{\"ts\": {}, \"worker\": \"{}\", \"event\": \"{}\", \"msg\": \"{}\", \"meta\": {}}}\n",
            timestamp, worker_id, event, msg, meta_clean
        );

        if let Ok(mut handle) = self.file.lock() {
            let _ = handle.write_all(log_line.as_bytes());
        }
    }
}

pub struct StructuralHasher;

impl StructuralHasher {
    pub fn hash(html: &str) -> u64 {
        let mut s = DefaultHasher::new();
        let mut in_tag_name = false;
        let mut current_tag = String::new();
        let mut chars = html.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '<' {
                if let Some(&next) = chars.peek() {
                    if next != '/' && next != '!' && next != '?' {
                        in_tag_name = true;
                        current_tag.clear();
                    }
                }
            } else if in_tag_name {
                if c.is_alphanumeric() {
                    current_tag.push(c);
                } else {
                    if !current_tag.is_empty() {
                        current_tag.hash(&mut s);
                        current_tag.clear();
                    }
                    in_tag_name = false;
                }
            }
        }
        s.finish()
    }
}

pub struct EntropyAnalyzer;

impl EntropyAnalyzer {
    pub fn calculate(data: &str) -> f64 {
        let mut counts = [0usize; 256];
        let mut total = 0;
        for &b in data.as_bytes() {
            counts[b as usize] += 1;
            total += 1;
        }
        if total == 0 {
            return 0.0;
        }
        let mut entropy = 0.0;
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / total as f64;
                entropy -= p * p.log2();
            }
        }
        entropy
    }
}



// --- Browser Solver (Biometric Spoofing) ---
pub struct BrowserSolver;

lazy_static::lazy_static! {
    static ref BROWSER_LIMITER: Semaphore = Semaphore::new(1);
}

impl BrowserSolver {
    fn find_chrome_binary() -> Option<PathBuf> {
        let possible_paths = [
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/usr/bin/google-chrome",
            "/snap/bin/chromium",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
        ];
        for path_str in possible_paths {
            if Path::new(path_str).exists() {
                return Some(PathBuf::from(path_str));
            }
        }
        None
    }

    fn simulate_human_behavior(tab: &Arc<Tab>) -> Result<()> {
        let mut rng = rand::thread_rng();
        let start_x = rng.gen_range(100.0..300.0);
        let start_y = rng.gen_range(100.0..300.0);
        let end_x = rng.gen_range(600.0..800.0);
        let end_y = rng.gen_range(400.0..600.0);

        // Control points for Cubic Bezier
        let cp1_x = start_x + rng.gen_range(-100.0..200.0);
        let cp1_y = start_y + rng.gen_range(-100.0..200.0);
        let cp2_x = end_x + rng.gen_range(-200.0..100.0);
        let cp2_y = end_y + rng.gen_range(-200.0..100.0);

        let steps = 25; // Smoother
        for i in 0..=steps {
            let t = i as f64 / steps as f64;
            
            // Cubic Bezier formula
            let u = 1.0 - t;
            let tt = t * t;
            let uu = u * u;
            let uuu = uu * u;
            let ttt = tt * t;

            let cur_x = (uuu * start_x) + (3.0 * uu * t * cp1_x) + (3.0 * u * tt * cp2_x) + (ttt * end_x);
            let cx = cur_x; // Just using cur_x logic
            let cy = (uuu * start_y) + (3.0 * uu * t * cp1_y) + (3.0 * u * tt * cp2_y) + (ttt * end_y);


            // Add jitter
            let jitter_x = rng.gen_range(-2.0..2.0);
            let jitter_y = rng.gen_range(-2.0..2.0);

            tab.evaluate(
                &format!(
                    "document.elementFromPoint({}, {})?.dispatchEvent(new MouseEvent('mousemove', {{bubbles: true, clientX: {}, clientY: {}}}));",
                    (cx + jitter_x) as i64, (cy + jitter_y) as i64, (cx + jitter_x) as i64, (cy + jitter_y) as i64
                ),
                false,
            )?;
            std::thread::sleep(Duration::from_millis(rng.gen_range(10..40)));
        }

        tab.evaluate("window.scrollBy(0, window.innerHeight / 3);", false)?;
        std::thread::sleep(Duration::from_millis(1000));
        Ok(())
    }

    pub async fn solve(
        url: &str,
        proxy: Option<&str>,
        logger: &SpectreLogger,
        worker_id: &str,
    ) -> Result<String> {
        let _permit = BROWSER_LIMITER.acquire().await?;
        
        let url = url.to_string();
        let logger = logger.clone();
        let worker_id = worker_id.to_string();
        let proxy_string = proxy.map(|s| s.to_string()); 

        let cookie_result = tokio::task::spawn_blocking(move || {
            let mut args_vec = vec![
                "--no-sandbox".to_string(),
                "--disable-gpu".to_string(),
                "--window-size=1920,1080".to_string(),
                "--disable-blink-features=AutomationControlled".to_string(),
                // --- CRITICAL FIX START: Force User-Agent at Launch ---
                "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36".to_string(),
                // --- CRITICAL FIX END ---
            ];

            if let Some(p) = proxy_string {
                let cleaned = p.replace("http://", "").replace("https://", "");
                args_vec.push(format!("--proxy-server={}", cleaned));
            }

            let args_refs: Vec<&std::ffi::OsStr> = args_vec
                .iter()
                .map(|s| std::ffi::OsStr::new(s))
                .collect();

            let options = LaunchOptions {
                path: Self::find_chrome_binary(),
                headless: true, 
                args: args_refs,
                ..Default::default()
            };

            let browser = Browser::new(options).context("Failed to launch browser")?;
            let tab = browser.new_tab()?;
            
            // --- CDP STEALTH INJECTION ---
            let stealth_script = r#"
                Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
                Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
                Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
                window.chrome = { runtime: {} };
            "#;
            tab.call_method(headless_chrome::protocol::cdp::Page::AddScriptToEvaluateOnNewDocument {
                source: stealth_script.into(),
                world_name: None,
                include_command_line_api: None,
                run_immediately: None,
            })?;

            // Note: This override is still here as a backup/for later XHR requests,
            // but the launch arg above does the heavy lifting for the initial handshake.
            tab.call_method(Network::SetUserAgentOverride {
                user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36".into(),
                accept_language: Some("en-US,en;q=0.9".into()),
                platform: Some("Windows".into()),
                user_agent_metadata: None,
            })?;

            logger.log(&worker_id, "BROWSER_NAV", "Navigating to Target", Some(&format!("\"{}\"", url)));
            
            tab.navigate_to(&url)?;
            tab.wait_until_navigated()?;

            if let Err(e) = Self::simulate_human_behavior(&tab) {
                logger.log(&worker_id, "BROWSER_WARN", "Biometric simulation issue", Some(&format!("\"{}\"", e)));
            }

            // Capture Screenshot for Debugging (SannySoft/BrowserScan)
            std::thread::sleep(Duration::from_secs(5));

            if let Ok(png) = tab.capture_screenshot(
                headless_chrome::protocol::cdp::Page::CaptureScreenshotFormatOption::Png, 
                None, 
                None, 
                true
            ) {
                 let _ = std::fs::write("debug_screenshot.png", png);
            }

            let start_time = Instant::now();
            let timeout = Duration::from_secs(20);

            while start_time.elapsed() < timeout {
                if let Ok(content) = tab.get_content() {
                    // Check for Success Indicators
                    if content.contains("OWASP Juice Shop") 
                        || content.contains("app-root") 
                        || content.contains("Access Granted") 
                        || (!content.to_lowercase().contains("checking your browser") 
                            && !content.contains("bw_id"))
                    {
                        if let Ok(cookies) = tab.get_cookies() {
                            let cookie_vec: Vec<String> = cookies
                                .iter()
                                .map(|c| format!("{}={}", c.name, c.value))
                                .collect();
                            
                            let cookie_str = cookie_vec.join("; ");
                            if !cookie_str.is_empty() {
                                logger.log(&worker_id, "BROWSER_SUCCESS", "Challenge Solved", Some(&format!("\"{}\"", cookie_str)));
                                return Ok(cookie_str);
                            }
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(500));
            }
            Err(anyhow!("Browser timed out waiting for clearance"))
        }).await??;

        Ok(cookie_result)
    }
}

// --- Client Factory ---
pub struct ClientFactory {
    profiles: HashMap<String, String>,
}

impl ClientFactory {
    pub fn new(profiles: HashMap<String, String>) -> Self {
        Self { profiles }
    }

    pub fn create_client(
        &self,
        profile_key: &str,
        proxy_url: Option<&str>,
        auth_cookies: Option<String>,
    ) -> Result<Client> {
        let impersonation_str = self
            .profiles
            .get(profile_key)
            .ok_or_else(|| anyhow!("Profile not found: {}", profile_key))?;

        let emulation = match impersonation_str.to_lowercase().as_str() {
            "chrome" | "chrome_130" => Emulation::Chrome130,
            "safari" | "safari_16" => Emulation::Safari16_5,
            "edge" => Emulation::Edge101, 
            "firefox" => Emulation::Firefox109, // Keeping provided, if fails will update
            "random" => {
                let options = [
                    Emulation::Chrome130,
                    Emulation::Safari16_5,
                    Emulation::Edge101,
                    Emulation::Firefox109,
                ];
                let mut rng = rand::thread_rng();
                *options.choose(&mut rng).unwrap_or(&Emulation::Chrome130)
            },
            _ => Emulation::Chrome130,
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            ),
        );
        
        if let Some(cookie_str) = auth_cookies {
            if let Ok(hval) = HeaderValue::from_str(&cookie_str) {
                headers.insert(COOKIE, hval);
            }
        }

        let mut builder = Client::builder()
            .emulation(emulation)
            .default_headers(headers)
            .redirect(rquest::redirect::Policy::limited(5));

        if let Some(proxy) = proxy_url {
            builder = builder.proxy(Proxy::all(proxy)?);
        }

        let client = builder.build().context("Failed to build TLS client")?;
        Ok(client)
    }
}

// --- Verdict & Analyzer ---
#[derive(Debug)]
pub enum Verdict {
    Success,
    Blocked(String),
    Challenge(String),
}

pub struct ResponseAnalyzer;

impl ResponseAnalyzer {
    pub fn analyze(status: u16, body: &str, logger: Option<(&SpectreLogger, &str)>) -> Verdict {
        let body_lower = body.to_lowercase();
        let entropy = EntropyAnalyzer::calculate(body);
        let size = body.len();
        
        // 1. High Entropy / Challenge Detection (New Heuristic)
        // If small page (<2KB) and (high entropy > 5.0 OR (minimal text & has script))
        if size < 2048 {
             let has_script = body_lower.contains("<script");
             if entropy > 5.5 || (size < 500 && has_script && entropy > 3.5) {
                 return Verdict::Challenge(format!("Heuristic: Low Size + Entropy {:.2}", entropy));
             }
        }

        // 2. Force Browser Launch for Fingerprint Testing Sites
        if body_lower.contains("browserscan") || body_lower.contains("sannysoft") {
            return Verdict::Challenge("Force Test (Fingerprinting)".into());
        }

        // Success Keywords
        if body.contains("OWASP Juice Shop")
            || body.contains("app-root")
            || body.contains("Access Granted")
        {
            return Verdict::Success;
        }

        // Challenge Detection
        if body_lower.contains("checking your browser") || body_lower.contains("enable javascript") {
            return Verdict::Challenge("Generic JS".into());
        }
        if body_lower.contains("cloudflare") && body_lower.contains("ray id") {
            return Verdict::Challenge("Cloudflare".into());
        }
        if body.contains("bw_id") || body.contains("BunkerWeb") {
             return Verdict::Challenge("BunkerWeb JS".into());
        }

        // Blocking Detection
        if status == 403 || status == 429 {
            return Verdict::Blocked(format!("HTTP {}", status));
        }

        let block_words = ["access denied", "attention required", "security check"];
        for word in block_words {
            if body_lower.contains(word) {
                if let Some((log, w_id)) = logger {
                    let snippet = body.chars().take(200).collect::<String>().replace("\"", "'");
                    log.log(w_id, "DEBUG_BLOCK", "Suspicious body content", Some(&format!("\"{}\"", snippet)));
                }
                return Verdict::Blocked(format!("Keyword: {}", word));
            }
        }

        if status >= 200 && status < 300 {
            Verdict::Success
        } else {
            Verdict::Blocked(format!("Status {}", status))
        }
    }
}

// --- Grid Manager ---
#[derive(Debug, Clone)]
struct Node {
    url: String,
    failures: usize,
    cooldown_until: Option<Instant>,
}

pub struct GridManager {
    nodes: Vec<Node>,
    index: usize,
}

impl GridManager {
    pub fn new(proxies: Vec<String>) -> Self {
        let nodes = proxies
            .into_iter()
            .map(|url| Node {
                url,
                failures: 0,
                cooldown_until: None,
            })
            .collect();
        Self { nodes, index: 0 }
    }

    pub fn get_next_node(&mut self) -> Option<String> {
        let start_index = self.index;
        loop {
            if self.nodes.is_empty() {
                return None;
            }
            let node = &mut self.nodes[self.index];

            if let Some(cooldown) = node.cooldown_until {
                if Instant::now() < cooldown {
                    self.advance();
                    if self.index == start_index {
                        return None;
                    } // All nodes on cooldown
                    continue;
                } else {
                    node.cooldown_until = None;
                    node.failures = 0;
                }
            }
            let url = node.url.clone();
            self.advance();
            return Some(url);
        }
    }

    fn advance(&mut self) {
        if self.nodes.is_empty() {
            return;
        }
        self.index = (self.index + 1) % self.nodes.len();
    }

    pub fn report_failure(&mut self, proxy_url: &str) {
        if let Some(node) = self.nodes.iter_mut().find(|n| n.url == proxy_url) {
            node.failures += 1;
            if node.failures > 3 {
                node.cooldown_until = Some(Instant::now() + Duration::from_secs(60));
            }
        }
    }

    pub fn report_success(&mut self, proxy_url: &str) {
        if let Some(node) = self.nodes.iter_mut().find(|n| n.url == proxy_url) {
            node.failures = 0;
        }
    }
}

// --- Core Engine ---
#[derive(Debug, Default, Clone)]
pub struct EngineStats {
    pub total_requests: Arc<AtomicUsize>,
    pub successful_requests: Arc<AtomicUsize>,
    pub blocked_requests: Arc<AtomicUsize>,
    pub failed_requests: Arc<AtomicUsize>,
    pub findings: Arc<Mutex<Vec<Finding>>>,
}

pub struct CoreEngine {
    config: Config,
    stats: EngineStats,
    logger: Arc<SpectreLogger>,
    baseline_hash: Arc<Mutex<Option<u64>>>,
    payload_manager: Arc<PayloadManager>,
    payload_index: Arc<AtomicUsize>,
    tampers: Vec<TamperType>,
}

impl CoreEngine {
    pub fn new(config: Config) -> Self {
        let logger =
            Arc::new(SpectreLogger::new().expect("CRITICAL: Failed to initialize logging subsystem"));

        let payload_conf = config.general.payload_file.as_ref().map(|p| PayloadConfig {
             file_path: p.clone(),
        });
        let payload_manager = Arc::new(PayloadManager::new(payload_conf).expect("Failed to load payloads"));
        
        let tampers: Vec<TamperType> = config.general.tampers.iter()
            .map(|t| t.parse().unwrap_or(TamperType::None))
            .collect();

        Self {
            config,
            stats: EngineStats::default(),
            logger,
            baseline_hash: Arc::new(Mutex::new(None)),
            payload_manager,
            payload_index: Arc::new(AtomicUsize::new(0)),
            tampers,
        }
    }

    pub fn get_stats(&self) -> EngineStats {
        self.stats.clone()
    }

    pub async fn run(&self) -> Result<()> {
        let (_tx, _rx) = mpsc::channel::<()>(self.config.general.concurrency);
        let grid_manager =
            Arc::new(Mutex::new(GridManager::new(self.config.network.proxies.clone())));
        let client_factory = Arc::new(ClientFactory::new(self.config.profiles.clone()));
        let target_url = self.config.general.target_url.clone();

        // CHECK MODE: Do we have proxies?
        let has_proxies = !self.config.network.proxies.is_empty();

        let start_time = Instant::now();
        let time_limit = self.config.general.time_limit.map(Duration::from_secs);

        info!("Engine started. Target: {}", target_url);

        let pii_regex = Arc::new(Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap());
        let mut handles = Vec::new();

        for i in 0..self.config.general.concurrency {
            let grid_manager = grid_manager.clone();
            let client_factory = client_factory.clone();
            let target_url = target_url.clone();
            let stats = self.stats.clone();
            let logger = self.logger.clone();
            let baseline_hash = self.baseline_hash.clone();
            let worker_id = format!("Worker-{:02}", i);
            let debug_mode = self.config.general.debug_mode;
            let method_config = self.config.general.method.clone();
            let headers_config = self.config.general.headers.clone();
            let raw_body_config = self.config.general.raw_body.clone();
            let payload_manager = self.payload_manager.clone();
            let payload_index = self.payload_index.clone();
            let findings = self.stats.findings.clone();
            let _pii_regex = pii_regex.clone();
            let tampers = self.tampers.clone(); 

            let handle = tokio::spawn(async move {
                let mut current_session: Option<Session> = None;
                
                loop {
                    // 1. Check Time Limit
                    if let Some(limit) = time_limit {
                        if start_time.elapsed() > limit {
                            break;
                        }
                    }

                    // 2. Manage Session (Sticky Logic)
                    if current_session.is_none() {
                         let (proxy_url, should_proceed) = if has_proxies {
                            let mut gm = grid_manager.lock().unwrap();
                            match gm.get_next_node() {
                                Some(p) => (Some(p), true),
                                None => (None, false), // Wait for cooldowns
                            }
                        } else {
                            (None, true) // DIRECT MODE
                        };

                        if !should_proceed {
                             tokio::time::sleep(Duration::from_secs(5)).await;
                             continue; // Wait for cooldown
                        }

                        // Create new session
                        let client_res = client_factory.create_client("desktop", proxy_url.as_deref(), None);
                        match client_res {
                            Ok(client) => {
                                current_session = Some(Session {
                                    client,
                                    proxy: proxy_url,
                                    user_agent: "desktop".to_string(), 
                                    created_at: Instant::now(),
                                });
                            },
                            Err(e) => {
                                logger.log(&worker_id, "ERROR", "Failed to create client", Some(&format!("\"{}\"", e)));
                                if let Some(p) = proxy_url {
                                    let mut gm = grid_manager.lock().unwrap();
                                    gm.report_failure(&p);
                                }
                            }
                        }
                    }

                    // 3. Execute Request
                    if let Some(session) = current_session.as_ref() {
                           // Prepare Payload
                           let p_idx = payload_index.fetch_add(1, Ordering::Relaxed);
                           let all_payloads = payload_manager.get_payloads();
                           let raw_payload = &all_payloads[p_idx % all_payloads.len()];
                           let payload = TamperEngine::apply(raw_payload, &tampers);

                           let method = match method_config.to_uppercase().as_str() {
                                    "GET" => rquest::Method::GET,
                                    "POST" => rquest::Method::POST,
                                    "PUT" => rquest::Method::PUT,
                                    "DELETE" => rquest::Method::DELETE,
                                    "PATCH" => rquest::Method::PATCH,
                                    "HEAD" => rquest::Method::HEAD,
                                    "OPTIONS" => rquest::Method::OPTIONS,
                                    _ => rquest::Method::GET,
                                };

                           let final_url = TemplateEngine::inject(&target_url, &payload);
                           let mut req_builder = session.client.request(method, &final_url);

                           if let Some(body_tmpl) = &raw_body_config {
                                 let final_body = TemplateEngine::inject(body_tmpl, &payload);
                                 req_builder = req_builder.body(final_body);
                           }

                           for h in &headers_config {
                                if let Some((k, v)) = h.split_once(':') {
                                    let final_v = TemplateEngine::inject(v.trim(), &payload);
                                    if let Ok(hv_parsed) = rquest::header::HeaderValue::from_str(&final_v) {
                                         if let Ok(hn_parsed) = rquest::header::HeaderName::from_str(k.trim()) {
                                             req_builder = req_builder.header(hn_parsed, hv_parsed);
                                         }
                                    }
                                }
                           }

                           stats.total_requests.fetch_add(1, Ordering::Relaxed);
                           
                           match req_builder.send().await {
                                Ok(resp) => {
                                    let status = resp.status().as_u16();
                                    let body_bytes = resp.bytes().await.unwrap_or_default();
                                    let body_str = String::from_utf8_lossy(&body_bytes);
                                    
                                    // Hash Baseline logic
                                    let current_hash = StructuralHasher::hash(&body_str);
                                    {
                                        let mut base = baseline_hash.lock().unwrap();
                                        if base.is_none() && status == 200 {
                                            *base = Some(current_hash);
                                             logger.log(
                                                &worker_id,
                                                "LEARNING",
                                                "Baseline Hash Acquired",
                                                Some(&format!("{}", current_hash)),
                                            );
                                        }
                                    }

                                    let verdict = ResponseAnalyzer::analyze(
                                            status,
                                            &body_str,
                                            if debug_mode { Some((&logger, &worker_id)) } else { None },
                                    );
                                    
                                    let verdict_str = match &verdict {
                                         Verdict::Success => "Passed".to_string(),
                                         Verdict::Blocked(r) => format!("Blocked: {}", r),
                                         Verdict::Challenge(r) => format!("Challenge: {}", r),
                                    };
                                    
                                    {
                                        let mut findings_guard = findings.lock().unwrap();
                                        findings_guard.push(Finding {
                                            url: final_url.clone(),
                                            payload: payload.to_string(),
                                            status_code: status,
                                            verdict: verdict_str,
                                            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis(),
                                        });
                                    }

                                    match verdict {
                                        Verdict::Success => {
                                            logger.log(&worker_id, "VERDICT_SUCCESS", "Request passed", None);
                                            stats.successful_requests.fetch_add(1, Ordering::Relaxed);
                                            if let Some(p) = &session.proxy {
                                                let mut gm = grid_manager.lock().unwrap();
                                                gm.report_success(p);
                                            }
                                        },
                                        Verdict::Blocked(reason) => {
                                             logger.log(&worker_id, "VERDICT_BLOCKED", &format!("Blocked: {}", reason), None);
                                             stats.blocked_requests.fetch_add(1, Ordering::Relaxed);
                                             if let Some(p) = &session.proxy {
                                                 let mut gm = grid_manager.lock().unwrap();
                                                 gm.report_failure(p);
                                             }
                                             // BURN SESSION
                                             current_session = None;
                                        },
                                        Verdict::Challenge(reason) => {
                                             logger.log(&worker_id, "VERDICT_CHALLENGE", &format!("Triggering Solver: {}", reason), None);
                                             
                                             // SOLVE challenge
                                             let solve_res = BrowserSolver::solve(
                                                 &target_url,
                                                 session.proxy.as_deref(),
                                                 &logger,
                                                 &worker_id
                                             ).await;

                                             match solve_res {
                                                 Ok(cookies) => {
                                                     logger.log(&worker_id, "SOLVER_WIN", "Cookies secured", None);
                                                     if let Some(p) = &session.proxy {
                                                         let mut gm = grid_manager.lock().unwrap();
                                                         gm.report_success(p);
                                                     }
                                                     
                                                     // REBUILD Client with new cookies
                                                     let new_client = client_factory.create_client(
                                                         "desktop", 
                                                         session.proxy.as_deref(),
                                                         Some(cookies)
                                                     );
                                                     
                                                     if let Ok(nc) = new_client {
                                                         if let Some(curr) = current_session.as_mut() {
                                                             curr.client = nc;
                                                         }
                                                     } else {
                                                         current_session = None;
                                                     }
                                                 },
                                                 Err(e) => {
                                                     logger.log(&worker_id, "SOLVER_FAIL", "Browser failed", Some(&format!("\"{}\"", e)));
                                                     // BURN
                                                     current_session = None; 
                                                 }
                                             }
                                        }
                                    }
                                },
                                Err(e) => {
                                     logger.log(&worker_id, "REQ_FAIL", "Transport Error", Some(&format!("\"{}\"", e)));
                                     stats.failed_requests.fetch_add(1, Ordering::Relaxed);
                                     if let Some(p) = &session.proxy {
                                          let mut gm = grid_manager.lock().unwrap();
                                          gm.report_failure(p);
                                     }
                                     // BURN
                                     current_session = None;
                                }
                           }
                    } else {
                         // Session creation failed, backoff
                         tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            });
            handles.push(handle);
        }

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Shutdown Signal Received");
            }
            _ = async {
                for h in handles {
                    let _ = h.await;
                }
            } => {
                info!("All workers finished.");
            }
        }
        
        // Generate Report
        if let Some(path) = &self.config.general.report_file {
            info!("Generating report to {}", path);
            let findings_data = self.stats.findings.lock().unwrap().clone();
            let summary = ScanSummary {
                target: self.config.general.target_url.clone(),
                total_requests: self.stats.total_requests.load(Ordering::Relaxed),
                blocked: self.stats.blocked_requests.load(Ordering::Relaxed),
                successful: self.stats.successful_requests.load(Ordering::Relaxed),
                duration_seconds: start_time.elapsed().as_secs(),
            };
            let report = Report::new(summary, findings_data);
            if let Err(e) = report.save(path) {
                error!("Failed to save report: {}", e);
            } else {
                info!("Report saved successfully.");
            }
        }

        Ok(())
    }
}