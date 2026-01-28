use anyhow::{anyhow, Context, Result};
use headless_chrome::protocol::cdp::Network;
use headless_chrome::{Browser, LaunchOptions, Tab};
use log::{error, info};
use rand::Rng;
use rquest::header::{HeaderMap, HeaderValue, ACCEPT, COOKIE};
use rquest::{Client, Proxy};
use rquest_util::Emulation;
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::fs::{self, File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::sync::Semaphore;

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
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct NetworkConfig {
    pub proxies: Vec<String>,
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
        let mut in_tag = false;

        for c in html.chars() {
            if c == '<' {
                in_tag = true;
            }
            if c == '>' {
                in_tag = false;
            }
            if in_tag {
                c.hash(&mut s);
            }
        }
        s.finish()
    }
}

// --- Shared State: Cookie Store ---
#[derive(Debug, Default, Clone)]
pub struct CookieStore {
    jar: Arc<RwLock<HashMap<String, String>>>,
}

impl CookieStore {
    pub fn update(&self, cookies: String) {
        if let Ok(mut write_guard) = self.jar.write() {
            write_guard.insert("TARGET".to_string(), cookies);
        }
    }

    pub fn get_cookies(&self) -> Option<String> {
        let read_guard = self.jar.read().unwrap();
        read_guard.get("TARGET").cloned()
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
        let start_x = rng.gen_range(100..300) as f64;
        let start_y = rng.gen_range(100..300) as f64;
        let end_x = rng.gen_range(600..800) as f64;
        let end_y = rng.gen_range(400..600) as f64;

        let steps = 10;
        for i in 0..=steps {
            let t = i as f64 / steps as f64;
            let noise_x = rng.gen_range(-10.0..10.0);
            let noise_y = rng.gen_range(-10.0..10.0);
            
            let cur_x = start_x + (end_x - start_x) * t + noise_x;
            let cur_y = start_y + (end_y - start_y) * t + noise_y;

            tab.evaluate(
                &format!(
                    "document.elementFromPoint({}, {})?.dispatchEvent(new MouseEvent('mousemove', {{bubbles: true, clientX: {}, clientY: {}}}));",
                    cur_x as i64, cur_y as i64, cur_x as i64, cur_y as i64
                ),
                false,
            )?;
            std::thread::sleep(Duration::from_millis(rng.gen_range(20..80)));
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

            // --- FIX START: Correct Enum and Arguments for headless_chrome v1.0 ---
            // 1. Path: headless_chrome::protocol::cdp::Page (Uppercase P)
            // 2. Enum: CaptureScreenshotFormatOption (Renamed in v1.0)
            // 3. Args: (format, quality, clip, from_surface)
            if let Ok(png) = tab.capture_screenshot(
                headless_chrome::protocol::cdp::Page::CaptureScreenshotFormatOption::Png, 
                None, 
                None, 
                true
            ) {
                 let _ = std::fs::write("debug_screenshot.png", png);
            }
            // --- FIX END ---

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

        let emulation = match impersonation_str.as_str() {
            "chrome_130" => Emulation::Chrome130,
            "safari_16" => Emulation::Safari16_5,
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

        // 1. Force Browser Launch for Fingerprint Testing Sites
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
}

pub struct CoreEngine {
    config: Config,
    stats: EngineStats,
    logger: Arc<SpectreLogger>,
    baseline_hash: Arc<Mutex<Option<u64>>>,
    cookie_store: CookieStore,
}

impl CoreEngine {
    pub fn new(config: Config) -> Self {
        let logger =
            Arc::new(SpectreLogger::new().expect("CRITICAL: Failed to initialize logging subsystem"));
        Self {
            config,
            stats: EngineStats::default(),
            logger,
            baseline_hash: Arc::new(Mutex::new(None)),
            cookie_store: CookieStore::default(),
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

        info!("Engine started. Target: {}", target_url);

        for i in 0..self.config.general.concurrency {
            let grid_manager = grid_manager.clone();
            let client_factory = client_factory.clone();
            let target_url = target_url.clone();
            let stats = self.stats.clone();
            let logger = self.logger.clone();
            let baseline_hash = self.baseline_hash.clone();
            let cookie_store = self.cookie_store.clone(); 
            let worker_id = format!("Worker-{:02}", i);
            let debug_mode = self.config.general.debug_mode;

            tokio::spawn(async move {
                loop {
                    // --- DIRECT MODE LOGIC ---
                    let (proxy_url, should_proceed) = if has_proxies {
                        let mut gm = grid_manager.lock().unwrap();
                        match gm.get_next_node() {
                            Some(p) => (Some(p), true),
                            None => (None, false), // Wait for cooldowns
                        }
                    } else {
                        (None, true) // DIRECT MODE
                    };

                    if should_proceed {
                        let current_cookies = cookie_store.get_cookies();
                        let proxy_display = proxy_url.clone().unwrap_or_else(|| "Direct".to_string());

                        logger.log(
                            &worker_id,
                            "REQ_START",
                            "Starting request",
                            Some(&format!("\"Mode: {}\"", proxy_display)),
                        );

                        let client_res =
                            client_factory.create_client("desktop", proxy_url.as_deref(), current_cookies);

                        match client_res {
                            Ok(client) => {
                                stats.total_requests.fetch_add(1, Ordering::Relaxed);
                                
                                match client.get(&target_url).send().await {
                                    Ok(resp) => {
                                        let status = resp.status().as_u16();
                                        let body_bytes = resp.bytes().await.unwrap_or_default();
                                        let body_str = String::from_utf8_lossy(&body_bytes);

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
                                            if debug_mode {
                                                Some((&logger, &worker_id))
                                            } else {
                                                None
                                            },
                                        );

                                        match verdict {
                                            Verdict::Success => {
                                                logger.log(&worker_id, "VERDICT_SUCCESS", "Request passed", None);
                                                stats.successful_requests.fetch_add(1, Ordering::Relaxed);
                                                if let Some(p) = &proxy_url {
                                                    let mut gm = grid_manager.lock().unwrap();
                                                    gm.report_success(p);
                                                }
                                            }
                                            Verdict::Blocked(reason) => {
                                                logger.log(
                                                    &worker_id,
                                                    "VERDICT_BLOCKED",
                                                    &format!("Blocked: {}", reason),
                                                    None,
                                                );
                                                stats.blocked_requests.fetch_add(1, Ordering::Relaxed);
                                                if let Some(p) = &proxy_url {
                                                    let mut gm = grid_manager.lock().unwrap();
                                                    gm.report_failure(p);
                                                }
                                            }
                                            Verdict::Challenge(reason) => {
                                                logger.log(
                                                    &worker_id,
                                                    "VERDICT_CHALLENGE",
                                                    &format!("Triggering Solver: {}", reason),
                                                    None,
                                                );

                                                let url_clone = target_url.clone();
                                                let proxy_clone = proxy_url.clone();
                                                let logger_clone = logger.clone();
                                                let w_id_clone = worker_id.clone();

                                                let result = BrowserSolver::solve(
                                                        &url_clone,
                                                        proxy_clone.as_deref(),
                                                        &logger_clone,
                                                        &w_id_clone,
                                                    ).await;

                                                match result {
                                                    Ok(fresh_cookies) => {
                                                        cookie_store.update(fresh_cookies.clone());
                                                        logger_clone.log(&w_id_clone, "SOLVER_WIN", "Cookies secured & broadcasted", None);
                                                        
                                                        if let Some(p) = &proxy_clone {
                                                            let mut gm = grid_manager.lock().unwrap();
                                                            gm.report_success(p);
                                                        }
                                                    }
                                                    Err(e) => {
                                                        logger_clone.log(&w_id_clone, "SOLVER_FAIL", "Browser failed", Some(&format!("\"{}\"", e)));
                                                        stats.blocked_requests.fetch_add(1, Ordering::Relaxed);
                                                        if let Some(p) = &proxy_clone {
                                                            let mut gm = grid_manager.lock().unwrap();
                                                            gm.report_failure(p);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        logger.log(
                                            &worker_id,
                                            "REQ_FAILED",
                                            "Network Error",
                                            Some(&format!("\"{}\"", e)),
                                        );
                                        stats.failed_requests.fetch_add(1, Ordering::Relaxed);
                                        if let Some(p) = &proxy_url {
                                            let mut gm = grid_manager.lock().unwrap();
                                            gm.report_failure(p);
                                        }
                                    }
                                }
                            }
                            Err(_) => {
                                stats.failed_requests.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    } else {
                        // Backoff if no proxies available
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            });
        }

        match tokio::signal::ctrl_c().await {
            Ok(()) => info!("Shutdown Signal Received"),
            Err(err) => error!("Shutdown signal error: {}", err),
        }
        Ok(())
    }
}
