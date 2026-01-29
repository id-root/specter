mod cli;
mod engine;
mod tui;
mod payloads;
mod tamper;
mod waf;
mod report;
mod api;

use anyhow::Result;
use clap::Parser;
use engine::{Config, CoreEngine};
use std::fs;
use std::sync::Arc;
use tokio::task;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    // Parse CLI
    let args = cli::Cli::parse();

    // API Mode
    if args.api {
        if !args.authorized {
             eprintln!("\x1b[31m[ERROR] Authorization Required for API Mode (--authorized)\x1b[0m");
             std::process::exit(1);
        }
        api::start_api().await;
        return Ok(());
    }

    // Global Consent Information
    if !args.authorized {
        eprintln!("
\x1b[31m[ERROR] Authorization Required\x1b[0m
Spectre is a professional security tool for \x1b[1mauthorized testing only\x1b[0m.
You must explicitly provide the --authorized flag to confirm you have permission to test the target.

Usage: spectre --authorized --target <URL>
");
        std::process::exit(1);
    }

    // Load Config (File + CLI Overrides)
    let config_content = fs::read_to_string(&args.config).unwrap_or_else(|_| "".to_string());
    
    // Parse partial config or default
    let mut config: Config = if !config_content.is_empty() {
        toml::from_str(&config_content)?
    } else {
        // Minimal Default Config if no file
        Config {
            general: engine::GeneralConfig {
                target_url: "http://localhost".to_string(),
                concurrency: 1,
                debug_mode: false,
                method: "GET".to_string(),
                headers: vec![],
                raw_body: None,
                payload_file: None,
                tampers: vec![],
                report_file: None,
                time_limit: None,
            },
            profiles: std::collections::HashMap::new(),
            network: engine::NetworkConfig { proxies: vec![] },
        }
    };

    // Apply CLI Overrides
    if let Some(target) = args.target {
        config.general.target_url = target;
    }
    if let Some(c) = args.concurrency {
        config.general.concurrency = c;
    }
    if args.debug {
        config.general.debug_mode = true;
    }
    config.general.method = args.method;
    
    if let Some(data) = args.data {
        config.general.raw_body = Some(data);
    }
    if let Some(h_vec) = args.headers {
        config.general.headers.extend(h_vec);
    }
    
    if let Some(p_file) = args.payloads {
        config.general.payload_file = Some(p_file);
    }
    
    if let Some(t_vec) = args.tamper {
        config.general.tampers = t_vec;
    }

    if let Some(r_file) = args.report {
        config.general.report_file = Some(r_file);
    }
    
    if let Some(tl) = args.time_limit {
        config.general.time_limit = Some(tl);
    }

    // WAF Detection
    if args.detect {
        eprintln!("[\x1b[33m*\x1b[0m] Starting WAF Detection on {}...", config.general.target_url);
        let detector = waf::WafDetector::new();
        match detector.detect(&config.general.target_url).await {
            Ok(waf_type) => {
                eprintln!("[\x1b[32m+\x1b[0m] WAF Identified: \x1b[1m{}\x1b[0m", waf_type);
            },
            Err(e) => eprintln!("[\x1b[31m-\x1b[0m] Detection failed: {}", e),
        }
    }

    // Initialize Engine
    let engine = Arc::new(CoreEngine::new(config));
    let engine_clone = engine.clone();

    // Run Engine in background
    let _engine_handle = task::spawn(async move {
        if let Err(e) = engine_clone.run().await {
            eprintln!("Engine error: {}", e);
        }
    });

    // Run TUI
    let mut tui_app = tui::TuiApp::new(engine.get_stats());
    tui_app.run().await?;

    // --- IMPORTANT: FORCE EXIT ---
    // This kills the background engine tasks immediately
    std::process::exit(0);
}

