<p align="center">
  <a href="https://www.rust-lang.org/">
    <img src="https://img.shields.io/badge/Made%20with-Rust-black.svg" alt="Made with Rust">
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/version-0.2.0-black.svg" alt="Version 0.2.0">
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/Engine-Hybrid%20Solver-blueviolet" alt="Engine: Hybrid">
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/Capability-WAF%20Bypass-red" alt="Capability: WAF Bypass">
  </a>
  <a href="https://github.com/id-root/spectre/actions/workflows/ci.yml">
  <img src="https://github.com/id-root/spectre/actions/workflows/ci.yml/badge.svg" alt="Build Status"> 
  </a>
  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-black.svg" alt="License: MIT">
  </a>
</p>

# Spectre - High-Performance Scraping & WAF Bypass Grid

**Spectre** is a Rust-based, high-concurrency web scraping engine designed to bypass modern Web Application Firewalls (WAFs) and challenge pages (like Cloudflare). It utilizes a hybrid approach, combining lightweight TLS-impersonated HTTP requests with heavy-duty headless browser automation when necessary.

## 🚀 Key Features

* **Hybrid Solving Engine**: Prioritizes fast HTTP requests; automatically escalates to a Headless Chrome browser instance only when a JavaScript challenge is detected.
* **TLS Fingerprint Impersonation**: Uses `rquest` to mimic specific browser TLS handshakes (Chrome 130, Safari 16) to evade bot detection.
* **Smart Proxy Management**: Includes a `GridManager` that handles proxy rotation, tracks failures, and enforces cooldown periods on bad nodes.
* **Real-time TUI Dashboard**: A terminal user interface built with `ratatui` to monitor RPS, latency, and grid health.
* **Enterprise Logging**: Thread-safe JSONL logging for detailed session auditing.

---

## 📂 Project Structure

| File | Description |
| :--- | :--- |
| `src/main.rs` | Entry point. Initializes the engine, spawns background workers, and launches the TUI. |
| `src/engine.rs` | The core logic containing the `CoreEngine`, `BrowserSolver`, `GridManager`, and request lifecycle handling. |
| `src/tui.rs` | UI implementation using `ratatui`. Visualizes engine statistics (Sparklines, Gauges). |
| `profiles.toml` | Configuration file for target URLs, concurrency settings, and proxy lists. |
| `infrastructure/main.tf` | Terraform configuration for deploying the engine as distributed AWS Lambda nodes. |

---

## ⚙️ Configuration (`profiles.toml`)

The behavior of the engine is controlled via `profiles.toml`.

```toml
[general]
# The target website to scrape/attack
target_url = ""
# Number of concurrent worker threads
concurrency = 2

[profiles]
# Maps internal profile keys to emulation types
desktop = "chrome_130"
mobile = "safari_16"

[network]
# List of proxy servers to rotate through
proxies = [
    "Add your list of proxies here",
]

```

---

## 🧠 Core Architecture

### 1. The Request Lifecycle

The `CoreEngine` spawns multiple workers based on the `concurrency` setting. Each worker follows this flow:

1. **Proxy Selection**: The `GridManager` provides the next available proxy that is not on cooldown.
2. **Client Creation**: `ClientFactory` generates a TLS-impersonated client (mimicking Chrome 130 or Safari 16).
3. **Initial Request**: A fast HTTP GET request is sent to the target.
4. **Response Analysis**: `ResponseAnalyzer` inspects the status code and body.
* **Success (200 + "Welcome")**: Request counts as successful.
* **Blocked (403/429)**: Proxy is marked for failure; if failures > 3, it enters a 60s cooldown.
* **JS Challenge Detected**: Trigger **Escalation**.



### 2. Browser Escalation (The "Heavy Artillery")

If the `ResponseAnalyzer` detects phrases like "Checking your browser" or "enable JavaScript", the engine escalates:

1. **Launch Chrome**: Starts a headless Chrome instance using `headless_chrome`.
2. **Configuration**: Patches `navigator.webdriver` flags and overrides User-Agents to appear organic.
3. **Solve**: Navigates to the target and waits.
4. **Cookie Extraction**: If the challenge is solved (e.g., "Access Granted" text appears), it extracts the `waf_clearance` cookie for future reuse.

### 3. Monitoring (TUI)

The application runs a TUI on the main thread while the engine runs in the background.

* **KPI Banner**: Shows Total requests, Success/Blocked/Failed counts, and calculated RPS.
* **Latency Sparkline**: Visualizes overhead trends.
* **Grid Health**: A gauge representing the ratio of successful requests vs. total attempts.

---

## 🛠️ Infrastructure

The project includes Terraform code (`infrastructure/main.tf`) for deploying the scraper as a distributed grid on AWS.

* **Provider**: AWS (`us-east-1`).
* **Resource**: `aws_lambda_function` (named `spectre-node-{i}`).
* **Runtime**: `provided.al2` (Custom runtime for the Rust binary).
* **Scale**: Provisions 10 independent lambda nodes.

---

## 📦 Dependencies

Defined in `Cargo.toml`:

* `tokio`: Async runtime.
* `rquest`: TLS impersonation client (Fork of reqwest).
* `headless_chrome`: Controls Chrome via DevTools Protocol.
* `ratatui` & `crossterm`: Terminal UI.
* `anyhow` & `log`: Error handling and logging.

Yes, absolutely. Most security researchers and casual users will prefer downloading the binary rather than setting up a full Rust development environment.

You should add a dedicated **"Quick Start (Binary)"** section to your `README.md`.

Here is a ready-to-use Markdown snippet you can copy directly into your `README.md`. It covers the installation, the critical requirement of `profiles.toml`, and the external dependency on Chrome.

## 🚀 Quick Start (Binary Release)

No Rust installation required.

### 1. Download
Go to the [Releases](https://github.com/id-root/spectre/releases) page and download the latest archive for your OS:
* **Linux**: `spectre-linux-x86_64.tar.gz`
* **Windows**: `spectre-windows-x86_64.zip`

### 2. Install Dependencies
**Spectre requires Google Chrome or Chromium** to solve JavaScript challenges.
* **Linux**: `sudo apt install chromium-browser`
* **Windows**: Install [Google Chrome](https://www.google.com/chrome/).

### 3. Run
Extract the archive. **Important:** The `profiles.toml` file must be in the same folder as the executable.

**Linux:**
```bash
tar -xvf spectre-linux-x86_64.tar.gz
cd spectre-linux-x86_64
chmod +x spectre
./spectre
```


**Windows:**

1. Right-click the zip -> **Extract All**.
2. Open the extracted folder.
3. `spectre.exe`  run it from PowerShell.

### ⚙️ Configuration

Edit `profiles.toml` to set your target:

```toml
[general]
target_url = "http://target-website.com"
concurrency = 2
```



## 📝 Build from source & Run

1. **Prerequisites**:
* Rust Toolchain (`cargo`)
* Google Chrome or Chromium installed (for `headless_chrome` execution).


2. **Build**:
```bash
cargo build --release

```


3. **Run**:
Ensure `profiles.toml` is in the root directory.
```bash
cargo run --release

```

---

## ⚠️ Safe Usage & Legal Disclaimer

**Spectre** is a powerful tool designed for **authorized security testing** and **educational purposes only**. It utilizes techniques (TLS fingerprinting, browser escalation, proxy rotation) that are commonly classified as "adversarial" by defensive systems.

### 1. 🛑 Authorization is Mandatory

* **Do Not Use on Unauthorized Targets**: You must have explicit, written permission from the system owner before running this tool against any URL.
* **WAF Evasion**: The `CoreEngine` is designed to bypass security controls (e.g., Cloudflare, Akamai). Using this against third-party websites without consent may violate the **Computer Fraud and Abuse Act (CFAA)** in the US, the **Computer Misuse Act** in the UK, and similar laws globally.

### 2. 📉 Denial of Service (DoS) Risk

* The `concurrency` setting in `profiles.toml` combined with the AWS Lambda infrastructure can generate significant traffic.
* **Warning**: High concurrency levels can inadvertently degrade or crash target servers. Always throttle your request rates (`concurrency` < 5) during testing to avoid causing a Denial of Service.

### 3. ☁️ Infrastructure & Costs

* **AWS Lambda Billing**: The Terraform script provisions 10 Lambda functions (`spectre-node-{i}`). While `provided.al2` is efficient, high-volume automated browser execution (Headless Chrome) is memory and CPU intensive.
* **Monitor Usage**: Extended runs can lead to unexpected AWS bills. Ensure you destroy infrastructure when not in use:
```bash
terraform destroy

```


* **Cloud Provider TOS**: Using cloud infrastructure (AWS, GCP, Azure) to launch abusive traffic or evasive scraping bots often violates Acceptable Use Policies and can result in account suspension.

### 4. 🤖 Ethical Scraping Guidelines

If using this for legitimate data aggregation:

* **Respect** `robots.txt`: Check the target's policy on automated collection.
* **User-Agent Identification**: Consider modifying the `BrowserSolver` in `src/engine.rs` to include a contact email in the User-Agent string so system admins can contact you if your bot causes issues.
* **Data Privacy**: Do not scrape or store Personally Identifiable Information (PII) (e.g., EU GDPR compliance).

---

**DISCLAIMER**: The authors and contributors of Spectre are not responsible for any misuse, damage, or legal consequences resulting from the execution of this software. Use responsibly.
