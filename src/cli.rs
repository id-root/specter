use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// MANDATORY: confirms that you have authorization to test the target.
    #[arg(long, required = true)]
    pub authorized: bool,

    /// Configuration file to load settings from.
    #[arg(short, long, default_value = "profiles.toml")]
    pub config: String,

    /// Target URL (overrides config).
    #[arg(short, long)]
    pub target: Option<String>,

    /// HTTP Method (GET, POST, PUT, DELETE, PATCH, etc.)
    #[arg(short, long, default_value = "GET")]
    pub method: String,

    /// Raw request body data (for POST/PUT).
    #[arg(short, long)]
    pub data: Option<String>,

    /// Headers in Key:Value format (can be used multiple times).
    #[arg(long)]
    pub headers: Option<Vec<String>>,

    /// Concurrency level (overrides config).
    #[arg(long)]
    pub concurrency: Option<usize>,

    /// Profile to use (e.g., desktop, mobile) (overrides config).
    #[arg(short, long)]
    pub profile: Option<String>,

    /// Enable debug mode.
    #[arg(long)]
    pub debug: bool,

    /// Path to a file containing payloads (one per line).
    #[arg(long)]
    pub payloads: Option<String>,

    /// Comma-separated list of tampers to apply (e.g., "url,b64").
    #[arg(long, value_delimiter = ',', num_args = 0..)]
    pub tamper: Option<Vec<String>>,

    /// Enable WAF detection before starting attacks.
    #[arg(long)]
    pub detect: bool,

    /// Report output path (supports .json and .html).
    #[arg(long)]
    pub report: Option<String>,

    /// Stop the scan after N seconds (safety cutoff).
    #[arg(long)]
    pub time_limit: Option<u64>,

    /// Run in REST API mode.
    #[arg(long)]
    pub api: bool,
}
