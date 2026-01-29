use serde::{Serialize, Deserialize};
use std::fs::File;
use std::io::Write;
use anyhow::{Context, Result};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Finding {
    pub url: String,
    pub payload: String,
    pub status_code: u16,
    pub verdict: String,
    pub timestamp: u128,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanSummary {
    pub target: String,
    pub total_requests: usize,
    pub blocked: usize,
    pub successful: usize,
    pub duration_seconds: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    pub summary: ScanSummary,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn new(summary: ScanSummary, findings: Vec<Finding>) -> Self {
        Self { summary, findings }
    }

    pub fn save(&self, path: &str) -> Result<()> {
        if path.ends_with(".json") {
            let file = File::create(path).context("Failed to create JSON report file")?;
            serde_json::to_writer_pretty(file, self)?;
        } else if path.ends_with(".html") {
            let html = self.generate_html();
            let mut file = File::create(path).context("Failed to create HTML report file")?;
            file.write_all(html.as_bytes())?;
        }
        Ok(())
    }

    fn generate_html(&self) -> String {
        format!(
            r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Spectre Security Report</title>
    <style>
        body {{ font-family: sans-serif; margin: 2rem; background: #f4f4f4; }}
        .container {{ max-width: 900px; margin: 0 auto; background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #ddd; padding-bottom: 0.5rem; }}
        .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem; }}
        .card {{ background: #f8f9fa; padding: 1rem; border-radius: 4px; text-align: center; border: 1px solid #ddd; }}
        .card h3 {{ margin: 0; color: #666; font-size: 0.9rem; }}
        .card p {{ margin: 0.5rem 0 0; font-size: 1.5rem; font-weight: bold; color: #333; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
        th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #333; color: white; }}
        tr:nth-child(even) {{ background: #f9f9f9; }}
        .verdict-blocked {{ color: #d9534f; font-weight: bold; }}
        .verdict-success {{ color: #5cb85c; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Spectre Scan Report</h1>
        <div class="summary">
            <div class="card"><h3>Total Requests</h3><p>{}</p></div>
            <div class="card"><h3>Blocked</h3><p>{}</p></div>
            <div class="card"><h3>Passed</h3><p>{}</p></div>
            <div class="card"><h3>Duration</h3><p>{}s</p></div>
        </div>
        
        <h2>Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Status</th>
                    <th>Verdict</th>
                    <th>Payload (Snippet)</th>
                </tr>
            </thead>
            <tbody>
                {}
            </tbody>
        </table>
    </div>
</body>
</html>
"#,
            self.summary.total_requests,
            self.summary.blocked,
            self.summary.successful,
            self.summary.duration_seconds,
            self.findings.iter().map(|f| format!(
                "<tr><td>{}</td><td>{}</td><td class='{}'>{}</td><td><code>{}</code></td></tr>",
                f.timestamp,
                f.status_code,
                if f.verdict.contains("Blocked") { "verdict-blocked" } else { "verdict-success" },
                f.verdict,
                f.payload.chars().take(50).collect::<String>()
            )).collect::<String>()
        )
    }
}
