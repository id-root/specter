use anyhow::Result;
use rquest::Client;

#[derive(Debug, Clone, PartialEq)]
pub enum WafType {
    Cloudflare,
    CloudFront,
    Akamai,
    Imperva,
    Azure,
    BunkerWeb,
    Unknown,
    #[allow(dead_code)]
    None,
}

impl std::fmt::Display for WafType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub struct WafSignature {
    pub name: WafType,
    pub headers: Vec<&'static str>,
    pub body_keywords: Vec<&'static str>,
}

pub struct WafDetector {
    signatures: Vec<WafSignature>,
}

impl WafDetector {
    pub fn new() -> Self {
        Self {
            signatures: vec![
                WafSignature {
                    name: WafType::Cloudflare,
                    headers: vec!["cf-ray", "__cfduid", "cf-cache-status"],
                    body_keywords: vec!["cloudflare"],
                },
                WafSignature {
                    name: WafType::CloudFront,
                    headers: vec!["x-amz-cf-id", "via"],
                    body_keywords: vec!["cloudfront"],
                },
                WafSignature {
                    name: WafType::Akamai,
                    headers: vec!["x-akamai-transformed", "akamai-origin-hop"],
                    body_keywords: vec!["akamai"],
                },
                WafSignature {
                    name: WafType::Imperva,
                    headers: vec!["x-cdn", "incap-ses"],
                    body_keywords: vec!["incapsula"],
                },
                WafSignature {
                    name: WafType::Azure,
                    headers: vec!["x-azure-ref", "x-fd-ref"],
                    body_keywords: vec!["azure"],
                },
                 WafSignature {
                    name: WafType::BunkerWeb,
                    headers: vec!["x-bunkerweb"],
                    body_keywords: vec!["bunkerweb", "bw_id"],
                },
            ],
        }
    }

    pub async fn detect(&self, url: &str) -> Result<WafType> {
        let client = Client::builder()
            .build()?;

        // 1. Benign Request
        let response = client.get(url).send().await;

        match response {
            Ok(resp) => {
                let headers = resp.headers().clone(); // Clone headers to keep ownership
                let body_bytes = resp.bytes().await.unwrap_or_default();
                let body = String::from_utf8_lossy(&body_bytes).to_lowercase();
                
                for sig in &self.signatures {
                    // Check Headers
                    for h in &sig.headers {
                        if headers.contains_key(*h) {
                            return Ok(sig.name.clone());
                        }
                    }
                    // Check Body
                    for k in &sig.body_keywords {
                        if body.contains(k) {
                            return Ok(sig.name.clone());
                        }
                    }
                }
            }
            Err(_) => return Ok(WafType::Unknown),
        }

        // 2. Provocation Request (Optional - keeping generic for now)
        // A slightly suspicious request could trigger WAF signatures that only appear on blocks.
        // For Phase 3 basic, we stick to passive + standard response detection.

        Ok(WafType::Unknown)
    }
}
