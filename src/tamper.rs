use base64::{engine::general_purpose, Engine as _};
use urlencoding::encode;

#[derive(Debug, Clone, PartialEq)]
pub enum TamperType {
    None,
    UrlEncode,
    DoubleUrlEncode,
    Base64,
    UnicodeOverflow,
}

impl std::str::FromStr for TamperType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(TamperType::None),
            "url" => Ok(TamperType::UrlEncode),
            "doubleurl" => Ok(TamperType::DoubleUrlEncode),
            "base64" => Ok(TamperType::Base64),
            "unicode" => Ok(TamperType::UnicodeOverflow),
            _ => Err(format!("Unknown tamper type: {}", s)),
        }
    }
}

pub struct TamperEngine;

impl TamperEngine {
    pub fn apply(input: &str, tampers: &[TamperType]) -> String {
        let mut result = input.to_string();

        for tamper in tampers {
            result = match tamper {
                TamperType::None => result,
                TamperType::UrlEncode => encode(&result).to_string(),
                TamperType::DoubleUrlEncode => encode(&encode(&result)).to_string(),
                TamperType::Base64 => general_purpose::STANDARD.encode(result),
                TamperType::UnicodeOverflow => {
                    result.chars().map(|c| match c {
                        '<' => '＜',
                        '>' => '＞',
                        '\'' => '＇',
                        '"' => '＂',
                        '(' => '（',
                        ')' => '）',
                        ';' => '；',
                        '-' => '－',
                        '/' => '／',
                        _ => c,
                    }).collect()
                }
            };
        }
        result
    }
}
