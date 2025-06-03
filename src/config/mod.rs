use serde::{Deserialize, Serialize};
use std::fs;
use anyhow::Result;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub enabled_checks: Vec<String>,
    pub severity_threshold: String,
    pub output_format: String,
    pub compiler_settings: CompilerSettings,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CompilerSettings {
    pub optimizer: bool,
    pub runs: u32,
    pub version: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled_checks: vec![
                "compatibility".to_string(),
                "security".to_string(),
                "resources".to_string(),
                "best-practices".to_string(),
            ],
            severity_threshold: "medium".to_string(),
            output_format: "text".to_string(),
            compiler_settings: CompilerSettings {
                optimizer: true,
                runs: 200,
                version: "0.8.0".to_string(),
            },
        }
    }
}

impl Config {
    pub fn load(path: Option<&str>) -> Result<Self> {
        match path {
            Some(p) => {
                let contents = fs::read_to_string(p)?;
                Ok(serde_json::from_str(&contents)?)
            }
            None => Ok(Self::default()),
        }
    }

    pub fn save(&self, path: &str) -> Result<()> {
        let contents = serde_json::to_string_pretty(self)?;
        fs::write(path, contents)?;
        Ok(())
    }
} 