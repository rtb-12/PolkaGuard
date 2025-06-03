use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisResults {
    pub compatibility_issues: Vec<String>,
    pub security_vulnerabilities: Vec<String>,
    pub resource_usage: ResourceUsage,
    pub best_practices: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub gas_estimation: u64,
    pub storage_usage: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContractMetadata {
    pub name: String,
    pub version: String,
    pub compiler_version: String,
    pub source_code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisConfig {
    pub enabled_checks: Vec<String>,
    pub severity_threshold: Severity,
    pub output_format: OutputFormat,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum OutputFormat {
    Text,
    Json,
} 