use anyhow::Result;
use std::process::Command;
use crate::models::{AnalysisResults, ContractMetadata, ResourceUsage};

pub struct Analyzer {
    path: String,
}

impl Analyzer {
    pub fn new(path: &str) -> Result<Self> {
        Ok(Self {
            path: path.to_string(),
        })
    }

    pub async fn analyze(&self) -> Result<AnalysisResults> {
        let contract_metadata = self.load_contract()?;
        
        let mut results = AnalysisResults {
            compatibility_issues: Vec::new(),
            security_vulnerabilities: Vec::new(),
            resource_usage: ResourceUsage {
                gas_estimation: 0,
                storage_usage: 0,
            },
            best_practices: Vec::new(),
        };

        // Run compatibility checks
        self.check_compatibility(&contract_metadata, &mut results)?;

        // Run security analysis
        self.analyze_security(&contract_metadata, &mut results)?;

        // Estimate resource usage
        self.estimate_resources(&contract_metadata, &mut results)?;

        // Check best practices
        self.check_best_practices(&contract_metadata, &mut results)?;

        Ok(results)
    }

    fn load_contract(&self) -> Result<ContractMetadata> {
        let source = std::fs::read_to_string(&self.path)?;
        
        let output = Command::new("solc")
            .arg("--version")
            .output()?;
        
        Ok(ContractMetadata {
            name: "Contract".to_string(),
            version: "0.1.0".to_string(),
            compiler_version: String::from_utf8_lossy(&output.stdout).to_string(),
            source_code: source,
        })
    }

    fn check_compatibility(&self, metadata: &ContractMetadata, results: &mut AnalysisResults) -> Result<()> {
        // Check for EVM-specific features that might not work in PolkaVM
        let evm_specific_patterns = [
            "assembly",
            "selfdestruct",
            "suicide",
            "block.coinbase",
            "block.difficulty",
        ];

        for pattern in evm_specific_patterns {
            if metadata.source_code.contains(pattern) {
                results.compatibility_issues.push(
                    format!("Contract uses EVM-specific feature: {}", pattern)
                );
            }
        }

        Ok(())
    }

    fn analyze_security(&self, metadata: &ContractMetadata, results: &mut AnalysisResults) -> Result<()> {
        // Check for common security vulnerabilities
        let security_patterns = [
            ("reentrancy", "Potential reentrancy vulnerability detected"),
            ("unchecked-send", "Unchecked send/call detected"),
            ("integer-overflow", "Potential integer overflow detected"),
            ("uninitialized-storage", "Uninitialized storage pointer detected"),
        ];

        for (pattern, message) in security_patterns {
            if metadata.source_code.contains(pattern) {
                results.security_vulnerabilities.push(message.to_string());
            }
        }

        Ok(())
    }

    fn estimate_resources(&self, metadata: &ContractMetadata, results: &mut AnalysisResults) -> Result<()> {
        // Simple estimation based on contract size and complexity currently not implemented( rough estimation)
        let size = metadata.source_code.len() as u64;
        results.resource_usage.gas_estimation = size * 100; 
        results.resource_usage.storage_usage = size / 2; 

        Ok(())
    }

    fn check_best_practices(&self, metadata: &ContractMetadata, results: &mut AnalysisResults) -> Result<()> {
        // Check for Solidity best practices
        let best_practices = [
            ("pragma solidity", "Use specific compiler version"),
            ("require(", "Use require statements for input validation"),
            ("event ", "Define events for important state changes"),
            ("modifier ", "Use modifiers for access control"),
        ];

        for (pattern, message) in best_practices {
            if !metadata.source_code.contains(pattern) {
                results.best_practices.push(format!("Missing: {}", message));
            }
        }

        Ok(())
    }
} 