use anyhow::Result;
use crate::models::{AnalysisResults, ResourceUsage};
use crate::utils::{extract_contract_name, calculate_complexity};
use std::fs;

pub struct Analyzer {
    contract_path: String,
    contract_name: Option<String>,
    complexity: u32,
    enabled_checks: Vec<String>,
}

impl Analyzer {
    pub fn new(contract_path: &str, enabled_checks: Option<Vec<String>>) -> Result<Self> {
        let source = fs::read_to_string(contract_path)?;
        let contract_name = extract_contract_name(&source);
        let complexity = calculate_complexity(&source);
        
        Ok(Self {
            contract_path: contract_path.to_string(),
            contract_name,
            complexity,
            enabled_checks: enabled_checks.unwrap_or_default(),
        })
    }

    pub async fn analyze(&self) -> Result<AnalysisResults> {
        let mut results = AnalysisResults::default();
        
        // Add contract metadata
        if let Some(name) = &self.contract_name {
            results.contract_name = name.clone();
        }
        results.complexity = self.complexity;
        
        // Run enabled checks or all checks if none specified
        if self.enabled_checks.is_empty() || self.enabled_checks.contains(&"resources".to_string()) {
            self.estimate_resources(&mut results)?;
        }
        
        if self.enabled_checks.is_empty() || self.enabled_checks.contains(&"compatibility".to_string()) {
            self.check_compatibility(&mut results)?;
        }
        
        if self.enabled_checks.is_empty() || self.enabled_checks.contains(&"security".to_string()) {
            self.check_security(&mut results)?;
        }
        
        if self.enabled_checks.is_empty() || self.enabled_checks.contains(&"best-practices".to_string()) {
            self.check_best_practices(&mut results)?;
        }
        
        Ok(results)
    }

    fn estimate_resources(&self, results: &mut AnalysisResults) -> Result<()> {

        const BASE_REF_TIME: u64 = 21_000;
        const FUNCTION_CALL_REF_TIME: u64 = 2_100;
        const STORAGE_WRITE_REF_TIME: u64 = 20_000;
        const STORAGE_READ_REF_TIME: u64 = 800;
        const MEMORY_OP_REF_TIME: u64 = 3;
        const LOG_BASE_REF_TIME: u64 = 375;
        const LOG_TOPIC_REF_TIME: u64 = 375;
        const EXTERNAL_CALL_REF_TIME: u64 = 400;


        const BASE_PROOF_SIZE: u64 = 1_000;
        const STORAGE_WRITE_PROOF_SIZE: u64 = 100;
        const STORAGE_READ_PROOF_SIZE: u64 = 50;
        const LOG_PROOF_SIZE: u64 = 200;


        const STORAGE_DEPOSIT_PER_BYTE: u64 = 1_000_000_000; // 1 ETH per byte

        let source = fs::read_to_string(&self.contract_path)?;
        

        let function_calls = source.matches("function").count();
        let storage_writes = source.matches("storage").count();
        let storage_reads = source.matches("load").count();
        let memory_ops = source.matches("memory").count();
        let log_ops = source.matches("emit").count();
        let external_calls = source.matches("call").count();


        let mut ref_time = BASE_REF_TIME;
        ref_time += function_calls as u64 * FUNCTION_CALL_REF_TIME;
        ref_time += storage_writes as u64 * STORAGE_WRITE_REF_TIME;
        ref_time += storage_reads as u64 * STORAGE_READ_REF_TIME;
        ref_time += memory_ops as u64 * MEMORY_OP_REF_TIME;
        ref_time += log_ops as u64 * (LOG_BASE_REF_TIME + LOG_TOPIC_REF_TIME);
        ref_time += external_calls as u64 * EXTERNAL_CALL_REF_TIME;


        ref_time = (ref_time as f64 * 1.2) as u64;


        let mut proof_size = BASE_PROOF_SIZE;
        proof_size += storage_writes as u64 * STORAGE_WRITE_PROOF_SIZE;
        proof_size += storage_reads as u64 * STORAGE_READ_PROOF_SIZE;
        proof_size += log_ops as u64 * LOG_PROOF_SIZE;


        let storage_usage = (storage_writes * 32) as u64; // Assuming 32 bytes per storage slot
        let storage_deposit = storage_usage * STORAGE_DEPOSIT_PER_BYTE;

        results.resource_usage = ResourceUsage {
            ref_time,
            proof_size,
            storage_deposit,
            storage_usage,
        };

        Ok(())
    }

    fn check_compatibility(&self, results: &mut AnalysisResults) -> Result<()> {
        let source = fs::read_to_string(&self.contract_path)?;
        

        let unsupported_opcodes = [
            "selfdestruct",
            "extcodesize",
            "extcodehash",
            "extcodecopy",
            "blockhash",
            "blobhash",
        ];

        for opcode in unsupported_opcodes {
            if source.contains(opcode) {
                results.compatibility_issues.push(format!(
                    "Unsupported opcode '{}' used in contract",
                    opcode
                ));
            }
        }

        Ok(())
    }

    fn check_security(&self, results: &mut AnalysisResults) -> Result<()> {
        let source = fs::read_to_string(&self.contract_path)?;
        

        if source.contains("call") && !source.contains("reentrancy") {
            results.security_vulnerabilities.push(
                "Potential reentrancy vulnerability: External calls without reentrancy guard".to_string()
            );
        }


        if source.contains("send") && !source.contains("require") {
            results.security_vulnerabilities.push(
                "Unchecked send operation: Missing require statement after send".to_string()
            );
        }

        Ok(())
    }

    fn check_best_practices(&self, results: &mut AnalysisResults) -> Result<()> {
        let source = fs::read_to_string(&self.contract_path)?;
        

        if !source.contains("pragma solidity") {
            results.best_practices.push(
                "Missing pragma directive: Should specify Solidity version".to_string()
            );
        }


        if !source.contains("SPDX-License-Identifier") {
            results.best_practices.push(
                "Missing license identifier: Should include SPDX-License-Identifier".to_string()
            );
        }


        if source.contains("function") && !source.contains("public") && !source.contains("private") && !source.contains("internal") && !source.contains("external") {
            results.best_practices.push(
                "Missing function visibility modifier".to_string()
            );
        }

        Ok(())
    }
} 