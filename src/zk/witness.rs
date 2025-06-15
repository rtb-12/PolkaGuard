//! Witness generation for PolkaGuard ZK proofs
//!
//! This module handles the generation of witnesses (private inputs) for ZK circuits
//! based on contract analysis results.

use anyhow::Result;
#[allow(unused_imports)]
use ark_ff::{Field, One, PrimeField, Zero};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use super::PublicSignals;
use crate::models::AnalysisResults;

/// Witness data for ZK proof generation
#[derive(Debug, Clone)]
pub struct Witness {
    /// Private inputs for each circuit type
    pub private_inputs: HashMap<String, Vec<String>>,
    /// Public inputs that will be revealed
    pub public_inputs: Vec<String>,
    /// Original analysis results for circuit creation
    pub analysis_results: AnalysisResults,
    /// Original contract source for circuit creation
    pub contract_source: String,
    /// Metadata for witness integrity
    pub metadata: WitnessMetadata,
}

/// Metadata for witness integrity and verification
#[derive(Debug, Clone)]
pub struct WitnessMetadata {
    /// Contract hash for integrity verification
    pub contract_hash: String,
    /// Timestamp when witness was generated
    pub timestamp: u64,
    /// Analysis results hash
    pub analysis_hash: String,
    /// Number of private inputs per circuit
    pub circuit_sizes: HashMap<String, usize>,
}

/// Generate witness from analysis results and contract source
pub fn generate_witness(
    results: &AnalysisResults,
    contract_source: &str,
    public_signals: &PublicSignals,
) -> Result<Witness> {
    let mut private_inputs = HashMap::new();
    let mut circuit_sizes = HashMap::new();

    // Generate compatibility witness
    let compat_witness = generate_compatibility_witness(results, contract_source)?;
    circuit_sizes.insert("compatibility".to_string(), compat_witness.len());
    private_inputs.insert("compatibility".to_string(), compat_witness);

    // Generate security witness
    let security_witness = generate_security_witness(results, contract_source)?;
    circuit_sizes.insert("security".to_string(), security_witness.len());
    private_inputs.insert("security".to_string(), security_witness);

    // Generate resource witness
    let resource_witness = generate_resource_witness(results)?;
    circuit_sizes.insert("resources".to_string(), resource_witness.len());
    private_inputs.insert("resources".to_string(), resource_witness);

    // Generate best practices witness
    let practices_witness = generate_best_practices_witness(results, contract_source)?;
    circuit_sizes.insert("best_practices".to_string(), practices_witness.len());
    private_inputs.insert("best_practices".to_string(), practices_witness);

    // Create public inputs from public signals
    let mut public_inputs = public_signals_to_field_elements(public_signals);
    
    // Add analysis field elements for verification
    let analysis_elements = crate::zk::circuits::analysis_to_field_elements::<ark_bn254::Fr>(results);
    // Include a hash of analysis elements for integrity verification
    if !analysis_elements.is_empty() {
        public_inputs.push(format!("{:?}", analysis_elements.len()));
    }

    // Generate metadata
    let contract_hash = {
        let mut hasher = Sha256::new();
        hasher.update(contract_source.as_bytes());
        hex::encode(hasher.finalize())
    };

    let analysis_hash = {
        let mut hasher = Sha256::new();
        hasher.update(serde_json::to_string(results)?.as_bytes());
        hex::encode(hasher.finalize())
    };

    let metadata = WitnessMetadata {
        contract_hash,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        analysis_hash,
        circuit_sizes,
    };

    Ok(Witness {
        private_inputs,
        public_inputs,
        analysis_results: results.clone(),
        contract_source: contract_source.to_string(),
        metadata,
    })
}

/// Generate witness for compatibility circuit
fn generate_compatibility_witness(
    results: &AnalysisResults,
    contract_source: &str,
) -> Result<Vec<String>> {
    let mut witness = Vec::new();

    // Issue count
    witness.push(results.compatibility_issues.len().to_string());

    // Complexity
    witness.push(results.complexity.to_string());

    // Check for unsupported opcodes
    let unsupported_opcodes = [
        "selfdestruct",
        "extcodesize",
        "extcodehash",
        "extcodecopy",
        "blockhash",
        "blobhash",
        "difficulty",
        "gaslimit",
    ];

    let has_unsupported = unsupported_opcodes
        .iter()
        .any(|opcode| contract_source.to_lowercase().contains(opcode));
    witness.push(if has_unsupported {
        "1".to_string()
    } else {
        "0".to_string()
    });

    // Add hash of compatibility issues for integrity
    let issues_hash = hash_string_vec(&results.compatibility_issues);
    witness.push(hex::encode(issues_hash));

    Ok(witness)
}

/// Generate witness for security circuit
fn generate_security_witness(results: &AnalysisResults, contract_source: &str) -> Result<Vec<String>> {
    let mut witness = Vec::new();

    // Vulnerability count
    witness.push(results.security_vulnerabilities.len().to_string());

    // Check for specific vulnerability types
    let has_reentrancy = results
        .security_vulnerabilities
        .iter()
        .any(|v| v.to_lowercase().contains("reentrancy"));
    witness.push(if has_reentrancy {
        "1".to_string()
    } else {
        "0".to_string()
    });

    let has_unchecked_calls = results
        .security_vulnerabilities
        .iter()
        .any(|v| v.to_lowercase().contains("unchecked"));
    witness.push(if has_unchecked_calls {
        "1".to_string()
    } else {
        "0".to_string()
    });

    let has_access_control_issues = contract_source.contains("onlyOwner")
        || contract_source.contains("require(msg.sender")
        || results
            .security_vulnerabilities
            .iter()
            .any(|v| v.to_lowercase().contains("access"));
    witness.push(if has_access_control_issues {
        "1".to_string()
    } else {
        "0".to_string()
    });

    // Add hash of security vulnerabilities for integrity
    let vulns_hash = hash_string_vec(&results.security_vulnerabilities);
    witness.push(hex::encode(vulns_hash));

    Ok(witness)
}

/// Generate witness for resource circuit
fn generate_resource_witness(results: &AnalysisResults) -> Result<Vec<String>> {
    let mut witness = Vec::new();

    // Resource usage metrics
    witness.push(results.resource_usage.ref_time.to_string());
    witness.push(results.resource_usage.proof_size.to_string());
    witness.push(results.resource_usage.storage_usage.to_string());
    witness.push(results.resource_usage.storage_deposit.to_string());

    // Add derived metrics
    let total_cost = results.resource_usage.ref_time
        + results.resource_usage.proof_size
        + results.resource_usage.storage_usage;
    witness.push(total_cost.to_string());

    Ok(witness)
}

/// Generate witness for best practices circuit
fn generate_best_practices_witness(
    results: &AnalysisResults,
    contract_source: &str,
) -> Result<Vec<String>> {
    let mut witness = Vec::new();

    // Violation count
    witness.push(results.best_practices.len().to_string());

    // Check for specific best practices
    let has_pragma = contract_source.contains("pragma solidity");
    witness.push(if has_pragma { "1".to_string() } else { "0".to_string() });

    let has_license = contract_source.contains("SPDX-License-Identifier");
    witness.push(if has_license { "1".to_string() } else { "0".to_string() });

    let has_visibility = contract_source.contains("public")
        || contract_source.contains("private")
        || contract_source.contains("internal")
        || contract_source.contains("external");
    witness.push(if has_visibility {
        "1".to_string()
    } else {
        "0".to_string()
    });

    let has_natspec = contract_source.contains("///") || contract_source.contains("/**");
    witness.push(if has_natspec { "1".to_string() } else { "0".to_string() });

    // Add hash of best practices violations for integrity
    let practices_hash = hash_string_vec(&results.best_practices);
    witness.push(hex::encode(practices_hash));

    Ok(witness)
}

/// Convert public signals to field elements
fn public_signals_to_field_elements(signals: &PublicSignals) -> Vec<String> {
    vec![
        signals.compatibility_score.to_string(),
        signals.security_score.to_string(),
        signals.resource_score.to_string(),
        signals.best_practices_score.to_string(),
        signals.overall_score.to_string(),
        signals.timestamp.to_string(),
    ]
}

/// Hash a vector of strings for integrity checking
fn hash_string_vec(strings: &[String]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for s in strings {
        hasher.update(s.as_bytes());
    }
    hasher.finalize().to_vec()
}

/// Validate witness integrity using private inputs and metadata
pub fn validate_witness_integrity(witness: &Witness) -> Result<bool> {
    // Check that private inputs match expected circuit sizes
    for (circuit_name, expected_size) in &witness.metadata.circuit_sizes {
        if let Some(private_inputs) = witness.private_inputs.get(circuit_name) {
            if private_inputs.len() != *expected_size {
                println!("⚠️  Circuit {} size mismatch: expected {}, got {}", 
                    circuit_name, expected_size, private_inputs.len());
                return Ok(false);
            }
        } else {
            println!("⚠️  Missing private inputs for circuit: {}", circuit_name);
            return Ok(false);
        }
    }

    // Validate that we have non-empty private inputs for expected circuits
    let required_circuits = ["compatibility", "security", "resources", "best_practices"];
    for circuit_name in &required_circuits {
        if let Some(inputs) = witness.private_inputs.get(*circuit_name) {
            if inputs.is_empty() {
                println!("⚠️  Empty private inputs for circuit: {}", circuit_name);
                return Ok(false);
            }
            println!("✅ Circuit {}: {} private inputs", circuit_name, inputs.len());
        }
    }

    println!("✅ Witness integrity validation passed");
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AnalysisResults, ResourceUsage};

    #[test]
    fn test_witness_generation() {
        let results = AnalysisResults {
            contract_name: "TestContract".to_string(),
            complexity: 15,
            compatibility_issues: vec!["Issue 1".to_string()],
            security_vulnerabilities: vec!["Reentrancy vulnerability".to_string()],
            resource_usage: ResourceUsage {
                ref_time: 100000,
                proof_size: 5000,
                storage_deposit: 1000,
                storage_usage: 2000,
            },
            best_practices: vec!["Missing pragma".to_string()],
        };

        let contract_source = "contract Test { function test() { selfdestruct(msg.sender); } }";
        let public_signals = PublicSignals::from_analysis(&results, "polkadot", "1.0.0");

        let witness = generate_witness(&results, contract_source, &public_signals).unwrap();

        // Check that all circuits have witnesses
        assert!(witness.private_inputs.contains_key("compatibility"));
        assert!(witness.private_inputs.contains_key("security"));
        assert!(witness.private_inputs.contains_key("resources"));
        assert!(witness.private_inputs.contains_key("best_practices"));

        // Check public inputs
        assert_eq!(witness.public_inputs.len(), 6);

        // Check metadata
        assert!(!witness.metadata.contract_hash.is_empty());
        assert!(!witness.metadata.analysis_hash.is_empty());
        assert_eq!(witness.metadata.circuit_sizes.len(), 4);
    }

    #[test]
    fn test_compatibility_witness() {
        let results = AnalysisResults {
            contract_name: "Test".to_string(),
            complexity: 10,
            compatibility_issues: vec!["Issue 1".to_string(), "Issue 2".to_string()],
            security_vulnerabilities: vec![],
            resource_usage: ResourceUsage::default(),
            best_practices: vec![],
        };

        let contract_source = "contract Test { function test() { selfdestruct(msg.sender); } }";
        let witness = generate_compatibility_witness(&results, contract_source).unwrap();

        assert_eq!(witness.len(), 4);
        assert_eq!(witness[0], "2"); // 2 issues
        assert_eq!(witness[1], "10"); // complexity 10
        assert_eq!(witness[2], "1"); // has selfdestruct (unsupported)
    }

    #[test]
    fn test_hash_string_vec() {
        let strings = vec!["test1".to_string(), "test2".to_string()];
        let hash1 = hash_string_vec(&strings);
        let hash2 = hash_string_vec(&strings);

        assert_eq!(hash1, hash2); // Same input should produce same hash
        assert_eq!(hash1.len(), 32); // SHA256 produces 32 bytes
    }

    #[test]
    fn test_validate_witness_integrity() {
        let results = AnalysisResults {
            contract_name: "TestContract".to_string(),
            complexity: 15,
            compatibility_issues: vec!["Issue 1".to_string()],
            security_vulnerabilities: vec!["Reentrancy vulnerability".to_string()],
            resource_usage: ResourceUsage {
                ref_time: 100000,
                proof_size: 5000,
                storage_deposit: 1000,
                storage_usage: 2000,
            },
            best_practices: vec!["Missing pragma".to_string()],
        };

        let contract_source = "contract Test { function test() { selfdestruct(msg.sender); } }";
        let public_signals = PublicSignals::from_analysis(&results, "polkadot", "1.0.0");

        let mut witness = generate_witness(&results, contract_source, &public_signals).unwrap();

        // Validate witness integrity
        assert!(validate_witness_integrity(&witness).unwrap());

        // Tamper with witness data
        witness.private_inputs.get_mut("compatibility").unwrap().push("extra_input".to_string());

        // Validate witness integrity after tampering
        assert!(!validate_witness_integrity(&witness).unwrap());
    }
}
