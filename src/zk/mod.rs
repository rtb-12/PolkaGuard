//! Zero-Knowledge Proof Module for PolkaGuard
//!
//! This module provides cryptographic proof generation and verification
//! for contract analysis results without revealing the source code.
//!
//! ## Architecture
//!
//! The ZK module implements a circuit-based approach where each analysis check
//! (compatibility, security, resources, best-practices) is encoded as a circuit.
//! The prover generates witnesses from contract analysis and produces a SNARK proof
//! that all checks passed.
//!
//! ## Usage
//!
//! ```bash
//! polkaguard --path contract.sol prove
//! ```
//!
//! This generates:
//! - `contract_proof.json` - The ZK proof
//! - `public_signals.json` - Public metadata (rule version, scores)
//! - `verifier.sol` - Solidity verifier contract (optional)

use anyhow::Result;
use serde::{Deserialize, Serialize};

pub mod circuits;
pub mod prover;
pub mod verifier;
pub mod witness;

#[cfg(feature = "production")]
pub mod production_prover;

use crate::models::AnalysisResults;

/// ZK-proof configuration and parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkConfig {
    /// Circuit type to use (groth16, plonk)
    pub circuit_type: CircuitType,
    /// Security level (128, 192, 256 bits)
    pub security_level: u32,
    /// Whether to generate Solidity verifier
    pub generate_solidity_verifier: bool,
    /// Output directory for proof artifacts
    pub output_dir: String,
    /// Rule set version for compatibility
    pub rule_version: String,
}

/// Supported circuit types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CircuitType {
    Groth16,
    Plonk,
}

/// Public signals included in the proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicSignals {
    /// Rule set version used for analysis
    pub rule_version: String,
    /// Timestamp when proof was generated
    pub timestamp: u64,
    /// Overall compatibility score (0-100)
    pub compatibility_score: u32,
    /// Security assessment score (0-100)
    pub security_score: u32,
    /// Resource efficiency score (0-100)
    pub resource_score: u32,
    /// Best practices compliance score (0-100)
    pub best_practices_score: u32,
    /// Combined overall score
    pub overall_score: u32,
    /// Contract complexity level (low, medium, high)
    pub complexity_level: String,
    /// Network target (polkadot, kusama, etc.)
    pub network_target: String,
}

/// Generated proof package
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofPackage {
    /// The actual ZK proof
    pub proof: String,
    /// Public signals/inputs
    pub public_signals: PublicSignals,
    /// Verification key (for standalone verification)
    pub verification_key: String,
    /// Proof generation metadata
    pub metadata: ProofMetadata,
}

/// Metadata about proof generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// Proof generation time in milliseconds
    pub generation_time_ms: u64,
    /// Circuit type used
    pub circuit_type: CircuitType,
    /// Security level
    pub security_level: u32,
    /// Prover version
    pub prover_version: String,
    /// Contract hash (for integrity)
    pub contract_hash: String,
}

impl Default for ZkConfig {
    fn default() -> Self {
        Self {
            circuit_type: CircuitType::Groth16,
            security_level: 128,
            generate_solidity_verifier: true,
            output_dir: "./zk_proofs".to_string(),
            rule_version: "1.0.0".to_string(),
        }
    }
}

impl PublicSignals {
    /// Create public signals from analysis results
    pub fn from_analysis(results: &AnalysisResults, network: &str, rule_version: &str) -> Self {
        let compatibility_score = Self::calculate_compatibility_score(results);
        let security_score = Self::calculate_security_score(results);
        let resource_score = Self::calculate_resource_score(results);
        let best_practices_score = Self::calculate_best_practices_score(results);

        let overall_score =
            (compatibility_score + security_score + resource_score + best_practices_score) / 4;

        let complexity_level = match results.complexity {
            0..=10 => "low",
            11..=25 => "medium",
            _ => "high",
        }
        .to_string();

        Self {
            rule_version: rule_version.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            compatibility_score,
            security_score,
            resource_score,
            best_practices_score,
            overall_score,
            complexity_level,
            network_target: network.to_string(),
        }
    }

    fn calculate_compatibility_score(results: &AnalysisResults) -> u32 {
        if results.compatibility_issues.is_empty() {
            100
        } else {
            std::cmp::max(0, 100 - (results.compatibility_issues.len() as u32 * 10)) as u32
        }
    }

    fn calculate_security_score(results: &AnalysisResults) -> u32 {
        if results.security_vulnerabilities.is_empty() {
            100
        } else {
            std::cmp::max(
                0,
                100 - (results.security_vulnerabilities.len() as u32 * 15),
            ) as u32
        }
    }

    fn calculate_resource_score(results: &AnalysisResults) -> u32 {
        // Score based on resource efficiency
        let ref_time_penalty = if results.resource_usage.ref_time > 1_000_000 {
            20
        } else {
            0
        };
        let proof_size_penalty = if results.resource_usage.proof_size > 100_000 {
            15
        } else {
            0
        };
        let storage_penalty = if results.resource_usage.storage_usage > 100_000 {
            10
        } else {
            0
        };

        std::cmp::max(
            0,
            100 - ref_time_penalty - proof_size_penalty - storage_penalty,
        ) as u32
    }

    fn calculate_best_practices_score(results: &AnalysisResults) -> u32 {
        if results.best_practices.is_empty() {
            100
        } else {
            std::cmp::max(0, 100 - (results.best_practices.len() as u32 * 5)) as u32
        }
    }
}

/// Main ZK proof generation interface
pub struct ZkProver {
    config: ZkConfig,
}

impl ZkProver {
    pub fn new(config: ZkConfig) -> Self {
        Self { config }
    }

    /// Generate a ZK proof for the given analysis results
    pub async fn generate_proof(
        &self,
        results: &AnalysisResults,
        contract_source: &str,
        network: &str,
    ) -> Result<ProofPackage> {
        let start_time = std::time::Instant::now();

        // Generate public signals
        let public_signals =
            PublicSignals::from_analysis(results, network, &self.config.rule_version);

        // Generate witness from analysis results
        let witness = witness::generate_witness(results, contract_source, &public_signals)?;

        // Generate the actual proof
        let (proof, verification_key) =
            prover::generate_groth16_proof(&witness, &self.config).await?;

        // Calculate contract hash for integrity
        let contract_hash = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(contract_source.as_bytes());
            hex::encode(hasher.finalize())
        };

        let generation_time_ms = start_time.elapsed().as_millis() as u64;

        let proof_package = ProofPackage {
            proof,
            public_signals,
            verification_key,
            metadata: ProofMetadata {
                generation_time_ms,
                circuit_type: self.config.circuit_type.clone(),
                security_level: self.config.security_level,
                prover_version: env!("CARGO_PKG_VERSION").to_string(),
                contract_hash,
            },
        };

        Ok(proof_package)
    }

    /// Verify a generated proof
    pub async fn verify_proof(&self, proof_package: &ProofPackage) -> Result<bool> {
        verifier::verify_groth16_proof(proof_package).await
    }

    /// Save proof package to files
    pub async fn save_proof_package(
        &self,
        proof_package: &ProofPackage,
        contract_name: &str,
    ) -> Result<Vec<String>> {
        use std::fs;
        use std::path::Path;

        // Create output directory
        fs::create_dir_all(&self.config.output_dir)?;

        let mut created_files = Vec::new();
        let base_name = format!("{}/{}", self.config.output_dir, contract_name);

        // Save proof
        let proof_file = format!("{}_proof.json", base_name);
        fs::write(&proof_file, serde_json::to_string_pretty(proof_package)?)?;
        created_files.push(proof_file);

        // Save public signals separately
        let signals_file = format!("{}_public_signals.json", base_name);
        fs::write(
            &signals_file,
            serde_json::to_string_pretty(&proof_package.public_signals)?,
        )?;
        created_files.push(signals_file);

        // Save verification key
        let vk_file = format!("{}_verification_key.json", base_name);
        fs::write(&vk_file, &proof_package.verification_key)?;
        created_files.push(vk_file);

        // Generate Solidity verifier if requested
        if self.config.generate_solidity_verifier {
            let verifier_contract =
                verifier::generate_solidity_verifier(&proof_package.verification_key)?;
            let verifier_file = format!("{}_verifier.sol", base_name);
            fs::write(&verifier_file, verifier_contract)?;
            created_files.push(verifier_file);

            // Also generate JavaScript verifier for web/Node.js integration
            let js_verifier =
                verifier::generate_javascript_verifier(&proof_package.verification_key)?;
            let js_verifier_file = format!("{}_verifier.js", base_name);
            fs::write(&js_verifier_file, js_verifier)?;
            created_files.push(js_verifier_file);
        }

        Ok(created_files)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AnalysisResults, ResourceUsage};

    #[test]
    fn test_public_signals_generation() {
        let results = AnalysisResults {
            contract_name: "TestContract".to_string(),
            complexity: 15,
            compatibility_issues: vec!["test issue".to_string()],
            security_vulnerabilities: vec![],
            resource_usage: ResourceUsage {
                ref_time: 50000,
                proof_size: 10000,
                storage_deposit: 1000,
                storage_usage: 2000,
            },
            best_practices: vec!["Missing pragma".to_string()],
        };

        let signals = PublicSignals::from_analysis(&results, "polkadot", "1.0.0");

        assert_eq!(signals.network_target, "polkadot");
        assert_eq!(signals.rule_version, "1.0.0");
        assert_eq!(signals.complexity_level, "medium");
        assert_eq!(signals.compatibility_score, 90); // 100 - (1 * 10)
        assert_eq!(signals.security_score, 100); // No vulnerabilities
        assert_eq!(signals.best_practices_score, 95); // 100 - (1 * 5)
    }

    #[tokio::test]
    async fn test_zk_prover_creation() {
        let config = ZkConfig::default();
        let prover = ZkProver::new(config);

        // Test that prover is created successfully
        assert_eq!(prover.config.security_level, 128);
        assert_eq!(prover.config.rule_version, "1.0.0");
    }
}
