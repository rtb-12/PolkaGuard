//! ZK proof generation using Groth16 and Arkworks
//!
//! This module handles the actual generation of zero-knowledge proofs
//! using the Groth16 proving system.

use anyhow::{anyhow, Result};
use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::json;
use std::time::Instant;

use super::witness::Witness;
use super::{circuits::MasterCircuit, ZkConfig};

/// Generate a Groth16 proof from witness data
pub async fn generate_groth16_proof(
    witness: &Witness,
    config: &ZkConfig,
) -> Result<(String, String)> {
    // Estimate resources before proof generation
    let estimate = estimate_proof_resources(witness);
    println!("📊 Proof generation estimates:");
    println!("  Estimated time: {}ms", estimate.estimated_time_ms);
    println!("  Estimated memory: {}MB", estimate.estimated_memory_mb);
    println!("  Constraint count: {}", estimate.constraint_count);
    println!("  Public inputs: {}", estimate.public_input_count);
    println!("  Private inputs: {}", estimate.private_input_count);

    let start_time = Instant::now();

    // Create a deterministic RNG for reproducible proofs (in production, use secure randomness)
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // Create the master circuit with witness data
    let circuit = create_master_circuit_from_witness(witness)?;

    println!("🔄 Generating circuit parameters...");

    // In a real implementation, these would be loaded from trusted setup
    // For demo purposes, we'll simulate the process
    let (proving_key, verifying_key) = simulate_trusted_setup(&mut rng, config).await?;

    println!("🔄 Generating ZK proof...");

    // Generate the proof (simulated for now since we need a complete circuit implementation)
    let proof = simulate_proof_generation(&circuit, &proving_key, &mut rng)?;

    let generation_time = start_time.elapsed();
    println!(
        "✅ Proof generated in {:.2}s",
        generation_time.as_secs_f64()
    );

    // Serialize proof and verification key
    let proof_json = serialize_proof(&proof)?;
    let vk_json = serialize_verification_key(&verifying_key)?;

    Ok((proof_json, vk_json))
}

/// Create master circuit from witness data
fn create_master_circuit_from_witness(witness: &Witness) -> Result<MasterCircuit<Fr>> {
    // Validate witness integrity first
    if !crate::zk::witness::validate_witness_integrity(witness)? {
        return Err(anyhow!("Witness integrity validation failed"));
    }

    // Extract overall score from public inputs
    if witness.public_inputs.len() < 5 {
        return Err(anyhow!("Insufficient public inputs for master circuit"));
    }

    let overall_score_str = &witness.public_inputs[4]; // Overall score is the 5th public input
    let overall_score = overall_score_str.parse::<u64>()
        .map_err(|_| anyhow!("Invalid overall score format: {}", overall_score_str))
        .map(Fr::from)?;

    // Create master circuit from analysis results and set overall score
    let master_circuit = MasterCircuit::from_analysis(&witness.analysis_results, &witness.contract_source)
        .with_overall_score(overall_score);

    // Log metadata for debugging
    println!("📊 Witness metadata:");
    println!("  Contract hash: {}", &witness.metadata.contract_hash[..8]);
    println!("  Timestamp: {}", witness.metadata.timestamp);
    println!("  Analysis hash: {}", &witness.metadata.analysis_hash[..8]);
    for (circuit, size) in &witness.metadata.circuit_sizes {
        println!("  {} circuit: {} private inputs", circuit, size);
    }

    Ok(master_circuit)
}

/// Simulate trusted setup (in production, this would use a real ceremony)
async fn simulate_trusted_setup(
    rng: &mut (impl RngCore + CryptoRng),
    _config: &ZkConfig,
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>)> {
    // In a real implementation, this would:
    // 1. Load parameters from a trusted setup ceremony
    // 2. Verify the setup integrity
    // 3. Return the actual proving and verifying keys

    // For demo purposes, we'll create dummy keys
    // This is NOT secure and should not be used in production

    println!("⚠️  Using simulated trusted setup (NOT SECURE - demo only)");

    // Create dummy circuit for parameter generation
    let dummy_circuit = MasterCircuit::<Fr> {
        compatibility: crate::zk::circuits::compatibility::CompatibilityCircuit::new(
            Some(Fr::from(0u64)),
            Some(Fr::from(0u64)),
            Some(Fr::from(0u64)),
            Some(Fr::from(100u64)),
        ),
        security: crate::zk::circuits::security::SecurityCircuit::new(
            Some(Fr::from(0u64)),
            Some(Fr::from(0u64)),
            Some(Fr::from(0u64)),
            Some(Fr::from(0u64)),
            Some(Fr::from(100u64)),
        ),
        resources: crate::zk::circuits::resources::ResourceCircuit::new(
            Some(Fr::from(1000u64)),
            Some(Fr::from(1000u64)),
            Some(Fr::from(1000u64)),
            Some(Fr::from(100u64)),
        ),
        best_practices: crate::zk::circuits::best_practices::BestPracticesCircuit::new(
            Some(Fr::from(0u64)),
            Some(Fr::from(1u64)),
            Some(Fr::from(1u64)),
            Some(Fr::from(1u64)),
            Some(Fr::from(1u64)),
            Some(Fr::from(100u64)),
        ),
        overall_score: Some(Fr::from(100u64)),
    };

    // Simulate key generation
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(dummy_circuit, rng)
        .map_err(|e| anyhow!("Failed to generate keys: {:?}", e))?;

    Ok((pk, vk))
}

/// Simulate proof generation (in production, this would generate a real proof)
fn simulate_proof_generation(
    _circuit: &MasterCircuit<Fr>,
    _proving_key: &ProvingKey<Bn254>,
    rng: &mut impl RngCore,
) -> Result<Proof<Bn254>> {
    // In a real implementation, this would:
    // 1. Use the actual circuit with witness data
    // 2. Generate a real Groth16 proof
    // 3. Return the proof for verification

    println!("⚠️  Using simulated proof generation (NOT SECURE - demo only)");

    // Create a dummy proof structure
    // This is NOT a real proof and cannot be verified
    use ark_bn254::{G1Projective, G2Projective};
    #[allow(unused_imports)]
    use ark_ec::pairing::Pairing;
    use ark_ec::Group;

    let g1_gen = G1Projective::generator();
    let g2_gen = G2Projective::generator();

    // Generate random group elements (this is not a real proof!)
    let mut scalar_bytes = [0u8; 32];
    rng.fill_bytes(&mut scalar_bytes);

    // Use the correct method from PrimeField trait
    let scalar = Fr::from_le_bytes_mod_order(&scalar_bytes);

    let proof = Proof {
        a: (g1_gen * scalar).into(),
        b: (g2_gen * scalar).into(),
        c: (g1_gen * scalar).into(),
    };

    Ok(proof)
}

/// Serialize proof to JSON
fn serialize_proof(_proof: &Proof<Bn254>) -> Result<String> {
    // In a real implementation, this would properly serialize the proof
    // For demo purposes, we'll create a JSON representation

    let proof_json = json!({
        "type": "groth16",
        "curve": "bn254",
        "a": "simulated_a_value",
        "b": "simulated_b_value",
        "c": "simulated_c_value",
        "note": "This is a simulated proof for demonstration purposes only"
    });

    Ok(serde_json::to_string_pretty(&proof_json)?)
}

/// Serialize verification key to JSON
fn serialize_verification_key(_vk: &VerifyingKey<Bn254>) -> Result<String> {
    // In a real implementation, this would properly serialize the verification key
    // For demo purposes, we'll create a JSON representation

    let vk_json = json!({
        "type": "groth16_verification_key",
        "curve": "bn254",
        "alpha_g1": "simulated_alpha_g1",
        "beta_g2": "simulated_beta_g2",
        "gamma_g2": "simulated_gamma_g2",
        "delta_g2": "simulated_delta_g2",
        "ic": ["simulated_ic_values"],
        "note": "This is a simulated verification key for demonstration purposes only"
    });

    Ok(serde_json::to_string_pretty(&vk_json)?)
}

/// Estimate proof generation time and resources
pub fn estimate_proof_resources(witness: &Witness) -> ProofEstimate {
    let total_constraints = witness
        .private_inputs
        .values()
        .map(|inputs| inputs.len())
        .sum::<usize>()
        * 10; // Rough estimate of constraints per input

    let estimated_time_ms = match total_constraints {
        0..=1000 => 500,
        1001..=5000 => 2000,
        5001..=10000 => 5000,
        _ => 10000,
    };

    let estimated_memory_mb = (total_constraints / 100).max(50); // Rough estimate

    ProofEstimate {
        estimated_time_ms,
        estimated_memory_mb,
        constraint_count: total_constraints,
        public_input_count: witness.public_inputs.len(),
        private_input_count: witness.private_inputs.values().map(|v| v.len()).sum(),
    }
}

/// Proof generation resource estimates
#[derive(Debug, Clone)]
pub struct ProofEstimate {
    pub estimated_time_ms: u64,
    pub estimated_memory_mb: usize,
    pub constraint_count: usize,
    pub public_input_count: usize,
    pub private_input_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::witness::{Witness, WitnessMetadata};
    use std::collections::HashMap;

    #[test]
    fn test_proof_estimation() {
        let mut private_inputs = HashMap::new();
        private_inputs.insert("compatibility".to_string(), vec!["1".to_string(); 5]);
        private_inputs.insert("security".to_string(), vec!["1".to_string(); 7]);

        let witness = Witness {
            private_inputs,
            public_inputs: vec!["100".to_string(); 6],
            analysis_results: crate::models::AnalysisResults::default(),
            contract_source: "contract Test {}".to_string(),
            metadata: WitnessMetadata {
                contract_hash: "test_hash".to_string(),
                timestamp: 1000000000,
                analysis_hash: "analysis_hash".to_string(),
                circuit_sizes: HashMap::new(),
            },
        };

        let estimate = estimate_proof_resources(&witness);

        assert_eq!(estimate.public_input_count, 6);
        assert_eq!(estimate.private_input_count, 12); // 5 + 7
        assert!(estimate.estimated_time_ms > 0);
        assert!(estimate.estimated_memory_mb > 0);
    }

    #[tokio::test]
    async fn test_simulated_trusted_setup() {
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let config = ZkConfig::default();

        let result = simulate_trusted_setup(&mut rng, &config).await;
        assert!(result.is_ok());
    }
}
