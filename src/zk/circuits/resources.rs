//! Resource circuit for resource usage validation
//!
//! This circuit validates that resource estimation was performed correctly
//! and that the contract meets resource efficiency requirements.

#[allow(unused_imports)]
use ark_ff::{Field, One, PrimeField, Zero};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use super::{validate_score_range};
use crate::models::AnalysisResults;

/// Circuit for resource usage validation
#[derive(Clone)]
pub struct ResourceCircuit<F: Field + PrimeField> {
    /// Reference time usage (private)
    pub ref_time: Option<F>,
    /// Proof size (private)
    pub proof_size: Option<F>,
    /// Storage usage (private)
    pub storage_usage: Option<F>,
    /// Resource efficiency score (public)
    pub score: Option<F>,
}

impl<F: Field + PrimeField> ResourceCircuit<F> {
    /// Create a new resource circuit
    pub fn new(
        ref_time: Option<F>,
        proof_size: Option<F>,
        storage_usage: Option<F>,
        score: Option<F>,
    ) -> Self {
        Self {
            ref_time,
            proof_size,
            storage_usage,
            score,
        }
    }

    /// Generate circuit from analysis results
    pub fn from_analysis(results: &AnalysisResults, _contract_source: &str) -> Self {
        let ref_time = F::from(results.resource_usage.ref_time);
        let proof_size = F::from(results.resource_usage.proof_size);
        let storage_usage = F::from(results.resource_usage.storage_usage);

        // Calculate score based on resource usage
        let mut score = 100;

        // Apply penalties for high resource usage
        if results.resource_usage.ref_time > 1_000_000 {
            score -= 20;
        }
        if results.resource_usage.proof_size > 100_000 {
            score -= 15;
        }
        if results.resource_usage.storage_usage > 100_000 {
            score -= 10;
        }

        score = std::cmp::max(0, score);

        Self::new(
            Some(ref_time),
            Some(proof_size),
            Some(storage_usage),
            Some(F::from(score as u64)),
        )
    }

    /// Calculate resource efficiency score
    fn calculate_score(
        &self,
        ref_time: &FpVar<F>,
        proof_size: &FpVar<F>,
        storage_usage: &FpVar<F>,
    ) -> Result<FpVar<F>, SynthesisError> {
        let hundred = FpVar::constant(F::from(100u32));
        let zero = FpVar::zero();

        // Define thresholds for penalties
        let ref_time_threshold = FpVar::constant(F::from(1_000_000u64)); // 1M ref_time units
        let proof_size_threshold = FpVar::constant(F::from(100_000u64)); // 100KB proof size
        let storage_threshold = FpVar::constant(F::from(100_000u64)); // 100KB storage

        // Calculate penalties
        let ref_time_penalty = self.calculate_penalty(ref_time, &ref_time_threshold, 20)?;
        let proof_size_penalty = self.calculate_penalty(proof_size, &proof_size_threshold, 15)?;
        let storage_penalty = self.calculate_penalty(storage_usage, &storage_threshold, 10)?;

        let total_penalty = &ref_time_penalty + &proof_size_penalty + &storage_penalty;
        let score = &hundred - &total_penalty;

        // Ensure score >= 0
        let is_negative = score.is_cmp(&zero, std::cmp::Ordering::Less, false)?;
        let final_score = FpVar::conditionally_select(&is_negative, &zero, &score)?;

        Ok(final_score)
    }

    /// Calculate penalty for a resource metric
    fn calculate_penalty(
        &self,
        value: &FpVar<F>,
        threshold: &FpVar<F>,
        max_penalty: u32,
    ) -> Result<FpVar<F>, SynthesisError> {
        let exceeds_threshold = value.is_cmp(threshold, std::cmp::Ordering::Greater, false)?;
        let penalty = FpVar::constant(F::from(max_penalty));
        let zero = FpVar::zero();

        // If exceeds threshold, apply penalty, otherwise 0
        FpVar::conditionally_select(&exceeds_threshold, &penalty, &zero)
    }
}

impl<F: Field + PrimeField> ConstraintSynthesizer<F> for ResourceCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Private inputs
        let ref_time = FpVar::new_witness(cs.clone(), || {
            self.ref_time.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let proof_size = FpVar::new_witness(cs.clone(), || {
            self.proof_size.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let storage_usage = FpVar::new_witness(cs.clone(), || {
            self.storage_usage.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Public input (score)
        let expected_score = FpVar::new_input(cs.clone(), || {
            self.score.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Validate score range
        validate_score_range(cs.clone(), &expected_score)?;

        // Calculate score from private inputs
        let calculated_score = self.calculate_score(&ref_time, &proof_size, &storage_usage)?;

        // Constrain that calculated score equals expected score
        calculated_score.enforce_equal(&expected_score)?;

        // Validate resource values are reasonable
        let zero = FpVar::zero();

        // ref_time should be positive and < 10M
        ref_time.enforce_cmp(&zero, std::cmp::Ordering::Greater, false)?;
        let max_ref_time = FpVar::constant(F::from(10_000_000u64));
        ref_time.enforce_cmp(&max_ref_time, std::cmp::Ordering::Less, true)?;

        // proof_size should be positive and < 10MB
        proof_size.enforce_cmp(&zero, std::cmp::Ordering::Greater, false)?;
        let max_proof_size = FpVar::constant(F::from(10_000_000u64));
        proof_size.enforce_cmp(&max_proof_size, std::cmp::Ordering::Less, true)?;

        // storage_usage should be non-negative and < 100MB
        let max_storage = FpVar::constant(F::from(100_000_000u64));
        storage_usage.enforce_cmp(&max_storage, std::cmp::Ordering::Less, true)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AnalysisResults, ResourceUsage};
    use ark_bn254::Fr;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_resource_circuit_creation() {
        let results = AnalysisResults {
            contract_name: "TestContract".to_string(),
            complexity: 15,
            compatibility_issues: vec![],
            security_vulnerabilities: vec![],
            resource_usage: ResourceUsage {
                ref_time: 500_000,  // Below threshold
                proof_size: 50_000, // Below threshold
                storage_deposit: 1000,
                storage_usage: 200_000, // Above threshold (100K)
            },
            best_practices: vec![],
        };

        let circuit = ResourceCircuit::<Fr>::from_analysis(&results, "");

        assert_eq!(circuit.ref_time, Some(Fr::from(500_000u64)));
        assert_eq!(circuit.proof_size, Some(Fr::from(50_000u64)));
        assert_eq!(circuit.storage_usage, Some(Fr::from(200_000u64)));
        assert_eq!(circuit.score, Some(Fr::from(90u64))); // 100 - 10 (storage penalty)
    }

    #[test]
    fn test_resource_circuit_constraints() {
        let circuit = ResourceCircuit::<Fr>::new(
            Some(Fr::from(50_000u64)), // Low ref_time
            Some(Fr::from(10_000u64)), // Low proof_size
            Some(Fr::from(5_000u64)),  // Low storage
            Some(Fr::from(100u64)),    // Perfect score
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        let result = circuit.generate_constraints(cs.clone());

        assert!(result.is_ok());
        assert!(cs.is_satisfied().unwrap());
    }
}
