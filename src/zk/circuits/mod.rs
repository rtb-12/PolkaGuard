//! Circuit definitions for PolkaGuard ZK proofs
//!
//! This module contains the circuit definitions for each type of analysis:
//! - Compatibility circuits (EVM opcode validation)
//! - Security circuits (vulnerability detection)
//! - Resource circuits (usage estimation validation)
//! - Best practices circuits (code quality validation)

pub mod best_practices;
pub mod compatibility;
pub mod resources;
pub mod security;
pub mod exploit;

#[allow(unused_imports)]
use ark_ff::{Field, One, PrimeField, Zero};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::models::AnalysisResults;

/// Master circuit that aggregates all individual circuits
#[derive(Clone)]
pub struct MasterCircuit<F: Field + PrimeField> {
    /// Compatibility circuit instance
    pub compatibility: compatibility::CompatibilityCircuit<F>,
    /// Security circuit instance  
    pub security: security::SecurityCircuit<F>,
    /// Resource circuit instance
    pub resources: resources::ResourceCircuit<F>,
    /// Best practices circuit instance
    pub best_practices: best_practices::BestPracticesCircuit<F>,
    /// Overall score (public input)
    pub overall_score: Option<F>,
}

impl<F: Field + PrimeField> MasterCircuit<F> {
    /// Create master circuit from analysis results
    pub fn from_analysis(results: &AnalysisResults, contract_source: &str) -> Self {
        Self {
            compatibility: compatibility::CompatibilityCircuit::from_analysis(
                results,
                contract_source,
            ),
            security: security::SecurityCircuit::from_analysis(results, contract_source),
            resources: resources::ResourceCircuit::from_analysis(results, contract_source),
            best_practices: best_practices::BestPracticesCircuit::from_analysis(
                results,
                contract_source,
            ),
            overall_score: None,
        }
    }

    /// Set the overall score as public input
    pub fn with_overall_score(mut self, score: F) -> Self {
        self.overall_score = Some(score);
        self
    }
}

impl<F: Field + PrimeField> ConstraintSynthesizer<F> for MasterCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Generate constraints for each sub-circuit
        self.compatibility.generate_constraints(cs.clone())?;
        self.security.generate_constraints(cs.clone())?;
        self.resources.generate_constraints(cs.clone())?;
        self.best_practices.generate_constraints(cs.clone())?;

        // If overall score is provided as public input, validate it
        if let Some(expected_score) = self.overall_score {
            let score_var = FpVar::new_input(cs.clone(), || Ok(expected_score))?;
            validate_score_range(cs.clone(), &score_var)?;
        }

        Ok(())
    }
}

/// Circuit metadata for proof verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitMetadata {
    /// Total number of constraints
    pub constraint_count: usize,
    /// Number of public inputs
    pub public_input_count: usize,
    /// Number of private inputs
    pub private_input_count: usize,
    /// Circuit compilation time
    pub compilation_time_ms: u64,
}

/// Helper function to convert analysis results to field elements
pub fn analysis_to_field_elements<F: Field + PrimeField>(results: &AnalysisResults) -> Vec<F> {
    let mut elements = Vec::new();

    // Convert various metrics to field elements
    elements.push(F::from(results.complexity as u64));
    elements.push(F::from(results.compatibility_issues.len() as u64));
    elements.push(F::from(results.security_vulnerabilities.len() as u64));
    elements.push(F::from(results.best_practices.len() as u64));
    elements.push(F::from(results.resource_usage.ref_time));
    elements.push(F::from(results.resource_usage.proof_size));
    elements.push(F::from(results.resource_usage.storage_usage));

    elements
}

/// Helper function to create boolean field element
pub fn bool_to_field<F: Field + PrimeField>(value: bool) -> F {
    if value {
        F::one()
    } else {
        F::zero()
    }
}

/// Helper function to validate score ranges (0-100)
pub fn validate_score_range<F: Field + PrimeField>(
    _cs: ConstraintSystemRef<F>,
    score: &FpVar<F>,
) -> Result<(), SynthesisError> {
    let zero = FpVar::zero();
    let hundred = FpVar::constant(F::from(100u32));

    // Score >= 0
    score.enforce_cmp(&zero, std::cmp::Ordering::Greater, true)?;
    // Score <= 100
    score.enforce_cmp(&hundred, std::cmp::Ordering::Less, true)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AnalysisResults, ResourceUsage};
    use ark_bn254::Fr;

    #[test]
    fn test_analysis_to_field_elements() {
        let results = AnalysisResults {
            contract_name: "Test".to_string(),
            complexity: 10,
            compatibility_issues: vec!["issue1".to_string()],
            security_vulnerabilities: vec![],
            resource_usage: ResourceUsage {
                ref_time: 1000,
                proof_size: 500,
                storage_deposit: 100,
                storage_usage: 200,
            },
            best_practices: vec!["practice1".to_string()],
        };

        let elements: Vec<Fr> = analysis_to_field_elements(&results);

        assert_eq!(elements.len(), 7);
        assert_eq!(elements[0], Fr::from(10u64)); // complexity
        assert_eq!(elements[1], Fr::from(1u64)); // compatibility issues count
        assert_eq!(elements[2], Fr::from(0u64)); // security vulnerabilities count
        assert_eq!(elements[3], Fr::from(1u64)); // best practices count
    }

    #[test]
    fn test_bool_to_field() {
        assert_eq!(bool_to_field::<Fr>(true), Fr::one());
        assert_eq!(bool_to_field::<Fr>(false), Fr::zero());
    }
}
