//! Compatibility circuit for PolkaVM compatibility validation
//!
//! This circuit validates that a contract is compatible with PolkaVM
//! by checking for unsupported opcodes and constructs.

#[allow(unused_imports)]
use ark_ff::{Field, One, PrimeField, Zero};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;

use super::{bool_to_field, validate_score_range, PolkaGuardCircuit, ZkCircuit};
use crate::models::AnalysisResults;

/// Circuit for PolkaVM compatibility validation
#[derive(Clone)]
pub struct CompatibilityCircuit<F: Field + PrimeField> {
    /// Number of compatibility issues (private)
    pub issue_count: Option<F>,
    /// Contract complexity (private)
    pub complexity: Option<F>,
    /// Has unsupported opcodes (private)
    pub has_unsupported_opcodes: Option<F>,
    /// Compatibility score (public)
    pub score: Option<F>,
}

impl<F: Field + PrimeField> CompatibilityCircuit<F> {
    /// Create a new compatibility circuit
    pub fn new(
        issue_count: Option<F>,
        complexity: Option<F>,
        has_unsupported_opcodes: Option<F>,
        score: Option<F>,
    ) -> Self {
        Self {
            issue_count,
            complexity,
            has_unsupported_opcodes,
            score,
        }
    }

    /// Calculate compatibility score based on issues
    fn calculate_score(&self, issue_count: &FpVar<F>) -> Result<FpVar<F>, SynthesisError> {
        let hundred = FpVar::constant(F::from(100u32));
        let ten = FpVar::constant(F::from(10u32));

        // Score = 100 - (issue_count * 10), minimum 0
        let penalty = issue_count * &ten;
        let score = &hundred - &penalty;

        // Ensure score >= 0
        let zero = FpVar::zero();
        let is_negative = score.is_cmp(&zero, std::cmp::Ordering::Less, false)?;

        // If negative, set to 0, otherwise keep the score
        let final_score = FpVar::conditionally_select(&is_negative, &zero, &score)?;

        Ok(final_score)
    }
}

impl<F: Field + PrimeField> ZkCircuit<F> for CompatibilityCircuit<F> {
    fn generate_constraints(&self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Clone self and call the ConstraintSynthesizer implementation
        self.clone().generate_constraints(cs)
    }
}

impl<F: Field + PrimeField> PolkaGuardCircuit<F> for CompatibilityCircuit<F> {
    fn circuit_id(&self) -> &'static str {
        "compatibility"
    }

    fn from_analysis(results: &AnalysisResults, contract_source: &str) -> Self {
        let issue_count = F::from(results.compatibility_issues.len() as u64);
        let complexity = F::from(results.complexity as u64);

        // Check for specific unsupported opcodes
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

        // Calculate score: 100 - (issue_count * 10), minimum 0
        let score = std::cmp::max(0, 100 - (results.compatibility_issues.len() as i32 * 10)) as u64;

        Self::new(
            Some(issue_count),
            Some(complexity),
            Some(bool_to_field(has_unsupported)),
            Some(F::from(score)),
        )
    }

    fn public_inputs(&self) -> Vec<F> {
        vec![self.score.unwrap_or(F::zero())]
    }

    fn constraint_count(&self) -> usize {
        50 // Estimated constraint count for compatibility checks
    }
}

impl<F: Field + PrimeField> ConstraintSynthesizer<F> for CompatibilityCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Private inputs
        let issue_count = FpVar::new_witness(cs.clone(), || {
            self.issue_count.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let complexity = FpVar::new_witness(cs.clone(), || {
            self.complexity.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let has_unsupported = FpVar::new_witness(cs.clone(), || {
            self.has_unsupported_opcodes
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Public input (score)
        let expected_score = FpVar::new_input(cs.clone(), || {
            self.score.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Validate score range
        validate_score_range(cs.clone(), &expected_score)?;

        // Calculate score from private inputs
        let calculated_score = self.calculate_score(&issue_count)?;

        // Additional penalty for unsupported opcodes
        let twenty = FpVar::constant(F::from(20u32));
        let opcode_penalty = &has_unsupported * &twenty;
        let final_score = &calculated_score - &opcode_penalty;

        // Ensure final score >= 0
        let zero = FpVar::zero();
        let is_negative = final_score.is_cmp(&zero, std::cmp::Ordering::Less, false)?;
        let constrained_score = FpVar::conditionally_select(&is_negative, &zero, &final_score)?;

        // Constrain that calculated score equals expected score
        constrained_score.enforce_equal(&expected_score)?;

        // Ensure issue count is reasonable (< 100)
        let max_issues = FpVar::constant(F::from(100u32));
        issue_count.enforce_cmp(&max_issues, std::cmp::Ordering::Less, true)?;

        // Ensure complexity is reasonable (< 1000)
        let max_complexity = FpVar::constant(F::from(1000u32));
        complexity.enforce_cmp(&max_complexity, std::cmp::Ordering::Less, true)?;

        // Ensure has_unsupported is boolean (0 or 1)
        let one = FpVar::one();
        let is_zero = has_unsupported.is_eq(&zero)?;
        let is_one = has_unsupported.is_eq(&one)?;
        let is_boolean = is_zero.or(&is_one)?;
        is_boolean.enforce_equal(&Boolean::constant(true))?;

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
    fn test_compatibility_circuit_creation() {
        let results = AnalysisResults {
            contract_name: "TestContract".to_string(),
            complexity: 15,
            compatibility_issues: vec!["Issue 1".to_string(), "Issue 2".to_string()],
            security_vulnerabilities: vec![],
            resource_usage: ResourceUsage::default(),
            best_practices: vec![],
        };

        let contract_source = "contract Test { function test() { selfdestruct(msg.sender); } }";
        let circuit = CompatibilityCircuit::<Fr>::from_analysis(&results, contract_source);

        assert_eq!(circuit.issue_count, Some(Fr::from(2u64)));
        assert_eq!(circuit.complexity, Some(Fr::from(15u64)));
        assert_eq!(circuit.has_unsupported_opcodes, Some(Fr::one())); // has selfdestruct
        assert_eq!(circuit.score, Some(Fr::from(80u64))); // 100 - (2 * 10)
    }

    #[test]
    fn test_compatibility_circuit_constraints() {
        let circuit = CompatibilityCircuit::<Fr>::new(
            Some(Fr::from(1u64)),  // 1 issue
            Some(Fr::from(10u64)), // complexity 10
            Some(Fr::zero()),      // no unsupported opcodes
            Some(Fr::from(90u64)), // expected score: 100 - (1 * 10) = 90
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        let result = circuit.generate_constraints(cs.clone());

        assert!(result.is_ok());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_public_inputs() {
        let circuit = CompatibilityCircuit::<Fr>::new(
            Some(Fr::from(2u64)),
            Some(Fr::from(5u64)),
            Some(Fr::zero()),
            Some(Fr::from(80u64)),
        );

        let public_inputs = circuit.public_inputs();
        assert_eq!(public_inputs.len(), 1);
        assert_eq!(public_inputs[0], Fr::from(80u64));
    }
}
