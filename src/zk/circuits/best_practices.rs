//! Best practices circuit for code quality validation
//!
//! This circuit validates that best practices analysis was performed correctly
//! and that the contract follows Solidity coding standards.

#[allow(unused_imports)]
use ark_ff::{Field, One, PrimeField, Zero};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;

use super::{bool_to_field, validate_score_range, PolkaGuardCircuit, ZkCircuit};
use crate::models::AnalysisResults;

/// Circuit for best practices validation
#[derive(Clone)]
pub struct BestPracticesCircuit<F: Field + PrimeField> {
    /// Number of best practice violations (private)  
    pub violation_count: Option<F>,
    /// Has proper pragma directive (private)
    pub has_pragma: Option<F>,
    /// Has SPDX license identifier (private)
    pub has_license: Option<F>,
    /// Has proper function visibility (private)
    pub has_visibility: Option<F>,
    /// Has proper documentation (private)
    pub has_natspec: Option<F>,
    /// Best practices score (public)
    pub score: Option<F>,
}

impl<F: Field + PrimeField> BestPracticesCircuit<F> {
    /// Create a new best practices circuit
    pub fn new(
        violation_count: Option<F>,
        has_pragma: Option<F>,
        has_license: Option<F>,
        has_visibility: Option<F>,
        has_natspec: Option<F>,
        score: Option<F>,
    ) -> Self {
        Self {
            violation_count,
            has_pragma,
            has_license,
            has_visibility,
            has_natspec,
            score,
        }
    }

    /// Calculate best practices score
    fn calculate_score(
        &self,
        violation_count: &FpVar<F>,
        has_pragma: &FpVar<F>,
        has_license: &FpVar<F>,
        has_visibility: &FpVar<F>,
        has_natspec: &FpVar<F>,
    ) -> Result<FpVar<F>, SynthesisError> {
        let hundred = FpVar::constant(F::from(100u32));
        let five = FpVar::constant(F::from(5u32)); // Base penalty per violation
        let ten = FpVar::constant(F::from(10u32)); // Penalty for missing core practices
        let fifteen = FpVar::constant(F::from(15u32)); // Penalty for missing pragma
        let zero = FpVar::zero();
        let one = FpVar::one();

        // Base penalty for violations
        let base_penalty = violation_count * &five;

        // Specific penalties for missing practices
        let missing_pragma = &one - has_pragma;
        let pragma_penalty = &missing_pragma * &fifteen;

        let missing_license = &one - has_license;
        let license_penalty = &missing_license * &ten;

        let missing_visibility = &one - has_visibility;
        let visibility_penalty = &missing_visibility * &ten;

        let missing_natspec = &one - has_natspec;
        let natspec_penalty = &missing_natspec * &five;

        let total_penalty = &base_penalty
            + &pragma_penalty
            + &license_penalty
            + &visibility_penalty
            + &natspec_penalty;
        let score = &hundred - &total_penalty;

        // Ensure score >= 0
        let is_negative = score.is_cmp(&zero, std::cmp::Ordering::Less, false)?;
        let final_score = FpVar::conditionally_select(&is_negative, &zero, &score)?;

        Ok(final_score)
    }
}

impl<F: Field + PrimeField> ZkCircuit<F> for BestPracticesCircuit<F> {
    fn generate_constraints(&self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        self.clone().generate_constraints(cs)
    }
}

impl<F: Field + PrimeField> PolkaGuardCircuit<F> for BestPracticesCircuit<F> {
    fn circuit_id(&self) -> &'static str {
        "best_practices"
    }

    fn from_analysis(results: &AnalysisResults, contract_source: &str) -> Self {
        let violation_count = F::from(results.best_practices.len() as u64);

        // Check for specific best practices
        let has_pragma = contract_source.contains("pragma solidity");
        let has_license = contract_source.contains("SPDX-License-Identifier");
        let has_visibility = contract_source.contains("public")
            || contract_source.contains("private")
            || contract_source.contains("internal")
            || contract_source.contains("external");
        let has_natspec = contract_source.contains("///") || contract_source.contains("/**");

        // Calculate score
        let mut score = 100;
        score -= results.best_practices.len() as i32 * 5; // Base penalty
        if !has_pragma {
            score -= 15;
        }
        if !has_license {
            score -= 10;
        }
        if !has_visibility {
            score -= 10;
        }
        if !has_natspec {
            score -= 5;
        }
        score = std::cmp::max(0, score);

        Self::new(
            Some(violation_count),
            Some(bool_to_field(has_pragma)),
            Some(bool_to_field(has_license)),
            Some(bool_to_field(has_visibility)),
            Some(bool_to_field(has_natspec)),
            Some(F::from(score as u64)),
        )
    }

    fn public_inputs(&self) -> Vec<F> {
        vec![self.score.unwrap_or(F::zero())]
    }

    fn constraint_count(&self) -> usize {
        40 // Estimated constraint count for best practices checks
    }
}

impl<F: Field + PrimeField> ConstraintSynthesizer<F> for BestPracticesCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Private inputs
        let violation_count = FpVar::new_witness(cs.clone(), || {
            self.violation_count
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let has_pragma = FpVar::new_witness(cs.clone(), || {
            self.has_pragma.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let has_license = FpVar::new_witness(cs.clone(), || {
            self.has_license.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let has_visibility = FpVar::new_witness(cs.clone(), || {
            self.has_visibility.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let has_natspec = FpVar::new_witness(cs.clone(), || {
            self.has_natspec.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Public input (score)
        let expected_score = FpVar::new_input(cs.clone(), || {
            self.score.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Validate score range
        validate_score_range(cs.clone(), &expected_score)?;

        // Calculate score from private inputs
        let calculated_score = self.calculate_score(
            &violation_count,
            &has_pragma,
            &has_license,
            &has_visibility,
            &has_natspec,
        )?;

        // Constrain that calculated score equals expected score
        calculated_score.enforce_equal(&expected_score)?;

        // Validate boolean constraints
        let zero = FpVar::zero();
        let one = FpVar::one();

        for bool_var in [&has_pragma, &has_license, &has_visibility, &has_natspec] {
            let is_zero = bool_var.is_eq(&zero)?;
            let is_one = bool_var.is_eq(&one)?;
            let is_boolean = is_zero.or(&is_one)?;
            is_boolean.enforce_equal(&Boolean::constant(true))?;
        }

        // Validate violation count is reasonable (< 20)
        let max_violations = FpVar::constant(F::from(20u32));
        violation_count.enforce_cmp(&max_violations, std::cmp::Ordering::Less, true)?;

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
    fn test_best_practices_circuit_creation() {
        let results = AnalysisResults {
            contract_name: "TestContract".to_string(),
            complexity: 15,
            compatibility_issues: vec![],
            security_vulnerabilities: vec![],
            resource_usage: ResourceUsage::default(),
            best_practices: vec![
                "Missing pragma directive".to_string(),
                "Missing license identifier".to_string(),
            ],
        };

        let contract_source = r#"
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;
            contract Test {
                function test() public pure returns (uint256) {
                    return 42;
                }
            }
        "#;

        let circuit = BestPracticesCircuit::<Fr>::from_analysis(&results, contract_source);

        assert_eq!(circuit.violation_count, Some(Fr::from(2u64)));
        assert_eq!(circuit.has_pragma, Some(Fr::one()));
        assert_eq!(circuit.has_license, Some(Fr::one()));
        assert_eq!(circuit.has_visibility, Some(Fr::one()));
        // Score = 100 - (2 * 5) = 90 (no missing practices penalties since they're present)
        assert_eq!(circuit.score, Some(Fr::from(90u64)));
    }

    #[test]
    fn test_best_practices_circuit_constraints() {
        let circuit = BestPracticesCircuit::<Fr>::new(
            Some(Fr::from(0u64)),   // No violations
            Some(Fr::one()),        // Has pragma
            Some(Fr::one()),        // Has license
            Some(Fr::one()),        // Has visibility
            Some(Fr::one()),        // Has natspec
            Some(Fr::from(100u64)), // Perfect score
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        let result = circuit.generate_constraints(cs.clone());

        assert!(result.is_ok());
        assert!(cs.is_satisfied().unwrap());
    }
}
