//! Security circuit for vulnerability detection validation
//!
//! This circuit validates that security analysis was performed correctly
//! and that the contract has no critical vulnerabilities.

#[allow(unused_imports)]
use ark_ff::{Field, One, PrimeField, Zero};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;

use super::{bool_to_field, validate_score_range, PolkaGuardCircuit, ZkCircuit};
use crate::models::AnalysisResults;

/// Circuit for security vulnerability validation
#[derive(Clone)]
pub struct SecurityCircuit<F: Field + PrimeField> {
    /// Number of security vulnerabilities found (private)
    pub vulnerability_count: Option<F>,
    /// Has reentrancy issues (private)
    pub has_reentrancy: Option<F>,
    /// Has unchecked calls (private)
    pub has_unchecked_calls: Option<F>,
    /// Has access control issues (private)
    pub has_access_control_issues: Option<F>,
    /// Security score (public)
    pub score: Option<F>,
}

impl<F: Field + PrimeField> SecurityCircuit<F> {
    /// Create a new security circuit
    pub fn new(
        vulnerability_count: Option<F>,
        has_reentrancy: Option<F>,
        has_unchecked_calls: Option<F>,
        has_access_control_issues: Option<F>,
        score: Option<F>,
    ) -> Self {
        Self {
            vulnerability_count,
            has_reentrancy,
            has_unchecked_calls,
            has_access_control_issues,
            score,
        }
    }

    /// Calculate security score based on vulnerabilities
    fn calculate_score(
        &self,
        vuln_count: &FpVar<F>,
        has_reentrancy: &FpVar<F>,
        has_unchecked_calls: &FpVar<F>,
        has_access_control: &FpVar<F>,
    ) -> Result<FpVar<F>, SynthesisError> {
        let hundred = FpVar::constant(F::from(100u32));
        let fifteen = FpVar::constant(F::from(15u32)); // Base penalty per vulnerability
        let twenty_five = FpVar::constant(F::from(25u32)); // Reentrancy penalty
        let twenty = FpVar::constant(F::from(20u32)); // Unchecked calls penalty
        let thirty = FpVar::constant(F::from(30u32)); // Access control penalty

        // Base score reduction: vuln_count * 15
        let base_penalty = vuln_count * &fifteen;

        // Additional penalties for specific vulnerability types
        let reentrancy_penalty = has_reentrancy * &twenty_five;
        let unchecked_penalty = has_unchecked_calls * &twenty;
        let access_penalty = has_access_control * &thirty;

        let total_penalty =
            &base_penalty + &reentrancy_penalty + &unchecked_penalty + &access_penalty;
        let score = &hundred - &total_penalty;

        // Ensure score >= 0
        let zero = FpVar::zero();
        let is_negative = score.is_cmp(&zero, std::cmp::Ordering::Less, false)?;
        let final_score = FpVar::conditionally_select(&is_negative, &zero, &score)?;

        Ok(final_score)
    }
}

impl<F: Field + PrimeField> ZkCircuit<F> for SecurityCircuit<F> {
    fn generate_constraints(&self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        self.clone().generate_constraints(cs)
    }
}

impl<F: Field + PrimeField> PolkaGuardCircuit<F> for SecurityCircuit<F> {
    fn circuit_id(&self) -> &'static str {
        "security"
    }

    fn from_analysis(results: &AnalysisResults, contract_source: &str) -> Self {
        let vulnerability_count = F::from(results.security_vulnerabilities.len() as u64);

        // Analyze specific vulnerability types
        let has_reentrancy = results
            .security_vulnerabilities
            .iter()
            .any(|v| v.to_lowercase().contains("reentrancy"));

        let has_unchecked_calls = results
            .security_vulnerabilities
            .iter()
            .any(|v| v.to_lowercase().contains("unchecked"));

        let has_access_control_issues = contract_source.contains("onlyOwner")
            || contract_source.contains("require(msg.sender")
            || results
                .security_vulnerabilities
                .iter()
                .any(|v| v.to_lowercase().contains("access"));

        // Calculate score with penalties
        let mut score = 100;
        score -= results.security_vulnerabilities.len() as i32 * 15;
        if has_reentrancy {
            score -= 25;
        }
        if has_unchecked_calls {
            score -= 20;
        }
        if has_access_control_issues {
            score -= 30;
        }
        score = std::cmp::max(0, score);

        Self::new(
            Some(vulnerability_count),
            Some(bool_to_field(has_reentrancy)),
            Some(bool_to_field(has_unchecked_calls)),
            Some(bool_to_field(has_access_control_issues)),
            Some(F::from(score as u64)),
        )
    }

    fn public_inputs(&self) -> Vec<F> {
        vec![self.score.unwrap_or(F::zero())]
    }

    fn constraint_count(&self) -> usize {
        75 // Estimated constraint count for security checks
    }
}

impl<F: Field + PrimeField> ConstraintSynthesizer<F> for SecurityCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Private inputs
        let vuln_count = FpVar::new_witness(cs.clone(), || {
            self.vulnerability_count
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let has_reentrancy = FpVar::new_witness(cs.clone(), || {
            self.has_reentrancy.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let has_unchecked_calls = FpVar::new_witness(cs.clone(), || {
            self.has_unchecked_calls
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let has_access_control = FpVar::new_witness(cs.clone(), || {
            self.has_access_control_issues
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Public input (score)
        let expected_score = FpVar::new_input(cs.clone(), || {
            self.score.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Validate score range
        validate_score_range(cs.clone(), &expected_score)?;

        // Calculate score from private inputs
        let calculated_score = self.calculate_score(
            &vuln_count,
            &has_reentrancy,
            &has_unchecked_calls,
            &has_access_control,
        )?;

        // Constrain that calculated score equals expected score
        calculated_score.enforce_equal(&expected_score)?;

        // Validate boolean constraints
        let zero = FpVar::zero();
        let one = FpVar::one();

        for bool_var in [&has_reentrancy, &has_unchecked_calls, &has_access_control] {
            let is_zero = bool_var.is_eq(&zero)?;
            let is_one = bool_var.is_eq(&one)?;
            let is_boolean = is_zero.or(&is_one)?;
            is_boolean.enforce_equal(&Boolean::constant(true))?;
        }

        // Validate vulnerability count is reasonable (< 50)
        let max_vulns = FpVar::constant(F::from(50u32));
        vuln_count.enforce_cmp(&max_vulns, std::cmp::Ordering::Less, true)?;

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
    fn test_security_circuit_creation() {
        let results = AnalysisResults {
            contract_name: "TestContract".to_string(),
            complexity: 15,
            compatibility_issues: vec![],
            security_vulnerabilities: vec![
                "Potential reentrancy vulnerability".to_string(),
                "Unchecked send operation".to_string(),
            ],
            resource_usage: ResourceUsage::default(),
            best_practices: vec![],
        };

        let contract_source = "contract Test { function test() { require(msg.sender == owner); } }";
        let circuit = SecurityCircuit::<Fr>::from_analysis(&results, contract_source);

        assert_eq!(circuit.vulnerability_count, Some(Fr::from(2u64)));
        assert_eq!(circuit.has_reentrancy, Some(Fr::one()));
        assert_eq!(circuit.has_unchecked_calls, Some(Fr::one()));
        // Score = 100 - (2 * 15) - 25 - 20 - 30 = 100 - 30 - 75 = -5 -> 0
        assert_eq!(circuit.score, Some(Fr::from(0u64)));
    }

    #[test]
    fn test_security_circuit_constraints() {
        let circuit = SecurityCircuit::<Fr>::new(
            Some(Fr::from(0u64)),   // No vulnerabilities
            Some(Fr::zero()),       // No reentrancy
            Some(Fr::zero()),       // No unchecked calls
            Some(Fr::zero()),       // No access control issues
            Some(Fr::from(100u64)), // Perfect score
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        let result = circuit.generate_constraints(cs.clone());

        assert!(result.is_ok());
        assert!(cs.is_satisfied().unwrap());
    }
}
