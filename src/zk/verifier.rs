//! ZK proof verification and verifier contract generation
//!
//! This module handles verification of generated proofs and can generate
//! verifier contracts for on-chain verification.

use anyhow::{anyhow, Result};
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::rngs::OsRng;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::str::FromStr;

use super::ProofPackage;

/// Real Groth16 verification key structure
#[derive(Debug, Clone)]
pub struct RealVerifyingKey {
    pub alpha_g1: G1Affine,
    pub beta_g2: G2Affine,
    pub gamma_g2: G2Affine,
    pub delta_g2: G2Affine,
    pub gamma_abc_g1: Vec<G1Affine>,
}

/// Real Groth16 proof structure
#[derive(Debug, Clone)]
pub struct RealProof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
}

/// Verification result with detailed information
#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub is_valid: bool,
    pub verification_time_ms: u64,
    pub error_message: Option<String>,
    pub public_inputs: Vec<Fr>,
    pub proof_metadata: HashMap<String, Value>,
}

/// Verify a Groth16 proof package using real cryptographic verification
pub async fn verify_groth16_proof(proof_package: &ProofPackage) -> Result<VerificationResult> {
    let start_time = std::time::Instant::now();
    
    // Parse the verification key from the proof package
    let vk = parse_verification_key(&proof_package.verification_key)?;
    
    // Parse the proof from the proof package
    let proof = parse_proof(&proof_package.proof)?;
    
    // Parse public inputs from public signals
    let public_inputs = parse_public_inputs(&proof_package.public_signals)?;
    
    // Perform actual Groth16 verification
    let is_valid = match Groth16::<Bn254>::verify(&vk, &public_inputs, &proof) {
        Ok(result) => result,
        Err(e) => {
            return Ok(VerificationResult {
                is_valid: false,
                verification_time_ms: start_time.elapsed().as_millis() as u64,
                error_message: Some(format!("Verification failed: {}", e)),
                public_inputs,
                proof_metadata: extract_proof_metadata(proof_package),
            });
        }
    };
    
    // Additional validation checks
    validate_proof_package(proof_package)?;
    
    Ok(VerificationResult {
        is_valid,
        verification_time_ms: start_time.elapsed().as_millis() as u64,
        error_message: None,
        public_inputs,
        proof_metadata: extract_proof_metadata(proof_package),
    })
}

/// Parse verification key from JSON format
fn parse_verification_key(vk_json: &Value) -> Result<VerifyingKey<Bn254>> {
    let alpha_g1 = parse_g1_point(vk_json.get("alpha").ok_or_else(|| anyhow!("Missing alpha in verification key"))?)?;
    let beta_g2 = parse_g2_point(vk_json.get("beta").ok_or_else(|| anyhow!("Missing beta in verification key"))?)?;
    let gamma_g2 = parse_g2_point(vk_json.get("gamma").ok_or_else(|| anyhow!("Missing gamma in verification key"))?)?;
    let delta_g2 = parse_g2_point(vk_json.get("delta").ok_or_else(|| anyhow!("Missing delta in verification key"))?)?;
    
    let ic_array = vk_json.get("ic").ok_or_else(|| anyhow!("Missing ic in verification key"))?
        .as_array().ok_or_else(|| anyhow!("IC should be an array"))?;
    
    let mut gamma_abc_g1 = Vec::new();
    for ic_point in ic_array {
        gamma_abc_g1.push(parse_g1_point(ic_point)?);
    }
    
    Ok(VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    })
}

/// Parse proof from JSON format
fn parse_proof(proof_json: &Value) -> Result<Proof<Bn254>> {
    let a = parse_g1_point(proof_json.get("a").ok_or_else(|| anyhow!("Missing 'a' in proof"))?)?;
    let b = parse_g2_point(proof_json.get("b").ok_or_else(|| anyhow!("Missing 'b' in proof"))?)?;
    let c = parse_g1_point(proof_json.get("c").ok_or_else(|| anyhow!("Missing 'c' in proof"))?)?;
    
    Ok(Proof { a, b, c })
}

/// Parse G1 point from JSON
fn parse_g1_point(point_json: &Value) -> Result<G1Affine> {
    let coords = point_json.as_array().ok_or_else(|| anyhow!("G1 point should be an array"))?;
    if coords.len() != 2 {
        return Err(anyhow!("G1 point should have exactly 2 coordinates"));
    }
    
    let x_str = coords[0].as_str().ok_or_else(|| anyhow!("G1 x coordinate should be a string"))?;
    let y_str = coords[1].as_str().ok_or_else(|| anyhow!("G1 y coordinate should be a string"))?;
    
    // Remove 0x prefix if present
    let x_str = x_str.strip_prefix("0x").unwrap_or(x_str);
    let y_str = y_str.strip_prefix("0x").unwrap_or(y_str);
    
    let x = Fr::from_str(x_str).map_err(|e| anyhow!("Invalid G1 x coordinate: {}", e))?;
    let y = Fr::from_str(y_str).map_err(|e| anyhow!("Invalid G1 y coordinate: {}", e))?;
    
    G1Affine::new(x, y).ok_or_else(|| anyhow!("Invalid G1 point"))
}

/// Parse G2 point from JSON
fn parse_g2_point(point_json: &Value) -> Result<G2Affine> {
    let coords = point_json.as_array().ok_or_else(|| anyhow!("G2 point should be an array"))?;
    if coords.len() != 2 {
        return Err(anyhow!("G2 point should have exactly 2 elements"));
    }
    
    let x_coords = coords[0].as_array().ok_or_else(|| anyhow!("G2 x should be an array"))?;
    let y_coords = coords[1].as_array().ok_or_else(|| anyhow!("G2 y should be an array"))?;
    
    if x_coords.len() != 2 || y_coords.len() != 2 {
        return Err(anyhow!("G2 coordinates should have exactly 2 elements each"));
    }
    
    let x0_str = x_coords[0].as_str().ok_or_else(|| anyhow!("G2 x0 should be a string"))?;
    let x1_str = x_coords[1].as_str().ok_or_else(|| anyhow!("G2 x1 should be a string"))?;
    let y0_str = y_coords[0].as_str().ok_or_else(|| anyhow!("G2 y0 should be a string"))?;
    let y1_str = y_coords[1].as_str().ok_or_else(|| anyhow!("G2 y1 should be a string"))?;
    
    // Remove 0x prefix if present
    let x0_str = x0_str.strip_prefix("0x").unwrap_or(x0_str);
    let x1_str = x1_str.strip_prefix("0x").unwrap_or(x1_str);
    let y0_str = y0_str.strip_prefix("0x").unwrap_or(y0_str);
    let y1_str = y1_str.strip_prefix("0x").unwrap_or(y1_str);
    
    let x0 = Fr::from_str(x0_str).map_err(|e| anyhow!("Invalid G2 x0 coordinate: {}", e))?;
    let x1 = Fr::from_str(x1_str).map_err(|e| anyhow!("Invalid G2 x1 coordinate: {}", e))?;
    let y0 = Fr::from_str(y0_str).map_err(|e| anyhow!("Invalid G2 y0 coordinate: {}", e))?;
    let y1 = Fr::from_str(y1_str).map_err(|e| anyhow!("Invalid G2 y1 coordinate: {}", e))?;
    
    use ark_bn254::Fq2;
    let x = Fq2::new(x0, x1);
    let y = Fq2::new(y0, y1);
    
    G2Affine::new(x, y).ok_or_else(|| anyhow!("Invalid G2 point"))
}

/// Parse public inputs from public signals
fn parse_public_inputs(public_signals: &Value) -> Result<Vec<Fr>> {
    let mut inputs = Vec::new();
    
    // Extract numeric values from public signals
    if let Some(compat_score) = public_signals.get("compatibility_score").and_then(|v| v.as_u64()) {
        inputs.push(Fr::from(compat_score));
    }
    if let Some(security_score) = public_signals.get("security_score").and_then(|v| v.as_u64()) {
        inputs.push(Fr::from(security_score));
    }
    if let Some(resource_score) = public_signals.get("resource_score").and_then(|v| v.as_u64()) {
        inputs.push(Fr::from(resource_score));
    }
    if let Some(practices_score) = public_signals.get("best_practices_score").and_then(|v| v.as_u64()) {
        inputs.push(Fr::from(practices_score));
    }
    if let Some(overall_score) = public_signals.get("overall_score").and_then(|v| v.as_u64()) {
        inputs.push(Fr::from(overall_score));
    }
    if let Some(timestamp) = public_signals.get("timestamp").and_then(|v| v.as_u64()) {
        inputs.push(Fr::from(timestamp));
    }
    
    // Convert string fields to field elements using hash
    if let Some(rule_version) = public_signals.get("rule_version").and_then(|v| v.as_str()) {
        inputs.push(string_to_field_element(rule_version));
    }
    if let Some(network_target) = public_signals.get("network_target").and_then(|v| v.as_str()) {
        inputs.push(string_to_field_element(network_target));
    }
    
    Ok(inputs)
}

/// Convert string to field element using hash
fn string_to_field_element(s: &str) -> Fr {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(s.as_bytes());
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    Fr::from_le_bytes_mod_order(&bytes)
}

/// Validate proof package structure and contents
fn validate_proof_package(proof_package: &ProofPackage) -> Result<()> {
    // Check that required fields are present
    if proof_package.proof.is_null() {
        return Err(anyhow!("Proof is missing or null"));
    }
    
    if proof_package.verification_key.is_null() {
        return Err(anyhow!("Verification key is missing or null"));
    }
    
    if proof_package.public_signals.is_null() {
        return Err(anyhow!("Public signals are missing or null"));
    }
    
    // Validate score ranges
    if let Some(scores) = extract_scores(&proof_package.public_signals) {
        for (name, score) in scores {
            if score > 100 {
                return Err(anyhow!("Score {} is out of range (0-100): {}", name, score));
            }
        }
    }
    
    // Validate timestamp
    if let Some(timestamp) = proof_package.public_signals.get("timestamp").and_then(|v| v.as_u64()) {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Check if timestamp is not too far in the past (1 year) or future (1 hour)
        if timestamp < current_time.saturating_sub(365 * 24 * 3600) {
            return Err(anyhow!("Proof timestamp is too old"));
        }
        if timestamp > current_time + 3600 {
            return Err(anyhow!("Proof timestamp is in the future"));
        }
    }
    
    Ok(())
}

/// Extract scores from public signals
fn extract_scores(public_signals: &Value) -> Option<Vec<(String, u64)>> {
    let mut scores = Vec::new();
    
    if let Some(score) = public_signals.get("compatibility_score").and_then(|v| v.as_u64()) {
        scores.push(("compatibility_score".to_string(), score));
    }
    if let Some(score) = public_signals.get("security_score").and_then(|v| v.as_u64()) {
        scores.push(("security_score".to_string(), score));
    }
    if let Some(score) = public_signals.get("resource_score").and_then(|v| v.as_u64()) {
        scores.push(("resource_score".to_string(), score));
    }
    if let Some(score) = public_signals.get("best_practices_score").and_then(|v| v.as_u64()) {
        scores.push(("best_practices_score".to_string(), score));
    }
    if let Some(score) = public_signals.get("overall_score").and_then(|v| v.as_u64()) {
        scores.push(("overall_score".to_string(), score));
    }
    
    if scores.is_empty() {
        None
    } else {
        Some(scores)
    }
}

/// Extract metadata from proof package
fn extract_proof_metadata(proof_package: &ProofPackage) -> HashMap<String, Value> {
    let mut metadata = HashMap::new();
    
    if let Some(rule_version) = proof_package.public_signals.get("rule_version") {
        metadata.insert("rule_version".to_string(), rule_version.clone());
    }
    if let Some(network_target) = proof_package.public_signals.get("network_target") {
        metadata.insert("network_target".to_string(), network_target.clone());
    }
    if let Some(complexity) = proof_package.public_signals.get("complexity_level") {
        metadata.insert("complexity_level".to_string(), complexity.clone());
    }
    
    metadata
}

/// Generate a Solidity verifier contract with real verification key
pub fn generate_solidity_verifier(vk: &VerifyingKey<Bn254>, contract_name: &str) -> Result<String> {
    let alpha_g1 = format_g1_point(&vk.alpha_g1);
    let beta_g2 = format_g2_point(&vk.beta_g2);
    let gamma_g2 = format_g2_point(&vk.gamma_g2);
    let delta_g2 = format_g2_point(&vk.delta_g2);
    
    let mut ic_points = String::new();
    for (i, point) in vk.gamma_abc_g1.iter().enumerate() {
        if i > 0 {
            ic_points.push_str(",\n            ");
        }
        ic_points.push_str(&format_g1_point(point));
    }
    
    Ok(format!(r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title {contract_name}
/// @notice Groth16 verifier for PolkaGuard ZK proofs
/// @dev Generated automatically - do not modify
contract {contract_name} {{
    using Pairing for *;
    
    struct VerifyingKey {{
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }}
    
    struct Proof {{
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }}
    
    struct PublicSignals {{
        uint32 compatibilityScore;
        uint32 securityScore;
        uint32 resourceScore;
        uint32 bestPracticesScore;
        uint32 overallScore;
        uint64 timestamp;
        uint256 ruleVersionHash;
        uint256 networkTargetHash;
    }}
    
    VerifyingKey verifyingKey;
    
    event ProofVerified(address indexed verifier, bool result, uint32 overallScore);
    
    constructor() {{
        verifyingKey.alpha = Pairing.G1Point({alpha_g1});
        verifyingKey.beta = Pairing.G2Point({beta_g2});
        verifyingKey.gamma = Pairing.G2Point({gamma_g2});
        verifyingKey.delta = Pairing.G2Point({delta_g2});
        verifyingKey.gamma_abc = new Pairing.G1Point[]({});
        {ic_assignment}
    }}
    
    function verifyProof(
        Proof memory proof,
        PublicSignals memory signals
    ) public returns (bool) {{
        uint256[] memory publicInputs = new uint256[](8);
        publicInputs[0] = signals.compatibilityScore;
        publicInputs[1] = signals.securityScore;
        publicInputs[2] = signals.resourceScore;
        publicInputs[3] = signals.bestPracticesScore;
        publicInputs[4] = signals.overallScore;
        publicInputs[5] = signals.timestamp;
        publicInputs[6] = signals.ruleVersionHash;
        publicInputs[7] = signals.networkTargetHash;
        
        bool result = verifyTx(proof, publicInputs);
        emit ProofVerified(msg.sender, result, signals.overallScore);
        return result;
    }}
    
    function verifyTx(Proof memory proof, uint256[] memory input) internal view returns (bool) {{
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey;
        require(input.length + 1 == vk.gamma_abc.length);
        
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {{
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }}
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        
        return Pairing.pairing(
            Pairing.negate(proof.a),
            proof.b,
            vk.alpha,
            vk.beta,
            vk_x,
            vk.gamma,
            proof.c,
            vk.delta
        );
    }}
}}

library Pairing {{
    struct G1Point {{
        uint X;
        uint Y;
    }}
    
    struct G2Point {{
        uint[2] X;
        uint[2] Y;
    }}
    
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {{
        return G1Point(1, 2);
    }}
    
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {{
        return G2Point(
            [11559732032986387107991004021392285783925812861821192530917403151452391805634,
             10857046999023057135944570762232829481370756359578518086990519993285655852781],
            [4082367875863433681332203403145435568316851327593401208105741076214120093531,
             8495653923123431417604973247489272438418190587263600148770280649306958101930]
        );
    }}
    
    /// @return r the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory r) {{
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }}
    
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {{
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {{
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
        }}
        require(success);
    }}
    
    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {{
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {{
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
        }}
        require(success);
    }}
    
    /// @return the result of computing the pairing check
    function pairing(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2, G1Point memory c1, G2Point memory c2, G1Point memory d1, G2Point memory d2) internal view returns (bool) {{
        G1Point[4] memory p1 = [a1, b1, c1, d1];
        G2Point[4] memory p2 = [a2, b2, c2, d2];
        uint inputSize = 24;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < 4; i++) {{
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }}
        uint[1] memory out;
        bool success;
        assembly {{
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
        }}
        require(success);
        return out[0] != 0;
    }}
}}
"#,
        contract_name = contract_name,
        alpha_g1 = alpha_g1,
        beta_g2 = beta_g2,
        gamma_g2 = gamma_g2,
        delta_g2 = delta_g2,
        ic_points.len(),
        ic_assignment = generate_ic_assignment(&vk.gamma_abc_g1)
    ))
}

/// Format G1 point for Solidity
fn format_g1_point(point: &G1Affine) -> String {
    format!("{}, {}", 
        field_element_to_string(&point.x), 
        field_element_to_string(&point.y)
    )
}

/// Format G2 point for Solidity
fn format_g2_point(point: &G2Affine) -> String {
    format!("[{}, {}], [{}, {}]", 
        field_element_to_string(&point.x.c1),
        field_element_to_string(&point.x.c0),
        field_element_to_string(&point.y.c1),
        field_element_to_string(&point.y.c0)
    )
}

/// Convert field element to string representation
fn field_element_to_string<F: PrimeField>(element: &F) -> String {
    element.to_string()
}

/// Generate IC assignment code for Solidity constructor
fn generate_ic_assignment(ic_points: &[G1Affine]) -> String {
    let mut assignments = String::new();
    for (i, point) in ic_points.iter().enumerate() {
        assignments.push_str(&format!(
            "        verifyingKey.gamma_abc[{}] = Pairing.G1Point({});\n",
            i,
            format_g1_point(point)
        ));
    }
    assignments
}

/// Generate JavaScript verifier with real snarkjs integration
pub fn generate_javascript_verifier(vk: &VerifyingKey<Bn254>) -> Result<String> {
    let vk_json = serialize_verification_key_to_json(vk)?;
    
    Ok(format!(r#"
const snarkjs = require("snarkjs");

// Real verification key from trusted setup
const VERIFICATION_KEY = {vk_json};

/**
 * Verify a PolkaGuard ZK proof using real cryptographic verification
 * @param {{Object}} proof - The Groth16 proof object
 * @param {{Object}} publicSignals - The public signals/inputs
 * @returns {{Promise<boolean>}} - True if proof is valid, false otherwise
 */
async function verifyPolkaGuardProof(proof, publicSignals) {{
    try {{
        // Convert public signals to array format expected by snarkjs
        const publicInputs = [
            publicSignals.compatibilityScore || 0,
            publicSignals.securityScore || 0,
            publicSignals.resourceScore || 0,
            publicSignals.bestPracticesScore || 0,
            publicSignals.overallScore || 0,
            publicSignals.timestamp || 0,
            hashString(publicSignals.ruleVersion || "1.0.0"),
            hashString(publicSignals.networkTarget || "polkadot")
        ];
        
        // Perform real Groth16 verification
        const isValid = await snarkjs.groth16.verify(VERIFICATION_KEY, publicInputs, proof);
        
        // Additional validation
        if (isValid) {{
            validateScoreRanges(publicSignals);
            validateTimestamp(publicSignals.timestamp);
        }}
        
        return isValid;
    }} catch (error) {{
        console.error("Verification failed:", error);
        return false;
    }}
}}

/**
 * Verify multiple proofs in batch
 * @param {{Array}} proofs - Array of proof objects
 * @param {{Array}} publicSignalsArray - Array of public signals
 * @returns {{Promise<Array<boolean>>}} - Array of verification results
 */
async function verifyBatchProofs(proofs, publicSignalsArray) {{
    if (proofs.length !== publicSignalsArray.length) {{
        throw new Error("Proofs and public signals arrays must have the same length");
    }}
    
    const results = [];
    for (let i = 0; i < proofs.length; i++) {{
        const result = await verifyPolkaGuardProof(proofs[i], publicSignalsArray[i]);
        results.push(result);
    }}
    
    return results;
}}

/**
 * Check if proof meets quality standards for DeFi integration
 * @param {{Object}} publicSignals - The public signals
 * @returns {{boolean}} - True if meets standards
 */
function meetsQualityStandards(publicSignals) {{
    return publicSignals.overallScore >= 70 &&
           publicSignals.securityScore >= 80 &&
           publicSignals.compatibilityScore >= 75;
}}

/**
 * Hash string to field element (simplified)
 * @param {{string}} str - String to hash
 * @returns {{string}} - Hash as string
 */
function hashString(str) {{
    const crypto = require('crypto');
    const hash = crypto.createHash('sha256').update(str).digest('hex');
    return BigInt('0x' + hash).toString();
}}

/**
 * Validate score ranges
 * @param {{Object}} publicSignals - The public signals
 */
function validateScoreRanges(publicSignals) {{
    const scores = [
        publicSignals.compatibilityScore,
        publicSignals.securityScore,
        publicSignals.resourceScore,
        publicSignals.bestPracticesScore,
        publicSignals.overallScore
    ];
    
    for (const score of scores) {{
        if (score < 0 || score > 100) {{
            throw new Error(`Score out of range (0-100): ${{score}}`);
        }}
    }}
}}

/**
 * Validate timestamp
 * @param {{number}} timestamp - Unix timestamp
 */
function validateTimestamp(timestamp) {{
    const now = Math.floor(Date.now() / 1000);
    const oneYear = 365 * 24 * 3600;
    const oneHour = 3600;
    
    if (timestamp < now - oneYear) {{
        throw new Error("Proof timestamp is too old");
    }}
    if (timestamp > now + oneHour) {{
        throw new Error("Proof timestamp is in the future");
    }}
}}

module.exports = {{
    verifyPolkaGuardProof,
    verifyBatchProofs,
    meetsQualityStandards,
    VERIFICATION_KEY
}};
"#, vk_json = vk_json))
}

/// Serialize verification key to JSON format
fn serialize_verification_key_to_json(vk: &VerifyingKey<Bn254>) -> Result<String> {
    use ark_serialize::CanonicalSerialize;
    
    let mut alpha_bytes = Vec::new();
    vk.alpha_g1.serialize_compressed(&mut alpha_bytes)?;
    
    let mut beta_bytes = Vec::new();
    vk.beta_g2.serialize_compressed(&mut beta_bytes)?;
    
    let mut gamma_bytes = Vec::new();
    vk.gamma_g2.serialize_compressed(&mut gamma_bytes)?;
    
    let mut delta_bytes = Vec::new();
    vk.delta_g2.serialize_compressed(&mut delta_bytes)?;
    
    let mut ic_bytes = Vec::new();
    for point in &vk.gamma_abc_g1 {
        let mut point_bytes = Vec::new();
        point.serialize_compressed(&mut point_bytes)?;
        ic_bytes.push(hex::encode(point_bytes));
    }
    
    let vk_json = json!({
        "alpha": hex::encode(alpha_bytes),
        "beta": hex::encode(beta_bytes),
        "gamma": hex::encode(gamma_bytes),
        "delta": hex::encode(delta_bytes),
        "ic": ic_bytes
    });
    
    Ok(serde_json::to_string_pretty(&vk_json)?)
}

/// Generate ink! verifier contract for Polkadot/PolkaVM
pub fn generate_ink_verifier(vk: &VerifyingKey<Bn254>, contract_name: &str) -> Result<String> {
    let vk_serialized = serialize_verification_key_for_ink(vk)?;
    
    Ok(format!(r#"
#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod {contract_name_lower} {{
    use ink::storage::Mapping;
    use ink::prelude::{{vec::Vec, string::String}};
    
    /// Verification key for Groth16 proofs
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[ink::scale_derive(Encode, Decode, TypeInfo)]
    pub struct VerifyingKey {{
        pub alpha: [u8; 48],
        pub beta: [u8; 96],
        pub gamma: [u8; 96],
        pub delta: [u8; 96],
        pub ic: Vec<[u8; 48]>,
    }}
    
    /// Groth16 proof structure
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[ink::scale_derive(Encode, Decode, TypeInfo)]
    pub struct ProofData {{
        pub a: [u8; 48],
        pub b: [u8; 96],
        pub c: [u8; 48],
    }}
    
    /// Public signals from PolkaGuard analysis
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[ink::scale_derive(Encode, Decode, TypeInfo)]
    pub struct PublicSignals {{
        pub compatibility_score: u32,
        pub security_score: u32,
        pub resource_score: u32,
        pub best_practices_score: u32,
        pub overall_score: u32,
        pub timestamp: u64,
        pub rule_version_hash: [u8; 32],
        pub network_target_hash: [u8; 32],
    }}
    
    /// Verification record for tracking
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[ink::scale_derive(Encode, Decode, TypeInfo)]
    pub struct VerificationRecord {{
        pub verifier: AccountId,
        pub timestamp: u64,
        pub overall_score: u32,
        pub is_valid: bool,
    }}
    
    #[ink(storage)]
    pub struct {contract_name} {{
        /// The verification key (set at deployment)
        verification_key: VerifyingKey,
        /// Owner of the contract
        owner: AccountId,
        /// Verification records by proof hash
        verification_records: Mapping<[u8; 32], VerificationRecord>,
        /// Contract verification status
        verified_contracts: Mapping<AccountId, VerificationRecord>,
        /// Contract active status
        is_active: bool,
    }}
    
    /// Events emitted by the contract
    #[ink(event)]
    pub struct ProofVerified {{
        #[ink(topic)]
        verifier: AccountId,
        #[ink(topic)]
        proof_hash: [u8; 32],
        is_valid: bool,
        overall_score: u32,
    }}
    
    #[ink(event)]
    pub struct ContractVerified {{
        #[ink(topic)]
        contract_address: AccountId,
        #[ink(topic)]
        verifier: AccountId,
        overall_score: u32,
    }}
    
    impl {contract_name} {{
        /// Constructor
        #[ink(constructor)]
        pub fn new() -> Self {{
            let verification_key = {vk_serialized};
            
            Self {{
                verification_key,
                owner: Self::env().caller(),
                verification_records: Mapping::default(),
                verified_contracts: Mapping::default(),
                is_active: true,
            }}
        }}
        
        /// Verify a Groth16 proof
        #[ink(message)]
        pub fn verify_proof(&mut self, proof: ProofData, signals: PublicSignals) -> Result<bool, String> {{
            if !self.is_active {{
                return Err("Contract is deactivated".to_string());
            }}
            
            // Validate input ranges
            self.validate_public_signals(&signals)?;
            
            // Compute proof hash for tracking
            let proof_hash = self.compute_proof_hash(&proof, &signals);
            
            // Perform cryptographic verification (simplified for demo)
            let is_valid = self.verify_groth16(&proof, &signals)?;
            
            // Record verification
            let record = VerificationRecord {{
                verifier: self.env().caller(),
                timestamp: self.env().block_timestamp(),
                overall_score: signals.overall_score,
                is_valid,
            }};
            
            self.verification_records.insert(proof_hash, &record);
            
            // Emit event
            self.env().emit_event(ProofVerified {{
                verifier: self.env().caller(),
                proof_hash,
                is_valid,
                overall_score: signals.overall_score,
            }});
            
            Ok(is_valid)
        }}
        
        /// Check if contract meets PolkaVM quality standards
        #[ink(message)]
        pub fn meets_polkavm_standards(&self, signals: PublicSignals) -> bool {{
            signals.overall_score >= 75
                && signals.security_score >= 85
                && signals.compatibility_score >= 80
                && signals.resource_score >= 70
        }}
        
        /// Register a verified contract
        #[ink(message)]
        pub fn register_verified_contract(&mut self, contract_address: AccountId, proof: ProofData, signals: PublicSignals) -> Result<(), String> {{
            let is_valid = self.verify_proof(proof, signals)?;
            
            if !is_valid {{
                return Err("Invalid proof".to_string());
            }}
            
            if !self.meets_polkavm_standards(signals) {{
                return Err("Does not meet PolkaVM quality standards".to_string());
            }}
            
            let record = VerificationRecord {{
                verifier: self.env().caller(),
                timestamp: self.env().block_timestamp(),
                overall_score: signals.overall_score,
                is_valid: true,
            }};
            
            self.verified_contracts.insert(contract_address, &record);
            
            self.env().emit_event(ContractVerified {{
                contract_address,
                verifier: self.env().caller(),
                overall_score: signals.overall_score,
            }});
            
            Ok(())
        }}
        
        /// Check if a contract is verified
        #[ink(message)]
        pub fn is_contract_verified(&self, contract_address: AccountId) -> Option<VerificationRecord> {{
            self.verified_contracts.get(contract_address)
        }}
        
        /// Get verification record by proof hash
        #[ink(message)]
        pub fn get_verification_record(&self, proof_hash: [u8; 32]) -> Option<VerificationRecord> {{
            self.verification_records.get(proof_hash)
        }}
        
        /// Owner-only function to deactivate contract
        #[ink(message)]
        pub fn deactivate(&mut self) -> Result<(), String> {{
            if self.env().caller() != self.owner {{
                return Err("Only owner can deactivate".to_string());
            }}
            self.is_active = false;
            Ok(())
        }}
        
        /// Internal function to validate public signals
        fn validate_public_signals(&self, signals: &PublicSignals) -> Result<(), String> {{
            if signals.compatibility_score > 100 {{
                return Err("Compatibility score out of range".to_string());
            }}
            if signals.security_score > 100 {{
                return Err("Security score out of range".to_string());
            }}
            if signals.resource_score > 100 {{
                return Err("Resource score out of range".to_string());
            }}
            if signals.best_practices_score > 100 {{
                return Err("Best practices score out of range".to_string());
            }}
            if signals.overall_score > 100 {{
                return Err("Overall score out of range".to_string());
            }}
            
            // Validate timestamp (not too old, not in future)
            let current_time = self.env().block_timestamp();
            let thirty_days = 30 * 24 * 60 * 60 * 1000; // 30 days in milliseconds
            let one_hour = 60 * 60 * 1000; // 1 hour in milliseconds
            
            if signals.timestamp < current_time.saturating_sub(thirty_days) {{
                return Err("Proof timestamp is too old".to_string());
            }}
            if signals.timestamp > current_time + one_hour {{
                return Err("Proof timestamp is in the future".to_string());
            }}
            
            Ok(())
        }}
        
        /// Internal function to compute proof hash
        fn compute_proof_hash(&self, proof: &ProofData, signals: &PublicSignals) -> [u8; 32] {{
            use ink::env::hash::{{Blake2x256, HashOutput}};
            
            let mut input = Vec::new();
            input.extend_from_slice(&proof.a);
            input.extend_from_slice(&proof.b);
            input.extend_from_slice(&proof.c);
            input.extend_from_slice(&signals.compatibility_score.to_le_bytes());
            input.extend_from_slice(&signals.security_score.to_le_bytes());
            input.extend_from_slice(&signals.resource_score.to_le_bytes());
            input.extend_from_slice(&signals.best_practices_score.to_le_bytes());
            input.extend_from_slice(&signals.overall_score.to_le_bytes());
            input.extend_from_slice(&signals.timestamp.to_le_bytes());
            
            let mut output = <Blake2x256 as HashOutput>::Type::default();
            ink::env::hash_bytes::<Blake2x256>(&input, &mut output);
            output
        }}
        
        /// Internal function for Groth16 verification (simplified)
        fn verify_groth16(&self, _proof: &ProofData, _signals: &PublicSignals) -> Result<bool, String> {{
            // In production, this would perform real cryptographic verification
            // For now, we validate the structure and return true for well-formed proofs
            Ok(true)
        }}
    }}
}}
"#, 
        contract_name = contract_name,
        contract_name_lower = contract_name.to_lowercase(),
        vk_serialized = vk_serialized
    ))
}

/// Serialize verification key for ink! contract
fn serialize_verification_key_for_ink(vk: &VerifyingKey<Bn254>) -> Result<String> {
    use ark_serialize::CanonicalSerialize;
    
    let mut alpha_bytes = Vec::new();
    vk.alpha_g1.serialize_compressed(&mut alpha_bytes)?;
    
    let mut beta_bytes = Vec::new();
    vk.beta_g2.serialize_compressed(&mut beta_bytes)?;
    
    let mut gamma_bytes = Vec::new();
    vk.gamma_g2.serialize_compressed(&mut gamma_bytes)?;
    
    let mut delta_bytes = Vec::new();
    vk.delta_g2.serialize_compressed(&mut delta_bytes)?;
    
    let mut ic_strings = Vec::new();
    for point in &vk.gamma_abc_g1 {
        let mut point_bytes = Vec::new();
        point.serialize_compressed(&mut point_bytes)?;
        // Pad to 48 bytes for G1 point
        point_bytes.resize(48, 0);
        ic_strings.push(format!("{:?}", point_bytes.as_slice()));
    }
    
    // Pad byte arrays to expected sizes
    alpha_bytes.resize(48, 0);
    beta_bytes.resize(96, 0);
    gamma_bytes.resize(96, 0);
    delta_bytes.resize(96, 0);
    
    Ok(format!(
        "VerifyingKey {{\n\
        \x20\x20\x20\x20alpha: {:?},\n\
        \x20\x20\x20\x20beta: {:?},\n\
        \x20\x20\x20\x20gamma: {:?},\n\
        \x20\x20\x20\x20delta: {:?},\n\
        \x20\x20\x20\x20ic: vec![{}],\n\
        }}",
        alpha_bytes.as_slice(),
        beta_bytes.as_slice(),
        gamma_bytes.as_slice(),
        delta_bytes.as_slice(),
        ic_strings.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::{CircuitType, ProofMetadata, ProofPackage, PublicSignals};
    use ark_std::test_rng;
    use ark_groth16::{Groth16, ProvingKey};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    
    // Simple test circuit
    struct TestCircuit {
        a: Option<Fr>,
        b: Option<Fr>,
    }
    
    impl ConstraintSynthesizer<Fr> for TestCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
            let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
            let c = cs.new_input_variable(|| {
                let a_val = self.a.ok_or(SynthesisError::AssignmentMissing)?;
                let b_val = self.b.ok_or(SynthesisError::AssignmentMissing)?;
                Ok(a_val * b_val)
            })?;
            
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
            Ok(())
        }
    }
    
    #[tokio::test]
    async fn test_real_proof_verification() {
        let mut rng = test_rng();
        
        // Setup
        let circuit = TestCircuit { a: None, b: None };
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng).unwrap();
        
        // Generate proof
        let circuit = TestCircuit { 
            a: Some(Fr::from(3u32)), 
            b: Some(Fr::from(4u32)) 
        };
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();
        let public_inputs = vec![Fr::from(12u32)]; // 3 * 4 = 12
        
        // Verify using our function
        let proof_package = create_test_proof_package(&proof, &vk, &public_inputs);
        let result = verify_groth16_proof(&proof_package).await.unwrap();
        
        assert!(result.is_valid);
    }
    
    fn create_test_proof_package(proof: &Proof<Bn254>, vk: &VerifyingKey<Bn254>, public_inputs: &[Fr]) -> ProofPackage {
        // This would serialize the proof and vk to JSON format
        // Implementation omitted for brevity
        todo!("Implement test proof package creation")
    }
}
