use serde::{Deserialize, Serialize};
use std::fs;
use anyhow::Result;

/// Network configuration for cost calculations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub name: String,
    pub token_symbol: String,
    pub token_decimals: u8,
    pub ref_time_price_per_unit: u64,    
    pub proof_size_price_per_byte: u64,  
    pub storage_deposit_per_byte: u64,   
    pub token_price_usd: f64,            
}

/// Cost calculation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostBreakdown {
    pub ref_time_cost_plancks: u64,
    pub proof_size_cost_plancks: u64,
    pub storage_deposit_plancks: u64,
    pub total_cost_plancks: u64,
    pub ref_time_cost_tokens: f64,
    pub proof_size_cost_tokens: f64,
    pub storage_deposit_tokens: f64,
    pub total_cost_tokens: f64,
    pub total_cost_usd: f64,
    pub network: NetworkConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub enabled_checks: Vec<String>,
    pub severity_threshold: String,
    pub output_format: String,
    pub compiler_settings: CompilerSettings,
    pub analysis_settings: AnalysisSettings,
    pub polkavm_settings: PolkaVMSettings,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CompilerSettings {
    pub optimizer: bool,
    pub runs: u32,
    pub version: String,
    pub evm_version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisSettings {
    pub memory_limits: MemoryLimits,
    pub security_checks: SecurityChecks,
    pub best_practices: BestPractices,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MemoryLimits {
    pub max_stack_size: u32,
    pub max_heap_size: u32,
    pub warn_on_large_arrays: bool,
    pub large_array_threshold: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityChecks {
    pub check_reentrancy: bool,
    pub check_access_control: bool,
    pub check_arithmetic: bool,
    pub check_external_calls: bool,
    pub check_selfdestruct: bool,
    pub check_timestamp_dependency: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BestPractices {
    pub require_events: bool,
    pub require_modifiers: bool,
    pub require_constructor: bool,
    pub require_spdx: bool,
    pub require_version_pragma: bool,
    pub require_natspec: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PolkaVMSettings {
    pub check_evm_compatibility: bool,
    pub check_memory_constraints: bool,
    pub check_gas_usage: bool,
    pub check_storage_usage: bool,
    pub allowed_opcodes: Vec<String>,
    pub forbidden_opcodes: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled_checks: vec![
                "compatibility".to_string(),
                "security".to_string(),
                "resources".to_string(),
                "best-practices".to_string(),
            ],
            severity_threshold: "medium".to_string(),
            output_format: "text".to_string(),
            compiler_settings: CompilerSettings {
                optimizer: true,
                runs: 200,
                version: "0.8.0".to_string(),
                evm_version: "paris".to_string(),
            },
            analysis_settings: AnalysisSettings {
                memory_limits: MemoryLimits {
                    max_stack_size: 32768,
                    max_heap_size: 65536,
                    warn_on_large_arrays: true,
                    large_array_threshold: 1000,
                },
                security_checks: SecurityChecks {
                    check_reentrancy: true,
                    check_access_control: true,
                    check_arithmetic: true,
                    check_external_calls: true,
                    check_selfdestruct: true,
                    check_timestamp_dependency: true,
                },
                best_practices: BestPractices {
                    require_events: true,
                    require_modifiers: true,
                    require_constructor: true,
                    require_spdx: true,
                    require_version_pragma: true,
                    require_natspec: true,
                },
            },
            polkavm_settings: PolkaVMSettings {
                check_evm_compatibility: true,
                check_memory_constraints: true,
                check_gas_usage: true,
                check_storage_usage: true,
                allowed_opcodes: vec![
                    "ADD".to_string(),
                    "SUB".to_string(),
                    "MUL".to_string(),
                    "DIV".to_string(),
                    "SDIV".to_string(),
                    "MOD".to_string(),
                    "SMOD".to_string(),
                    "EXP".to_string(),
                    "NOT".to_string(),
                    "LT".to_string(),
                    "GT".to_string(),
                    "SLT".to_string(),
                    "SGT".to_string(),
                    "EQ".to_string(),
                    "ISZERO".to_string(),
                    "AND".to_string(),
                    "OR".to_string(),
                    "XOR".to_string(),
                    "BYTE".to_string(),
                    "SHL".to_string(),
                    "SHR".to_string(),
                    "SAR".to_string(),
                    "ADDMOD".to_string(),
                    "MULMOD".to_string(),
                    "SIGNEXTEND".to_string(),
                    "KECCAK256".to_string(),
                    "ADDRESS".to_string(),
                    "BALANCE".to_string(),
                    "ORIGIN".to_string(),
                    "CALLER".to_string(),
                    "CALLVALUE".to_string(),
                    "CALLDATALOAD".to_string(),
                    "CALLDATASIZE".to_string(),
                    "CALLDATACOPY".to_string(),
                    "CODESIZE".to_string(),
                    "CODECOPY".to_string(),
                    "GASPRICE".to_string(),
                    "EXTCODESIZE".to_string(),
                    "EXTCODECOPY".to_string(),
                    "RETURNDATASIZE".to_string(),
                    "RETURNDATACOPY".to_string(),
                    "EXTCODEHASH".to_string(),
                    "BLOCKHASH".to_string(),
                    "COINBASE".to_string(),
                    "TIMESTAMP".to_string(),
                    "NUMBER".to_string(),
                    "DIFFICULTY".to_string(),
                    "GASLIMIT".to_string(),
                    "POP".to_string(),
                    "MLOAD".to_string(),
                    "MSTORE".to_string(),
                    "MSTORE8".to_string(),
                    "SLOAD".to_string(),
                    "SSTORE".to_string(),
                    "JUMP".to_string(),
                    "JUMPI".to_string(),
                    "PC".to_string(),
                    "MSIZE".to_string(),
                    "GAS".to_string(),
                    "JUMPDEST".to_string(),
                    "PUSH1".to_string(),
                    "PUSH2".to_string(),
                    "PUSH3".to_string(),
                    "PUSH4".to_string(),
                    "PUSH5".to_string(),
                    "PUSH6".to_string(),
                    "PUSH7".to_string(),
                    "PUSH8".to_string(),
                    "PUSH9".to_string(),
                    "PUSH10".to_string(),
                    "PUSH11".to_string(),
                    "PUSH12".to_string(),
                    "PUSH13".to_string(),
                    "PUSH14".to_string(),
                    "PUSH15".to_string(),
                    "PUSH16".to_string(),
                    "PUSH17".to_string(),
                    "PUSH18".to_string(),
                    "PUSH19".to_string(),
                    "PUSH20".to_string(),
                    "PUSH21".to_string(),
                    "PUSH22".to_string(),
                    "PUSH23".to_string(),
                    "PUSH24".to_string(),
                    "PUSH25".to_string(),
                    "PUSH26".to_string(),
                    "PUSH27".to_string(),
                    "PUSH28".to_string(),
                    "PUSH29".to_string(),
                    "PUSH30".to_string(),
                    "PUSH31".to_string(),
                    "PUSH32".to_string(),
                    "DUP1".to_string(),
                    "DUP2".to_string(),
                    "DUP3".to_string(),
                    "DUP4".to_string(),
                    "DUP5".to_string(),
                    "DUP6".to_string(),
                    "DUP7".to_string(),
                    "DUP8".to_string(),
                    "DUP9".to_string(),
                    "DUP10".to_string(),
                    "DUP11".to_string(),
                    "DUP12".to_string(),
                    "DUP13".to_string(),
                    "DUP14".to_string(),
                    "DUP15".to_string(),
                    "DUP16".to_string(),
                    "SWAP1".to_string(),
                    "SWAP2".to_string(),
                    "SWAP3".to_string(),
                    "SWAP4".to_string(),
                    "SWAP5".to_string(),
                    "SWAP6".to_string(),
                    "SWAP7".to_string(),
                    "SWAP8".to_string(),
                    "SWAP9".to_string(),
                    "SWAP10".to_string(),
                    "SWAP11".to_string(),
                    "SWAP12".to_string(),
                    "SWAP13".to_string(),
                    "SWAP14".to_string(),
                    "SWAP15".to_string(),
                    "SWAP16".to_string(),
                    "LOG0".to_string(),
                    "LOG1".to_string(),
                    "LOG2".to_string(),
                    "LOG3".to_string(),
                    "LOG4".to_string(),
                    "CREATE".to_string(),
                    "CALL".to_string(),
                    "CALLCODE".to_string(),
                    "RETURN".to_string(),
                    "DELEGATECALL".to_string(),
                    "CREATE2".to_string(),
                    "STATICCALL".to_string(),
                    "REVERT".to_string(),
                    "INVALID".to_string(),
                    "SELFDESTRUCT".to_string(),
                ],
                forbidden_opcodes: vec![
                    "SELFDESTRUCT".to_string(),
                    "EXTCODESIZE".to_string(),
                    "EXTCODECOPY".to_string(),
                    "EXTCODEHASH".to_string(),
                    "BLOBHASH".to_string(),
                    "BLOBBASEFEE".to_string(),
                ],
            },
        }
    }
}

impl Config {
    #[allow(dead_code)]
    pub fn load(path: Option<&str>) -> Result<Self> {
        match path {
            Some(p) => {
                let contents = fs::read_to_string(p)?;
                Ok(serde_json::from_str(&contents)?)
            }
            None => Ok(Self::default()),
        }
    }

    pub fn save(&self, path: &str) -> Result<()> {
        let contents = serde_json::to_string_pretty(self)?;
        fs::write(path, contents)?;
        Ok(())
    }
}

impl NetworkConfig {
    /// Polkadot mainnet configuration
    pub fn polkadot() -> Self {
        Self {
            name: "Polkadot".to_string(),
            token_symbol: "DOT".to_string(),
            token_decimals: 10,
            
            // These values are derived from Polkadot's runtime configuration
            ref_time_price_per_unit: 100,      // ~0.0000000001 DOT per ref_time unit
            proof_size_price_per_byte: 1_000,  // ~0.000000001 DOT per proof_size byte
            storage_deposit_per_byte: 1_000_000_000, // ~0.1 DOT per byte
            token_price_usd: 7.0, // Approximate DOT price (should be updated dynamically)
        }
    }

    /// Kusama network configuration
    pub fn kusama() -> Self {
        Self {
            name: "Kusama".to_string(),
            token_symbol: "KSM".to_string(),
            token_decimals: 12,
            ref_time_price_per_unit: 100,
            proof_size_price_per_byte: 1_000,
            storage_deposit_per_byte: 100_000_000, // Lower storage deposit than Polkadot
            token_price_usd: 25.0, // Approximate KSM price
        }
    }

    /// Westend testnet configuration
    pub fn westend() -> Self {
        Self {
            name: "Westend".to_string(),
            token_symbol: "WND".to_string(),
            token_decimals: 12,
            ref_time_price_per_unit: 100,
            proof_size_price_per_byte: 1_000,
            storage_deposit_per_byte: 100_000_000,
            token_price_usd: 0.0, // Testnet tokens have no real value
        }
    }

    /// Rococo testnet configuration
    pub fn rococo() -> Self {
        Self {
            name: "Rococo".to_string(),
            token_symbol: "ROC".to_string(),
            token_decimals: 12,
            ref_time_price_per_unit: 100,
            proof_size_price_per_byte: 1_000,
            storage_deposit_per_byte: 100_000_000,
            token_price_usd: 0.0, // Testnet tokens have no real value
        }
    }

    /// Local development network configuration
    pub fn local() -> Self {
        Self {
            name: "Local".to_string(),
            token_symbol: "UNIT".to_string(),
            token_decimals: 12,
            ref_time_price_per_unit: 100,
            proof_size_price_per_byte: 1_000,
            storage_deposit_per_byte: 100_000_000,
            token_price_usd: 0.0, // Development tokens have no real value
        }
    }

    /// Get network configuration by name
    pub fn by_name(name: &str) -> Self {
        match name.to_lowercase().as_str() {
            "polkadot" => Self::polkadot(),
            "kusama" => Self::kusama(),
            "westend" => Self::westend(),
            "rococo" => Self::rococo(),
            "local" | "development" => Self::local(),
            _ => Self::polkadot(), // Default to Polkadot
        }
    }

    /// Convert plancks to human-readable token amount
    pub fn plancks_to_token(&self, plancks: u64) -> f64 {
        plancks as f64 / 10_u64.pow(self.token_decimals as u32) as f64
    }

    /// Convert token amount to plancks
    pub fn token_to_plancks(&self, tokens: f64) -> u64 {
        (tokens * 10_u64.pow(self.token_decimals as u32) as f64) as u64
    }
}

impl CostBreakdown {
    /// Calculate cost breakdown 
    /// 
    /// # Arguments
    /// * `ref_time` - Reference time in picoseconds (weight units)
    /// * `proof_size` - Proof size in bytes
    /// * `storage_deposit` - Storage deposit in plancks
    /// * `network` - Network configuration
    /// 
    /// # Cost Calculation Methodology
    /// 
    /// The cost calculation is based on Polkadot's Weight system:
    /// 
    /// 1. **ref_time**: Represents the computational complexity of an operation
    ///    - Measured in picoseconds of execution time
    ///    - Each unit costs `ref_time_price_per_unit` plancks
    ///    - Based on the computational resources consumed
    /// 
    /// 2. **proof_size**: Represents the amount of data that needs to be proved
    ///    - Measured in bytes
    ///    - Each byte costs `proof_size_price_per_byte` plancks
    ///    - Related to the state proof verification cost
    /// 
    /// 3. **storage_deposit**: One-time deposit for storing data on-chain
    ///    - Measured in plancks
    ///    - Refundable when storage is freed
    ///    - Based on the economic security model
    /// 
    /// Total cost = (ref_time × ref_time_price) + (proof_size × proof_size_price) + storage_deposit
    pub fn calculate(
        ref_time: u64,
        proof_size: u64,
        storage_deposit: u64,
        network: NetworkConfig,
    ) -> Self {
        let ref_time_cost_plancks = ref_time * network.ref_time_price_per_unit;
        let proof_size_cost_plancks = proof_size * network.proof_size_price_per_byte;
        let total_cost_plancks = ref_time_cost_plancks + proof_size_cost_plancks + storage_deposit;

        let ref_time_cost_tokens = network.plancks_to_token(ref_time_cost_plancks);
        let proof_size_cost_tokens = network.plancks_to_token(proof_size_cost_plancks);
        let storage_deposit_tokens = network.plancks_to_token(storage_deposit);
        let total_cost_tokens = network.plancks_to_token(total_cost_plancks);
        let total_cost_usd = total_cost_tokens * network.token_price_usd;

        Self {
            ref_time_cost_plancks,
            proof_size_cost_plancks,
            storage_deposit_plancks: storage_deposit,
            total_cost_plancks,
            ref_time_cost_tokens,
            proof_size_cost_tokens,
            storage_deposit_tokens,
            total_cost_tokens,
            total_cost_usd,
            network,
        }
    }
}