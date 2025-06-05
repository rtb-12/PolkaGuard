use serde::{Deserialize, Serialize};
use std::fs;
use anyhow::Result;

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