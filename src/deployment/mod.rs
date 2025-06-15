pub mod verifier_deployer;
pub use verifier_deployer::*;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Configuration for smart contract deployment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentConfig {
    pub rpc_url: String,
    pub private_key: String,
    pub gas_limit: u64,
    pub gas_price: Option<u64>,
    pub chain_id: u64,
}

/// Result of a successful contract deployment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentResult {
    pub contract_address: String,
    pub transaction_hash: String,
    pub gas_used: u64,
    pub deployment_cost: u64, // in wei
    pub network_name: String,
    pub chain_id: u64,
}

/// Supported testnets configuration
#[derive(Debug, Clone)]
pub struct TestnetConfig {
    pub name: String,
    pub rpc_url: String,
    pub chain_id: u64,
    pub explorer_url: String,
    pub currency_symbol: String,
}

/// Get predefined testnet configurations
pub fn get_testnet_configs() -> HashMap<String, TestnetConfig> {
    let mut configs = HashMap::new();
    
    // Paseo Asset Hub Testnet (Polkadot)
    configs.insert("paseo".to_string(), TestnetConfig {
        name: "Paseo Asset Hub".to_string(),
        rpc_url: "https://testnet-passet-hub-eth-rpc.polkadot.io".to_string(),
        chain_id: 420420421,
        explorer_url: "https://blockscout-passet-hub.parity-testnet.parity.io".to_string(),
        currency_symbol: "PAS".to_string(),
    });
    
    // Ethereum Sepolia Testnet
    configs.insert("sepolia".to_string(), TestnetConfig {
        name: "Ethereum Sepolia".to_string(),
        rpc_url: "https://rpc.sepolia.org".to_string(),
        chain_id: 11155111,
        explorer_url: "https://sepolia.etherscan.io".to_string(),
        currency_symbol: "ETH".to_string(),
    });
    
    // Ethereum Goerli Testnet (deprecated but still listed)
    configs.insert("goerli".to_string(), TestnetConfig {
        name: "Ethereum Goerli".to_string(),
        rpc_url: "https://goerli.infura.io/v3/".to_string(), // User needs to add API key
        chain_id: 5,
        explorer_url: "https://goerli.etherscan.io".to_string(),
        currency_symbol: "ETH".to_string(),
    });
    
    // Polygon Mumbai Testnet
    configs.insert("mumbai".to_string(), TestnetConfig {
        name: "Polygon Mumbai".to_string(),
        rpc_url: "https://rpc-mumbai.maticvigil.com".to_string(),
        chain_id: 80001,
        explorer_url: "https://mumbai.polygonscan.com".to_string(),
        currency_symbol: "MATIC".to_string(),
    });
    
    // BSC Testnet
    configs.insert("bsc-testnet".to_string(), TestnetConfig {
        name: "BSC Testnet".to_string(),
        rpc_url: "https://data-seed-prebsc-1-s1.binance.org:8545".to_string(),
        chain_id: 97,
        explorer_url: "https://testnet.bscscan.com".to_string(),
        currency_symbol: "BNB".to_string(),
    });
    
    // Arbitrum Sepolia Testnet
    configs.insert("arbitrum-sepolia".to_string(), TestnetConfig {
        name: "Arbitrum Sepolia".to_string(),
        rpc_url: "https://sepolia-rollup.arbitrum.io/rpc".to_string(),
        chain_id: 421614,
        explorer_url: "https://sepolia.arbiscan.io".to_string(),
        currency_symbol: "ETH".to_string(),
    });
    
    // Optimism Sepolia Testnet
    configs.insert("optimism-sepolia".to_string(), TestnetConfig {
        name: "Optimism Sepolia".to_string(),
        rpc_url: "https://sepolia.optimism.io".to_string(),
        chain_id: 11155420,
        explorer_url: "https://sepolia-optimism.etherscan.io".to_string(),
        currency_symbol: "ETH".to_string(),
    });
    
    configs
}

/// Display available testnets with their details
pub fn display_available_testnets() {
    let configs = get_testnet_configs();
    
    println!("🌐 Available Testnets:");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    for (key, config) in configs {
        println!("🔗 {}", key);
        println!("   Name: {}", config.name);
        println!("   Chain ID: {}", config.chain_id);
        println!("   RPC: {}", config.rpc_url);
        println!("   Explorer: {}", config.explorer_url);
        println!("   Currency: {}", config.currency_symbol);
        println!();
    }
}
