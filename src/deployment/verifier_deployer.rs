use super::{DeploymentConfig, DeploymentResult, get_testnet_configs};
use anyhow::{anyhow, Result};
use ethers::prelude::*;
use std::collections::HashMap;
use std::io::{self, Write};

/// Secure credential collection for deployment
pub async fn collect_deployment_credentials(
    private_key: Option<String>,
    rpc_url: Option<String>,
    chain_id: Option<u64>,
    target_network: Option<String>,
) -> Result<DeploymentConfig> {
    // Get testnet configurations
    let testnet_configs = get_testnet_configs();
    
    // Handle network selection and RPC URL
    let (final_rpc_url, final_chain_id, network_name) = if let Some(network) = target_network {
        if let Some(config) = testnet_configs.get(&network) {
            println!("🌐 Using predefined testnet: {}", config.name);
            println!("   RPC: {}", config.rpc_url);
            println!("   Chain ID: {}", config.chain_id);
            (config.rpc_url.clone(), config.chain_id, config.name.clone())
        } else {
            // Custom network - require manual RPC and chain ID
            let rpc = rpc_url.ok_or_else(|| {
                anyhow!("Custom network '{}' requires --rpc-url parameter", network)
            })?;
            let chain = chain_id.ok_or_else(|| {
                anyhow!("Custom network '{}' requires --chain-id parameter", network)
            })?;
            (rpc, chain, network)
        }
    } else if let Some(rpc) = rpc_url {
        // Manual RPC provided
        let chain = if let Some(id) = chain_id {
            id
        } else {
            println!("⚠️  No chain ID provided, attempting to detect from RPC...");
            detect_chain_id(&rpc).await?
        };
        (rpc, chain, "Custom".to_string())
    } else {
        // No network specified, show options and prompt
        super::display_available_testnets();
        print!("Please enter testnet name (or 'custom' for manual RPC): ");
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let selection = input.trim().to_lowercase();
        
        if selection == "custom" {
            print!("Enter RPC URL: ");
            io::stdout().flush()?;
            let mut rpc_input = String::new();
            io::stdin().read_line(&mut rpc_input)?;
            let rpc = rpc_input.trim().to_string();
            
            let chain = if let Some(id) = chain_id {
                id
            } else {
                println!("Detecting chain ID from RPC...");
                detect_chain_id(&rpc).await?
            };
            (rpc, chain, "Custom".to_string())
        } else if let Some(config) = testnet_configs.get(&selection) {
            (config.rpc_url.clone(), config.chain_id, config.name.clone())
        } else {
            return Err(anyhow!("Unknown testnet '{}'. Use 'custom' for manual configuration.", selection));
        }
    };
    
    // Handle private key collection
    let final_private_key = if let Some(key) = private_key {
        key
    } else {
        print!("🔑 Enter private key for deployment (input hidden): ");
        io::stdout().flush()?;
        rpassword::read_password()?
    };
    
    // Validate private key format
    if !final_private_key.starts_with("0x") && final_private_key.len() != 64 && final_private_key.len() != 66 {
        return Err(anyhow!("Invalid private key format. Expected 64 hex characters or 66 with '0x' prefix."));
    }
    
    // Test connection to RPC
    println!("🔍 Testing RPC connection...");
    test_rpc_connection(&final_rpc_url).await?;
    
    println!("✅ RPC connection successful!");
    println!("📋 Deployment Configuration:");
    println!("   Network: {}", network_name);
    println!("   Chain ID: {}", final_chain_id);
    println!("   RPC: {}", final_rpc_url);
    
    Ok(DeploymentConfig {
        rpc_url: final_rpc_url,
        private_key: final_private_key,
        gas_limit: 3_000_000, // Default gas limit
        gas_price: None, // Use network suggested price
        chain_id: final_chain_id,
    })
}

/// Auto-detect chain ID from RPC endpoint
async fn detect_chain_id(rpc_url: &str) -> Result<u64> {
    let provider = Provider::<Http>::try_from(rpc_url)?;
    let chain_id = provider.get_chainid().await?;
    Ok(chain_id.as_u64())
}

/// Test RPC connection
async fn test_rpc_connection(rpc_url: &str) -> Result<()> {
    let provider = Provider::<Http>::try_from(rpc_url)?;
    let _block_number = provider.get_block_number().await?;
    Ok(())
}

/// Deploy Solidity verifier contract to testnet
pub async fn deploy_verifier_contract(
    _solidity_code: &str,
    _contract_name: &str,
    deployment_config: &DeploymentConfig,
) -> Result<DeploymentResult> {
    println!("🚀 Starting contract deployment...");
    
    // For now, this is a placeholder implementation
    // In a real deployment, you would:
    // 1. Compile the Solidity contract
    // 2. Create provider and wallet 
    // 3. Deploy the contract
    // 4. Wait for confirmation
    
    // Simulate deployment for demonstration
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    
    println!("✅ Contract deployment simulation completed!");
    
    Ok(DeploymentResult {
        contract_address: "0x1234567890123456789012345678901234567890".to_string(),
        transaction_hash: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef".to_string(),
        gas_used: 500000,
        deployment_cost: 5000000000000000, // 0.005 ETH in wei
        network_name: "Paseo Asset Hub Testnet".to_string(),
        chain_id: deployment_config.chain_id,
    })
}

// Note: Real contract compilation and deployment would be implemented here
// This is a placeholder implementation for the deployment pipeline

/// Calculate deployment cost in various units
pub fn calculate_deployment_cost(gas_used: u64, gas_price: u64) -> HashMap<String, String> {
    let mut costs = HashMap::new();
    
    let cost_wei = gas_used * gas_price;
    let cost_gwei = cost_wei as f64 / 1_000_000_000.0;
    let cost_eth = cost_wei as f64 / 1_000_000_000_000_000_000.0;
    
    costs.insert("wei".to_string(), cost_wei.to_string());
    costs.insert("gwei".to_string(), format!("{:.6}", cost_gwei));
    costs.insert("eth".to_string(), format!("{:.8}", cost_eth));
    
    costs
}

/// Get explorer URL for transaction
pub fn get_explorer_url(chain_id: u64, tx_hash: &str, address: Option<&str>) -> Option<String> {
    let testnet_configs = get_testnet_configs();
    
    for config in testnet_configs.values() {
        if config.chain_id == chain_id {
            return if let Some(addr) = address {
                Some(format!("{}/address/{}", config.explorer_url, addr))
            } else {
                Some(format!("{}/tx/{}", config.explorer_url, tx_hash))
            };
        }
    }
    
    None
}
