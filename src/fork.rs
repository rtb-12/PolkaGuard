use anyhow::{anyhow, Result};
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use sysinfo::{System, Pid};
use tokio::time::sleep;
use which::which;

const PID_FILE: &str = ".polkaguard_fork.pid";
const CONFIG_FILE: &str = "hardhat.config.js";

/// Manages PolkaVM fork processes and dependencies
pub struct ForkManager {
    project_dir: PathBuf,
    port: u16,
    system: System,
}

impl ForkManager {
    pub fn new(project_dir: Option<String>, port: u16) -> Result<Self> {
        let project_dir = if let Some(dir) = project_dir {
            PathBuf::from(dir)
        } else {
            std::env::current_dir()?.join("polkaguard_fork")
        };

        Ok(Self {
            project_dir,
            port,
            system: System::new_all(),
        })
    }

    /// Check if Node.js is installed
    pub fn check_nodejs(&self) -> Result<bool> {
        match which("node") {
            Ok(_) => {
                // Check Node.js version
                let output = Command::new("node").arg("--version").output()?;
                if output.status.success() {
                    let version = String::from_utf8_lossy(&output.stdout);
                    let version_str = version.trim();
                    println!("✅ Node.js found: {}", version_str);
                    
                    // Check for Hardhat compatibility (Node.js 16-22)
                    if let Some(version_num) = version_str.strip_prefix('v') {
                        if let Ok(major_version) = version_num.split('.').next().unwrap_or("0").parse::<u32>() {
                            if major_version > 22 {
                                println!("⚠️  Warning: Node.js {} may not be fully compatible with Hardhat", version_str);
                                println!("   Recommended: Node.js v16-v22 for best compatibility");
                                println!("   Consider using nvm to install a compatible version:");
                                println!("   nvm install 20 && nvm use 20");
                            }
                        }
                    }
                    
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Err(_) => Ok(false),
        }
    }

    /// Check if npm is installed
    pub fn check_npm(&self) -> Result<bool> {
        match which("npm") {
            Ok(_) => {
                let output = Command::new("npm").arg("--version").output()?;
                if output.status.success() {
                    let version = String::from_utf8_lossy(&output.stdout);
                    println!("✅ npm found: v{}", version.trim());
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Err(_) => Ok(false),
        }
    }

    /// Check if Substrate node binary exists
    pub fn check_substrate_node(&self, binary_path: Option<&str>) -> Result<Option<String>> {
        let candidates = if let Some(path) = binary_path {
            vec![path.to_string()]
        } else {
            vec![
                "substrate-node".to_string(),
                "polkadot-parachain".to_string(),
                "substrate".to_string(),
                "./target/release/substrate-node".to_string(),
                "./node/target/release/substrate-node".to_string(),
            ]
        };

        for candidate in candidates {
            if let Ok(path) = which(&candidate) {
                println!("✅ Substrate node found: {}", path.display());
                return Ok(Some(path.to_string_lossy().to_string()));
            }
        }

        Ok(None)
    }

    /// Check if eth-rpc adapter binary exists
    pub fn check_eth_rpc_adapter(&self, binary_path: Option<&str>) -> Result<Option<String>> {
        let candidates = if let Some(path) = binary_path {
            vec![path.to_string()]
        } else {
            vec![
                "revive-eth-rpc".to_string(),
                "eth-rpc".to_string(),
                "./target/release/revive-eth-rpc".to_string(),
            ]
        };

        for candidate in candidates {
            if let Ok(path) = which(&candidate) {
                println!("✅ ETH-RPC adapter found: {}", path.display());
                return Ok(Some(path.to_string_lossy().to_string()));
            }
        }

        Ok(None)
    }

    /// Install Node.js if not present (asks user for permission)
    pub async fn install_nodejs(&self) -> Result<()> {
        println!("❌ Node.js not found on system");
        println!("📋 Node.js is required for PolkaVM fork mode");
        println!();
        println!("🔧 Installation options:");
        println!("   1. Install via Node Version Manager (recommended):");
        println!("      curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash");
        println!("      source ~/.bashrc && nvm install --lts");
        println!();
        println!("   2. Install via package manager:");
        println!("      Ubuntu/Debian: sudo apt update && sudo apt install nodejs npm");
        println!("      Fedora/RHEL:   sudo dnf install nodejs npm");
        println!("      Arch:          sudo pacman -S nodejs npm");
        println!();
        println!("   3. Download from: https://nodejs.org/");
        println!();
        
        Err(anyhow!(
            "Please install Node.js and npm, then run the command again. See installation options above."
        ))
    }

    /// Create project directory and initialize Hardhat project
    pub async fn setup_project(&self) -> Result<()> {
        println!("📁 Setting up PolkaVM fork project at: {}", self.project_dir.display());

        // Create project directory
        if !self.project_dir.exists() {
            fs::create_dir_all(&self.project_dir)?;
            println!("✅ Created project directory");
        }

        // Check if already initialized
        let package_json = self.project_dir.join("package.json");
        let node_modules = self.project_dir.join("node_modules");
        let hardhat_installed = node_modules.join("hardhat").exists();
        let hardhat_bin = node_modules.join(".bin").join("hardhat").exists();

        if package_json.exists() && hardhat_installed && hardhat_bin {
            println!("✅ Project already initialized and Hardhat is locally installed");
            return Ok(());
        }
            // Initialize npm project
            println!("🔄 Initializing npm project...");
            let npm_init = Command::new("npm")
                .args(["init", "-y"])
                .current_dir(&self.project_dir)
                .output()?;

            if !npm_init.status.success() {
                return Err(anyhow!(
                    "Failed to initialize npm project: {}",
                    String::from_utf8_lossy(&npm_init.stderr)
                ));
            }
        if !package_json.exists() {
            // Initialize npm project
            println!("🔄 Initializing npm project...");
            let npm_init = Command::new("npm")
                .args(["init", "-y"])
                .current_dir(&self.project_dir)
                .output()?;

            if !npm_init.status.success() {
                return Err(anyhow!(
                    "Failed to initialize npm project: {}",
                    String::from_utf8_lossy(&npm_init.stderr)
                ));
            }
        }

        // Install required packages if not already installed
        if !hardhat_installed || !hardhat_bin {
            println!("📦 Installing Hardhat and dependencies locally...");
            
            // First install core hardhat
            let npm_install_hardhat = Command::new("npm")
                .args(["install", "--save-dev", "hardhat@^2.19.0", "@nomicfoundation/hardhat-toolbox"])
                .current_dir(&self.project_dir)
                .output()?;

            if !npm_install_hardhat.status.success() {
                let error_msg = String::from_utf8_lossy(&npm_install_hardhat.stderr);
                return Err(anyhow!(
                    "Failed to install Hardhat: {}",
                    error_msg
                ));
            }

            // Install additional packages that are available
            let additional_packages = ["dotenv"];
            
            let npm_install_additional = Command::new("npm")
                .args(["install", "--save-dev"])
                .args(&additional_packages)
                .current_dir(&self.project_dir)
                .output()?;

            if !npm_install_additional.status.success() {
                println!("⚠️  Some additional packages failed to install, continuing...");
            }

            println!("✅ Hardhat installed successfully");
        } else {
            println!("✅ Hardhat already installed locally");
        }
        
        // Create basic contracts directory
        let contracts_dir = self.project_dir.join("contracts");
        if !contracts_dir.exists() {
            fs::create_dir_all(&contracts_dir)?;
            
            // Create a simple example contract
            let example_contract = r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract ExampleContract {
    uint256 public value;
    
    constructor() {
        value = 42;
    }
    
    function setValue(uint256 _value) public {
        value = _value;
    }
    
    function getValue() public view returns (uint256) {
        return value;
    }
}
"#;
            fs::write(contracts_dir.join("ExampleContract.sol"), example_contract)?;
            println!("✅ Created example contract");
        }

        Ok(())
    }

    /// Generate Hardhat configuration for PolkaVM
    pub fn generate_hardhat_config(
        &self,
        substrate_node: Option<&str>,
        eth_rpc_adapter: Option<&str>,
    ) -> Result<()> {
        let config_path = self.project_dir.join(CONFIG_FILE);
        
        let node_binary = substrate_node.unwrap_or("substrate-node");
        let adapter_binary = eth_rpc_adapter.unwrap_or("revive-eth-rpc");

        let config_content = format!(
            r#"require('@nomicfoundation/hardhat-toolbox');
require('dotenv').config();

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {{
  solidity: {{
    version: "0.8.19",
    settings: {{
      optimizer: {{
        enabled: true,
        runs: 200
      }}
    }}
  }},
  networks: {{
    hardhat: {{
      // Standard Hardhat local network
      // PolkaVM integration will be added when hardhat-polkadot is available
    }},
    localhost: {{
      url: "http://127.0.0.1:8545",
      // This will connect to your locally running fork
    }},
    polkavm_fork: {{
      url: "http://127.0.0.1:{}",
      accounts: {{
        mnemonic: "test test test test test test test test test test test junk"
      }},
      // Custom network for PolkaVM fork
      // Substrate node path: {}
      // ETH-RPC adapter path: {}
    }}
  }},
  // PolkaVM-specific configuration (placeholder for future hardhat-polkadot plugin)
  polkavm: {{
    enabled: false, // Will be enabled when plugin is available
    substrateBinary: "{}",
    ethRpcBinary: "{}"
  }}
}};
"#,
            self.port, node_binary, adapter_binary, node_binary, adapter_binary
        );

        fs::write(&config_path, config_content)?;
        println!("✅ Generated Hardhat configuration: {}", config_path.display());

        // Create .env file with default values
        let env_path = self.project_dir.join(".env");
        if !env_path.exists() {
            let env_content = format!(
                r#"# PolkaVM Fork Configuration
POLKAVM_RPC_PORT={}
SUBSTRATE_NODE_PATH={}
ETH_RPC_ADAPTER_PATH={}

# Optional: Custom resolc compiler path
# RESOLC_PATH=/path/to/resolc
"#,
                self.port, node_binary, adapter_binary
            );
            fs::write(&env_path, env_content)?;
            println!("✅ Generated .env file");
        }

        Ok(())
    }

    /// Start the PolkaVM fork
    pub async fn start_fork(&mut self, daemon: bool) -> Result<()> {
        // Check if already running
        if self.is_fork_running()? {
            println!("⚠️  PolkaVM fork is already running on port {}", self.port);
            return Ok(());
        }

        // Ensure Hardhat is installed locally
        let hardhat_bin = self.project_dir.join("node_modules").join(".bin").join("hardhat");
        if !hardhat_bin.exists() {
            return Err(anyhow!(
                "Hardhat not found in local project. Please run setup first or install with: npm install --save-dev hardhat"
            ));
        }

        println!("🚀 Starting PolkaVM local fork on port {}...", self.port);

        // Use local Hardhat installation
        let mut cmd = Command::new(&hardhat_bin);
        cmd.args(["node", "--network", "hardhat", "--port", &self.port.to_string()])
            .current_dir(&self.project_dir);

        if daemon {
            cmd.stdout(Stdio::null()).stderr(Stdio::null()).stdin(Stdio::null());
            
            let child = cmd.spawn()?;
            let pid = child.id();
            
            // Save PID for later cleanup
            let pid_file = self.project_dir.join(PID_FILE);
            fs::write(&pid_file, pid.to_string())?;
            
            println!("✅ PolkaVM fork started in daemon mode");
            println!("📋 Process ID: {}", pid);
            println!("🌐 RPC Endpoint: http://localhost:{}", self.port);
            println!("🛑 Stop with: polkaguard run-fork --stop");
            
            // Wait a bit to ensure process starts
            sleep(Duration::from_secs(3)).await;
            
            if !self.is_fork_running()? {
                return Err(anyhow!("Failed to start PolkaVM fork - process died"));
            }
        } else {
            println!("🔄 Starting PolkaVM fork in interactive mode...");
            println!("💡 Press Ctrl+C to stop");
            println!("🌐 RPC Endpoint: http://localhost:{}", self.port);
            
            let status = cmd.status()?;
            if !status.success() {
                return Err(anyhow!("PolkaVM fork exited with error"));
            }
        }

        Ok(())
    }

    /// Stop the PolkaVM fork daemon
    pub fn stop_fork(&mut self) -> Result<()> {
        let pid_file = self.project_dir.join(PID_FILE);
        
        if !pid_file.exists() {
            println!("ℹ️  No PolkaVM fork daemon found");
            return Ok(());
        }

        let pid_str = fs::read_to_string(&pid_file)?;
        let pid: u32 = pid_str.trim().parse()?;

        // Update system info
        self.system.refresh_processes();
        
        if let Some(process) = self.system.process(Pid::from(pid as usize)) {
            println!("🛑 Stopping PolkaVM fork daemon (PID: {})...", pid);
            
            if process.kill() {
                println!("✅ PolkaVM fork stopped successfully");
                fs::remove_file(&pid_file)?;
            } else {
                return Err(anyhow!("Failed to stop process {}", pid));
            }
        } else {
            println!("ℹ️  Process {} not found (may have already stopped)", pid);
            fs::remove_file(&pid_file)?;
        }

        Ok(())
    }

    /// Check if fork is currently running
    pub fn is_fork_running(&mut self) -> Result<bool> {
        let pid_file = self.project_dir.join(PID_FILE);
        
        if !pid_file.exists() {
            return Ok(false);
        }

        let pid_str = fs::read_to_string(&pid_file)?;
        if let Ok(pid) = pid_str.trim().parse::<u32>() {
            self.system.refresh_processes();
            
            if let Some(process) = self.system.process(Pid::from(pid as usize)) {
                // Check if it's actually our hardhat process
                let name = process.name();
                if name.contains("node") || name.contains("hardhat") {
                    return Ok(true);
                }
            }
        }

        // Clean up stale PID file
        fs::remove_file(&pid_file).ok();
        Ok(false)
    }

    /// Get fork status information
    pub fn get_fork_status(&mut self) -> Result<HashMap<String, serde_json::Value>> {
        let mut status = HashMap::new();
        
        status.insert("running".to_string(), json!(self.is_fork_running()?));
        status.insert("port".to_string(), json!(self.port));
        status.insert("project_dir".to_string(), json!(self.project_dir.display().to_string()));
        status.insert("rpc_endpoint".to_string(), json!(format!("http://localhost:{}", self.port)));
        
        let pid_file = self.project_dir.join(PID_FILE);
        if pid_file.exists() {
            if let Ok(pid_str) = fs::read_to_string(&pid_file) {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    status.insert("pid".to_string(), json!(pid));
                }
            }
        }

        // Check dependencies
        status.insert("nodejs_installed".to_string(), json!(self.check_nodejs().unwrap_or(false)));
        status.insert("npm_installed".to_string(), json!(self.check_npm().unwrap_or(false)));
        
        Ok(status)
    }

    /// Cleanup on CLI exit (called from signal handler)
    pub fn cleanup_on_exit(&mut self) -> Result<()> {
        if self.is_fork_running()? {
            println!("\n🧹 Cleaning up PolkaVM fork process...");
            self.stop_fork()?;
        }
        Ok(())
    }
}

impl Drop for ForkManager {
    fn drop(&mut self) {
        // Auto-cleanup when ForkManager is dropped
        if let Err(e) = self.cleanup_on_exit() {
            eprintln!("Warning: Failed to cleanup fork process: {}", e);
        }
    }
}
