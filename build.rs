use std::process::Command;

fn main() {
    // Check for solc
    let solc_version = Command::new("solc")
        .arg("--version")
        .output();
    
    if solc_version.is_err() {
        println!("cargo:warning=solc not found. Please install solc version 0.8.0 or higher.");
    } else if let Ok(output) = solc_version {
        let version = String::from_utf8_lossy(&output.stdout);
        if !version.contains("0.8.") {
            println!("cargo:warning=solc version must be 0.8.0 or higher. Current version: {}", version);
        }
    }

    // Check for resolc
    let resolc_version = Command::new("resolc")
        .arg("--version")
        .output();
    
    if resolc_version.is_err() {
        println!("cargo:warning=resolc not found. Please install the revive compiler.");
        println!("cargo:warning=You can find binary releases at: https://contracts.polkadot.io/revive_compiler/installation");
    }

    // Check for polkatool
    let polkatool_version = Command::new("polkatool")
        .arg("--version")
        .output();
    
    if polkatool_version.is_err() {
        println!("cargo:warning=polkatool not found. Please install it using: cargo install polkatool");
    }

    // Check for xxd
    let xxd_version = Command::new("xxd")
        .arg("--version")
        .output();
    
    if xxd_version.is_err() {
        println!("cargo:warning=xxd not found. Please install it using your system package manager.");
    }
} 