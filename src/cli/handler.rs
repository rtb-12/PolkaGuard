use anyhow::Result;
use crate::config::Config;
use crate::cli::{Commands, Cli};
use crate::analyzer::Analyzer;
use crate::linter::{Linter, LinterConfig, LintSeverity};
use crate::utils::format_bytes;
use std::fs;
use std::process::Command;
use serde_json::json;

pub async fn handle_command(cli: &Cli) -> Result<()> {
    match &cli.command {
        Commands::Init { config_path } => {
            let config = Config::default();
            config.save(config_path)?;
            if cli.format == "json" {
                println!("{}", json!({
                    "status": "success",
                    "message": format!("Created new configuration file at: {}", config_path)
                }));
            } else {
                println!("Created new configuration file at: {}", config_path);
            }
        }
        Commands::Analyze => {
            if !fs::metadata(&cli.path)?.is_file() {
                return Err(anyhow::anyhow!("Contract file not found: {}", cli.path));
            }

            if cli.format != "json" {
                println!("Analyzing contract: {}", cli.path);
                if let Some(stack_size) = cli.stack_size {
                    println!("Stack size: {} bytes", stack_size);
                }
                if let Some(heap_size) = cli.heap_size {
                    println!("Heap size: {} bytes", heap_size);
                }
            }
            

            let source = fs::read_to_string(&cli.path)?;
            let linter_config = LinterConfig::default();
            let linter = Linter::new(linter_config);
            let lint_issues = linter.lint(&source)?;

            let mut output = if cli.format == "json" {
                json!({
                    "contract": cli.path,
                    "configuration": {
                        "stack_size": cli.stack_size,
                        "heap_size": cli.heap_size,
                        "optimization": cli.optimization,
                        "debug": cli.debug
                    },
                    "linting_issues": {
                        "errors": Vec::<serde_json::Value>::new(),
                        "warnings": Vec::<serde_json::Value>::new(),
                        "info": Vec::<serde_json::Value>::new()
                    },
                    "analysis_results": {}
                })
            } else {
                json!(null)
            };

            if !lint_issues.is_empty() {

                let mut errors = Vec::new();
                let mut warnings = Vec::new();
                let mut infos = Vec::new();

                for issue in &lint_issues {
                    let issue_json = json!({
                        "file": cli.path,
                        "line": issue.line,
                        "column": issue.column,
                        "rule": issue.rule.name,
                        "message": issue.message
                    });

                    match issue.rule.severity {
                        LintSeverity::Error => errors.push(issue_json),
                        LintSeverity::Warning => warnings.push(issue_json),
                        LintSeverity::Info => infos.push(issue_json),
                    }
                }

                if cli.format == "json" {
                    if let Some(obj) = output.as_object_mut() {
                        if let Some(linting) = obj.get_mut("linting_issues") {
                            if let Some(linting_obj) = linting.as_object_mut() {
                                linting_obj.insert("errors".to_string(), json!(errors));
                                linting_obj.insert("warnings".to_string(), json!(warnings));
                                linting_obj.insert("info".to_string(), json!(infos));
                            }
                        }
                    }
                } else {
                    println!("\nLinting Issues:");
                    println!("---------------");
                    
                    if !errors.is_empty() {
                        println!("\nErrors:");
                        for issue in &errors {
                            println!("  {}:{}:{}: {} - {}", 
                                cli.path, issue["line"], issue["column"], 
                                issue["rule"], issue["message"]);
                        }
                    }

                    if !warnings.is_empty() {
                        println!("\nWarnings:");
                        for issue in &warnings {
                            println!("  {}:{}:{}: {} - {}", 
                                cli.path, issue["line"], issue["column"], 
                                issue["rule"], issue["message"]);
                        }
                    }

                    if !infos.is_empty() {
                        println!("\nInfo:");
                        for issue in &infos {
                            println!("  {}:{}:{}: {} - {}", 
                                cli.path, issue["line"], issue["column"], 
                                issue["rule"], issue["message"]);
                        }
                    }

                    println!("\nTotal issues: {} ({} errors, {} warnings, {} info)",
                        errors.len() + warnings.len() + infos.len(),
                        errors.len(), warnings.len(), infos.len());
                }
            }


            let analyzer = Analyzer::new(&cli.path, cli.checks.clone())?;
            let results = analyzer.analyze().await?;

            if cli.format == "json" {
                if let Some(obj) = output.as_object_mut() {
                    obj.insert("analysis_results".to_string(), json!({
                        "contract_name": results.contract_name,
                        "complexity": results.complexity,
                        "compatibility_issues": results.compatibility_issues,
                        "security_vulnerabilities": results.security_vulnerabilities,
                        "resource_usage": {
                            "ref_time": results.resource_usage.ref_time,
                            "proof_size": results.resource_usage.proof_size,
                            "storage_deposit": results.resource_usage.storage_deposit,
                            "storage_usage": results.resource_usage.storage_usage,
                            "stack_size": cli.stack_size.map(|s| s as u64),
                            "heap_size": cli.heap_size.map(|h| h as u64)
                        },
                        "best_practices": results.best_practices
                    }));
                }
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {

                if !results.compatibility_issues.is_empty() {
                    println!("\nCompatibility Issues:");
                    for issue in &results.compatibility_issues {
                        println!("- {}", issue);
                    }
                }

                if !results.security_vulnerabilities.is_empty() {
                    println!("\nSecurity Vulnerabilities:");
                    for vuln in &results.security_vulnerabilities {
                        println!("- {}", vuln);
                    }
                }

                println!("\nResource Usage Analysis:");
                println!("------------------------");
                

                println!("\n1. Resource Usage Estimation:");
                println!("   - Computation Time (ref_time): {} units", results.resource_usage.ref_time);
                println!("   - State Proof Size: {} bytes", format_bytes(results.resource_usage.proof_size));
                println!("   - Storage Deposit: {:.6} ETH", results.resource_usage.storage_deposit as f64 / 1e18);
                println!("   - Storage Usage: {} bytes", format_bytes(results.resource_usage.storage_usage));
                if let Some(stack_size) = cli.stack_size {
                    println!("   - Stack Size: {} bytes", format_bytes(stack_size as u64));
                }
                if let Some(heap_size) = cli.heap_size {
                    println!("   - Heap Size: {} bytes", format_bytes(heap_size as u64));
                }
                

                println!("\n2. Cost Implications:");
                let ref_time_price = 0.000000001;
                let proof_size_price = 0.0000000001;
                let eth_price = 2000.0;
                
                let ref_time_cost = results.resource_usage.ref_time as f64 * ref_time_price;
                let proof_size_cost = results.resource_usage.proof_size as f64 * proof_size_price;
                let total_cost_eth = ref_time_cost + proof_size_cost + (results.resource_usage.storage_deposit as f64 / 1e18);
                let total_cost_usd = total_cost_eth * eth_price;
                
                println!("   - Computation Cost: {:.6} ETH", ref_time_cost);
                println!("   - Proof Size Cost: {:.6} ETH", proof_size_cost);
                println!("   - Storage Deposit: {:.6} ETH", results.resource_usage.storage_deposit as f64 / 1e18);
                println!("   - Total Estimated Cost: {:.6} ETH (${:.2})", total_cost_eth, total_cost_usd);
                

                println!("\n3. Optimization Suggestions:");
                if results.resource_usage.ref_time > 1_000_000 {
                    println!("   ⚠️  High computation time detected. Consider:");
                    println!("      - Optimizing storage operations");
                    println!("      - Reducing external calls");
                    println!("      - Using more efficient data structures");
                }
                if results.resource_usage.proof_size > 100_000 {
                    println!("   ⚠️  Large proof size detected. Consider:");
                    println!("      - Reducing storage operations");
                    println!("      - Optimizing event emissions");
                    println!("      - Minimizing cross-contract calls");
                }
                if results.resource_usage.storage_usage > 100_000 {
                    println!("   ⚠️  High storage usage detected. Consider:");
                    println!("      - Using more compact data types");
                    println!("      - Implementing data compression");
                    println!("      - Using off-chain storage for large data");
                }
                if let Some(stack_size) = cli.stack_size {
                    if stack_size < 32768 {
                        println!("   ⚠️  Small stack size detected. Consider:");
                        println!("      - Increasing stack size to at least 32KB");
                        println!("      - Optimizing function call depth");
                        println!("      - Reducing local variable usage");
                    }
                }
                if let Some(heap_size) = cli.heap_size {
                    if heap_size < 65536 {
                        println!("   ⚠️  Small heap size detected. Consider:");
                        println!("      - Increasing heap size to at least 64KB");
                        println!("      - Optimizing memory allocations");
                        println!("      - Using more efficient data structures");
                    }
                }

                if !results.best_practices.is_empty() {
                    println!("\nBest Practices:");
                    for practice in &results.best_practices {
                        println!("- {}", practice);
                    }
                }

                if results.compatibility_issues.is_empty() && 
                   results.security_vulnerabilities.is_empty() && 
                   results.best_practices.is_empty() {
                    println!("\nNo issues found. Contract appears to be compatible with PolkaVM.");
                }
            }
        }
        Commands::ListChecks => {
            println!("Available analysis checks:");
            println!("\n1. compatibility - Checks for PolkaVM compatibility");
            println!("   - EVM-specific opcodes and instructions");
            println!("   - Assembly code compatibility");
            println!("   - PolkaVM-specific function calls (ecalli)");
            println!("   - Storage access patterns");
            
            println!("\n2. security - Performs security vulnerability analysis");
            println!("   - Reentrancy vulnerabilities");
            println!("   - Unchecked send/call");
            println!("   - Integer overflow");
            println!("   - Access control issues");
            println!("   - PolkaVM-specific security considerations");
            
            println!("\n3. resources - Estimates resource usage");
            println!("   - Stack memory usage");
            println!("   - Heap memory usage");
            println!("   - Contract size");
            println!("   - Gas cost estimation");
            println!("   - Storage requirements");
            
            println!("\n4. best-practices - Validates Solidity best practices");
            println!("   - Compiler version specification");
            println!("   - Input validation");
            println!("   - Event emission");
            println!("   - Access control modifiers");
            println!("   - PolkaVM-specific optimizations");
        }
        Commands::CheckInfo { check_name } => {
            match check_name.as_str() {
                "compatibility" => {
                    println!("Compatibility Check:");
                    println!("Analyzes the contract for features that might not work in PolkaVM.");
                    println!("\nChecks for:");
                    println!("- EVM-specific opcodes and instructions");
                    println!("- Assembly code compatibility with RISC-V");
                    println!("- PolkaVM-specific function calls (ecalli)");
                    println!("- Storage access patterns and compatibility");
                    println!("- Contract deployment and initialization");
                    println!("- Constructor arguments handling");
                }
                "security" => {
                    println!("Security Analysis:");
                    println!("Performs static analysis to detect common vulnerabilities.");
                    println!("\nChecks for:");
                    println!("- Reentrancy vulnerabilities");
                    println!("- Unchecked send/call operations");
                    println!("- Integer overflow/underflow");
                    println!("- Access control issues");
                    println!("- PolkaVM-specific security considerations");
                    println!("- Storage access patterns");
                    println!("- Memory management issues");
                }
                "resources" => {
                    println!("Resource Usage Analysis:");
                    println!("Estimates contract resource consumption.");
                    println!("\nAnalyzes:");
                    println!("- Stack memory usage (default: 32768 bytes)");
                    println!("- Heap memory usage (default: 65536 bytes)");
                    println!("- Contract size and complexity");
                    println!("- Gas cost estimation");
                    println!("- Storage requirements");
                    println!("- Memory access patterns");
                }
                "best-practices" => {
                    println!("Best Practices Validation:");
                    println!("Checks for adherence to Solidity best practices.");
                    println!("\nValidates:");
                    println!("- Compiler version specification");
                    println!("- Input validation and sanitization");
                    println!("- Event emission and logging");
                    println!("- Access control modifiers");
                    println!("- PolkaVM-specific optimizations");
                    println!("- Memory management best practices");
                }
                _ => println!("Unknown check: {}", check_name),
            }
        }
        Commands::Disassemble => {
            if !fs::metadata(&cli.path)?.is_file() {
                return Err(anyhow::anyhow!("Contract file not found: {}", cli.path));
            }

            println!("Disassembling contract: {}", cli.path);
            

            let solc_output = Command::new("solc")
                .args(["--bin", "--optimize"])
                .arg(&cli.path)
                .output()?;

            if !solc_output.status.success() {
                return Err(anyhow::anyhow!("Failed to compile Solidity: {}", 
                    String::from_utf8_lossy(&solc_output.stderr)));
            }


            let stdout = String::from_utf8_lossy(&solc_output.stdout);
            let bytecode = stdout
                .lines()
                .find(|line| line.starts_with("Binary:"))
                .ok_or_else(|| anyhow::anyhow!("No bytecode found in solc output"))?
                .trim_start_matches("Binary:")
                .trim()
                .to_string();


            let temp_bytecode = format!("{}.bin", cli.path);
            fs::write(&temp_bytecode, bytecode)?;


            let polkavm_output = format!("{}.polkavm", cli.path);
            let resolc_output = Command::new("resolc")
                .arg(&cli.path)
                .arg("--bin")
                .arg("-O3")
                .arg("--output-dir")
                .arg(".")
                .output()?;

            if !resolc_output.status.success() {
                return Err(anyhow::anyhow!("Failed to translate to PolkaVM: {}", 
                    String::from_utf8_lossy(&resolc_output.stderr)));
            }


            let _polkavm_bytecode = fs::read_to_string(&polkavm_output)?;


            let output = Command::new("polkatool")
                .arg("disassemble")
                .arg(&format!("{}.polkavm", cli.path))
                .output()?;

            if !output.status.success() {
                return Err(anyhow::anyhow!("Failed to disassemble: {}", 
                    String::from_utf8_lossy(&output.stderr)));
            }

            let disassembly = String::from_utf8_lossy(&output.stdout);
            

            let mut in_code_section = false;
            let mut current_section = String::new();
            let mut entry_points = Vec::new();
            let mut system_calls = Vec::new();
            let mut memory_usage = (0, 0, 0); // (ro_data, rw_data, stack_size)
            
            println!("\nPolkaVM Contract Disassembly");
            println!("===========================");
            
            for line in disassembly.lines() {
                if line.starts_with("//") {

                    if line.contains("RO data") {
                        let parts: Vec<&str> = line.split('=').collect();
                        if parts.len() > 1 {
                            memory_usage.0 = parts[1].trim().split('/').next()
                                .and_then(|s| s.trim().parse().ok())
                                .unwrap_or(0);
                        }
                    } else if line.contains("RW data") {
                        let parts: Vec<&str> = line.split('=').collect();
                        if parts.len() > 1 {
                            memory_usage.1 = parts[1].trim().split('/').next()
                                .and_then(|s| s.trim().parse().ok())
                                .unwrap_or(0);
                        }
                    } else if line.contains("Stack size") {
                        let parts: Vec<&str> = line.split('=').collect();
                        if parts.len() > 1 {
                            memory_usage.2 = parts[1].trim().split_whitespace().next()
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(0);
                        }
                    }
                    println!("\n{}", line);
                } else if line.contains("[export") {

                    entry_points.push(line.trim().to_string());
                    println!("\n{}", line);
                } else if line.starts_with("  : @") {

                    if in_code_section {
                        println!("\n{}", current_section);
                        current_section.clear();
                    }
                    in_code_section = true;
                    current_section.push_str(&format!("\nSection {}", line.trim()));
                } else if in_code_section {

                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let addr = parts[0];
                        let instr = parts[1..].join(" ");
                        current_section.push_str(&format!("\n  {:<8} {}", addr, instr));
                        

                        if instr.contains("ecalli") {
                            let syscall_num = instr.split_whitespace()
                                .nth(1)
                                .and_then(|s| s.parse::<u32>().ok())
                                .unwrap_or(0);
                            system_calls.push((addr.to_string(), syscall_num));
                            current_section.push_str(" // System call to pallet_revive");
                        }
                    }
                }
            }
            

            if !current_section.is_empty() {
                println!("{}", current_section);
            }


            println!("\nContract Analysis Summary");
            println!("=======================");
            println!("\nMemory Usage:");
            println!("  - Read-Only Data: {} bytes", format_bytes(memory_usage.0 as u64));
            println!("  - Read-Write Data: {} bytes", format_bytes(memory_usage.1 as u64));
            println!("  - Stack Size: {} bytes", format_bytes(memory_usage.2 as u64));
            
            println!("\nEntry Points:");
            for entry in entry_points {
                println!("  - {}", entry);
            }
            
            if !system_calls.is_empty() {
                println!("\nSystem Calls (pallet_revive):");
                for (addr, num) in system_calls {
                    println!("  - Address {}: System call #{}", addr, num);
                }
            }


            fs::remove_file(temp_bytecode)?;
            fs::remove_file(format!("{}.polkavm", cli.path))?;
            
            println!("\nDisassembly complete. Note: 'ecalli' instructions indicate system calls to pallet_revive.");
            println!("For more information about system calls, refer to the pallet_revive documentation.");
        }
        Commands::MemoryAnalysis => {
            if !fs::metadata(&cli.path)?.is_file() {
                return Err(anyhow::anyhow!("Contract file not found: {}", cli.path));
            }
            
            println!("Analyzing memory usage for contract: {}", cli.path);
            

            let source = fs::read_to_string(&cli.path)?;
            

            let function_count = source.matches("function").count();
            let state_vars = source.matches("uint").count() +
                           source.matches("bool").count() * 2 +
                           source.matches("address").count() * 3 +
                           source.matches("bytes").count() * 32 +
                           source.matches("string").count() * 32;
            
            let array_declarations = source.matches("[").count();
            let dynamic_arrays = source.matches("[]").count();
            

            let stack_usage = cli.stack_size.unwrap_or(32768) as usize;
            let heap_usage = cli.heap_size.unwrap_or(65536) as usize;
            let total_memory = stack_usage + heap_usage;
            

            let large_arrays = source.lines()
                .filter(|line| line.contains("["))
                .filter(|line| {
                    if let Some(size) = line.split('[').nth(1).and_then(|s| s.split(']').next()) {
                        size.parse::<usize>().map(|n| n > 1000).unwrap_or(false)
                    } else {
                        false
                    }
                })
                .count();
            
            println!("\nMemory Analysis Results:");
            println!("------------------------");
            

            println!("\n1. Memory Configuration:");
            println!("   - Stack size: {} bytes (used for function calls and local variables)", format_bytes(stack_usage as u64));
            println!("   - Heap size: {} bytes (used for dynamic memory allocation)", format_bytes(heap_usage as u64));
            println!("   - Total available memory: {} bytes", format_bytes(total_memory as u64));
            

            println!("\n2. Contract Structure:");
            println!("   - Number of functions: {}", function_count);
            println!("   - State variables: {} (estimated {} bytes)", state_vars, format_bytes((state_vars * 32) as u64));
            println!("   - Array declarations: {}", array_declarations);
            println!("   - Dynamic arrays: {}", dynamic_arrays);
            

            println!("\n3. Memory Usage Analysis:");
            let estimated_stack_per_function = 1024; // Rough estimate of stack usage per function
            let total_estimated_stack = function_count * estimated_stack_per_function;
            println!("   - Estimated stack usage: {} bytes ({} bytes per function)", 
                    format_bytes(total_estimated_stack as u64), format_bytes(estimated_stack_per_function as u64));
            
            let estimated_heap = (state_vars * 32) + (dynamic_arrays * 64);
            println!("   - Estimated heap usage: {} bytes", format_bytes(estimated_heap as u64));
            

            println!("\n4. Potential Memory Issues:");
            if large_arrays > 0 {
                println!("   ⚠️  Found {} large fixed-size arrays (may exceed memory limits)", large_arrays);
            }
            if dynamic_arrays > 0 {
                println!("   ⚠️  Found {} dynamic arrays (requires careful memory management)", dynamic_arrays);
            }
            if total_estimated_stack > stack_usage {
                let stack_usage_str = format_bytes(stack_usage as u64);
                let total_stack_str = format_bytes(total_estimated_stack as u64);
                println!("   ⚠️  Estimated stack usage ({}) exceeds configured stack size ({})", 
                    total_stack_str, stack_usage_str);
            }
            if estimated_heap > heap_usage {
                let heap_usage_str = format_bytes(heap_usage as u64);
                let total_heap_str = format_bytes(estimated_heap as u64);
                println!("   ⚠️  Estimated heap usage ({}) exceeds configured heap size ({})", 
                    total_heap_str, heap_usage_str);
            }
            

            println!("\n5. Recommendations:");
            println!("   - Consider using smaller fixed-size arrays where possible");
            println!("   - Implement proper memory cleanup for dynamic arrays");
            println!("   - Monitor stack usage in recursive functions");
            println!("   - Use storage instead of memory for large data structures");
            println!("   - Consider implementing pagination for large data sets");
            

            println!("\n6. PolkaVM-Specific Notes:");
            println!("   - PolkaVM has a fixed memory model (unlike EVM's gas-based model)");
            println!("   - Memory operations are more expensive in PolkaVM");
            println!("   - Consider using storage for data that doesn't need frequent updates");
            println!("   - Implement proper error handling for out-of-memory scenarios");
            
            println!("\nNote: These are estimates based on static analysis. Actual memory usage may vary during execution.");
            // println!("      Use --stack-size and --heap-size options to adjust memory limits if needed.");
        }
    }
    Ok(())
} 