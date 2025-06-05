use anyhow::Result;
use std::path::Path;
use walkdir::WalkDir;

#[allow(dead_code)]
pub fn find_solidity_files(path: &str) -> Result<Vec<String>> {
    let mut files = Vec::new();
    
    for entry in WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.path().extension().map_or(false, |ext| ext == "sol") {
            files.push(entry.path().to_string_lossy().into_owned());
        }
    }
    
    Ok(files)
}

#[allow(dead_code)]
pub fn is_valid_solidity_file(path: &Path) -> bool {
    path.extension().map_or(false, |ext| ext == "sol")
}

#[allow(dead_code)]
pub fn extract_contract_name(source: &str) -> Option<String> {
    // Simple regex to find contract name
    let re = regex::Regex::new(r"contract\s+(\w+)").ok()?;
    re.captures(source)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}

#[allow(dead_code)]
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    format!("{:.2} {}", size, UNITS[unit_index])
}

#[allow(dead_code)]
pub fn calculate_complexity(source: &str) -> u32 {
    // Simple cyclomatic complexity calculation
    let control_flow_keywords = [
        "if", "else", "for", "while", "do", "switch", "case",
        "catch", "&&", "||", "?", ":", "return"
    ];
    
    control_flow_keywords.iter()
        .map(|keyword| source.matches(keyword).count() as u32)
        .sum()
} 