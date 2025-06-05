use anyhow::Result;

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct LintRule {
    pub name: String,
    pub description: String,
    pub severity: LintSeverity,
    pub category: LintCategory,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LintSeverity {
    Error,
    Warning,
    Info,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub enum LintCategory {
    Style,
    Security,
    Performance,
    PolkaVM,
}

#[derive(Debug, Clone)]
pub struct LintIssue {
    pub rule: LintRule,
    pub line: usize,
    pub column: usize,
    pub message: String,
}

pub struct Linter {
    rules: Vec<LintRule>,
    config: LinterConfig,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct LinterConfig {
    pub max_line_length: usize,
    pub require_pragma: bool,
    pub require_license: bool,
    pub require_version: bool,
    pub require_visibility: bool,
    pub require_events: bool,
    pub require_natspec: bool,
}

impl Default for LinterConfig {
    fn default() -> Self {
        Self {
            max_line_length: 120,
            require_pragma: true,
            require_license: true,
            require_version: true,
            require_visibility: true,
            require_events: true,
            require_natspec: true,
        }
    }
}

impl Linter {
    pub fn new(config: LinterConfig) -> Self {
        let rules = vec![
            LintRule {
                name: "max-line-length".to_string(),
                description: "Lines should not exceed maximum length".to_string(),
                severity: LintSeverity::Warning,
                category: LintCategory::Style,
            },
            LintRule {
                name: "pragma-directive".to_string(),
                description: "Contract should specify compiler version".to_string(),
                severity: LintSeverity::Error,
                category: LintCategory::Style,
            },
            LintRule {
                name: "license-identifier".to_string(),
                description: "Contract should include license identifier".to_string(),
                severity: LintSeverity::Warning,
                category: LintCategory::Style,
            },
            LintRule {
                name: "function-visibility".to_string(),
                description: "Functions should have explicit visibility".to_string(),
                severity: LintSeverity::Warning,
                category: LintCategory::Security,
            },
            LintRule {
                name: "event-emission".to_string(),
                description: "State changes should emit events".to_string(),
                severity: LintSeverity::Info,
                category: LintCategory::Style,
            },
            LintRule {
                name: "natspec-comments".to_string(),
                description: "Public functions should have NatSpec comments".to_string(),
                severity: LintSeverity::Info,
                category: LintCategory::Style,
            },
        ];

        Self { rules, config }
    }

    pub fn lint(&self, source: &str) -> Result<Vec<LintIssue>> {
        let mut issues = Vec::new();
        let lines: Vec<&str> = source.lines().collect();


        for (i, line) in lines.iter().enumerate() {
            if line.len() > self.config.max_line_length {
                issues.push(LintIssue {
                    rule: self.rules[0].clone(),
                    line: i + 1,
                    column: self.config.max_line_length + 1,
                    message: format!("Line exceeds maximum length of {} characters", self.config.max_line_length),
                });
            }
        }


        if self.config.require_pragma && !source.contains("pragma solidity") {
            issues.push(LintIssue {
                rule: self.rules[1].clone(),
                line: 1,
                column: 1,
                message: "Missing pragma directive".to_string(),
            });
        }


        if self.config.require_license && !source.contains("SPDX-License-Identifier") {
            issues.push(LintIssue {
                rule: self.rules[2].clone(),
                line: 1,
                column: 1,
                message: "Missing license identifier".to_string(),
            });
        }


        if self.config.require_visibility {
            for (i, line) in lines.iter().enumerate() {
                if line.contains("function") && !line.contains("public") && !line.contains("private") 
                   && !line.contains("internal") && !line.contains("external") {
                    issues.push(LintIssue {
                        rule: self.rules[3].clone(),
                        line: i + 1,
                        column: line.find("function").unwrap_or(0) + 1,
                        message: "Function missing visibility modifier".to_string(),
                    });
                }
            }
        }


        if self.config.require_events {
            let state_changes = ["mapping", "uint", "bool", "address", "string", "bytes"];
            for (i, line) in lines.iter().enumerate() {
                if state_changes.iter().any(|&change| line.contains(change)) {
                    let has_event = lines.iter().any(|l| l.contains("event"));
                    if !has_event {
                        issues.push(LintIssue {
                            rule: self.rules[4].clone(),
                            line: i + 1,
                            column: 1,
                            message: "State changes should emit events".to_string(),
                        });
                    }
                }
            }
        }

        
        if self.config.require_natspec {
            for (i, line) in lines.iter().enumerate() {
                if line.contains("function") && line.contains("public") {
                    let has_natspec = lines.iter().any(|l| l.contains("///"));
                    if !has_natspec {
                        issues.push(LintIssue {
                            rule: self.rules[5].clone(),
                            line: i + 1,
                            column: 1,
                            message: "Public function missing NatSpec documentation".to_string(),
                        });
                    }
                }
            }
        }

        Ok(issues)
    }
} 