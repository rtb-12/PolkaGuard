#!/bin/bash

# Colors for better output formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print section headers
print_header() {
    echo -e "\n${BLUE}================================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${BLUE}================================================${NC}\n"
}

# Function to print test descriptions
print_test() {
    echo -e "${YELLOW}→ $1${NC}"
    echo -e "${PURPLE}Command: $2${NC}"
    echo ""
}

# Function to print separators
print_separator() {
    echo -e "\n${GREEN}------------------------------------------------${NC}\n"
}

print_header "🚀 PolkaGuard CLI Testing Suite"

# Test initialization
print_header "📋 INITIALIZATION TESTS"

print_test "Test 1: Initialize with default config" "polkaguard --path ./contracts init"
polkaguard --path ./contracts init
print_separator

print_test "Test 2: Initialize with custom config path" "polkaguard --path ./contracts init --config-path ./config/polkaguard.toml"
polkaguard --path ./contracts init --config-path ./config/polkaguard.toml
print_separator

# Test analysis
print_header "🔍 ANALYSIS TESTS"

print_test "Test 3: Basic contract analysis" "polkaguard --path ./contracts/MyContract.sol analyze"
polkaguard --path ./contracts/MyContract.sol analyze
print_separator

print_test "Test 4: Selective checks (compatibility + security)" "polkaguard --path ./contracts/MyContract.sol --checks compatibility,security analyze"
polkaguard --path ./contracts/MyContract.sol --checks compatibility,security analyze
print_separator

print_test "Test 5: Analysis with Polkadot network" "polkaguard --path ./contracts/MyContract.sol --network polkadot analyze"
polkaguard --path ./contracts/MyContract.sol --network polkadot analyze
print_separator

print_test "Test 6: Analysis with Kusama network" "polkaguard --path ./contracts/MyContract.sol --network kusama analyze"
polkaguard --path ./contracts/MyContract.sol --network kusama analyze
print_separator

print_test "Test 7: Analysis with Westend testnet" "polkaguard --path ./contracts/MyContract.sol --network westend analyze"
polkaguard --path ./contracts/MyContract.sol --network westend analyze
print_separator

print_test "Test 8: Analysis with Local development network" "polkaguard --path ./contracts/MyContract.sol --network local analyze"
polkaguard --path ./contracts/MyContract.sol --network local analyze
print_separator

print_test "Test 9: JSON output format" "polkaguard --path ./contracts/MyContract.sol --format json analyze"
polkaguard --path ./contracts/MyContract.sol --format json analyze
print_separator

print_test "Test 10: JSON output with network cost breakdown" "polkaguard --path ./contracts/MyContract.sol --network polkadot --format json analyze"
polkaguard --path ./contracts/MyContract.sol --network polkadot --format json analyze
print_separator

print_test "Test 11: Analysis with custom memory limits" "polkaguard --path ./contracts/MyContract.sol --stack-size 65536 --heap-size 131072 analyze"
polkaguard --path ./contracts/MyContract.sol --stack-size 65536 --heap-size 131072 analyze
print_separator

# Test list checks
print_header "📝 CHECK LISTING TESTS"

print_test "Test 12: List all available checks" "polkaguard --path ./contracts list-checks"
polkaguard --path ./contracts list-checks
print_separator

# Test check info
print_header "ℹ️  CHECK INFORMATION TESTS"

print_test "Test 13: Compatibility check info" "polkaguard --path ./contracts check-info compatibility"
polkaguard --path ./contracts check-info compatibility
print_separator

print_test "Test 13: Security check info" "polkaguard --path ./contracts check-info security"
polkaguard --path ./contracts check-info security
print_separator

print_test "Test 14: Resources check info" "polkaguard --path ./contracts check-info resources"
polkaguard --path ./contracts check-info resources
print_separator

print_test "Test 15: Best practices check info" "polkaguard --path ./contracts check-info best-practices"
polkaguard --path ./contracts check-info best-practices
print_separator

# Test disassemble
print_header "⚙️  DISASSEMBLY TESTS"

print_test "Test 16: Contract disassembly (with overwrite)" "polkaguard --path ./contracts/MyContract.sol --overwrite disassemble"
polkaguard --path ./contracts/MyContract.sol --overwrite disassemble
print_separator

# Test memory analysis
print_header "🧠 MEMORY ANALYSIS TESTS"

print_test "Test 17: Basic memory analysis" "polkaguard --path ./contracts/MyContract.sol memory-analysis"
polkaguard --path ./contracts/MyContract.sol memory-analysis
print_separator

print_test "Test 18: Memory analysis with custom limits" "polkaguard --path ./contracts/MyContract.sol --stack-size 65536 --heap-size 131072 memory-analysis"
polkaguard --path ./contracts/MyContract.sol --stack-size 65536 --heap-size 131072 memory-analysis
print_separator

# Test help and version
print_header "❓ HELP & VERSION TESTS"

print_test "Test 19: Display help information" "polkaguard --help"
polkaguard --help
print_separator

print_test "Test 20: Display version information" "polkaguard --version"
polkaguard --version
print_separator

# Test network cost comparison
print_header "💰 NETWORK COST COMPARISON"

print_test "Test 21: Cost comparison across networks" "echo 'Comparing costs across different networks:'"
echo 'Comparing costs across different networks:'
echo -e "${YELLOW}→ Polkadot mainnet:${NC}"
polkaguard --path ./contracts/MyContract.sol --network polkadot analyze | grep -A 15 "Cost Implications"
echo -e "${YELLOW}→ Kusama:${NC}"
polkaguard --path ./contracts/MyContract.sol --network kusama analyze | grep -A 15 "Cost Implications"
echo -e "${YELLOW}→ Westend testnet:${NC}"
polkaguard --path ./contracts/MyContract.sol --network westend analyze | grep -A 15 "Cost Implications"
print_separator

print_header "✅ Testing Complete!"