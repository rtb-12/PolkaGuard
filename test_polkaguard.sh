#!/bin/bash

# Test initialization
echo "Testing init..."
polkaguard --path ./contracts init
polkaguard --path ./contracts init --config-path ./config/polkaguard.toml

# Test analysis
echo "Testing analyze..."
polkaguard --path ./contracts/MyContract.sol analyze
polkaguard --path ./contracts/MyContract.sol analyze --checks compatibility,security
polkaguard --path ./contracts/MyContract.sol analyze --format json
polkaguard --path ./contracts/MyContract.sol analyze --stack-size 65536 --heap-size 131072

# Test list checks
echo "Testing list-checks..."
polkaguard --path ./contracts list-checks

# Test check info
echo "Testing check-info..."
polkaguard --path ./contracts check-info compatibility
polkaguard --path ./contracts check-info security
polkaguard --path ./contracts check-info resources
polkaguard --path ./contracts check-info best-practices

# Test disassemble
echo "Testing disassemble..."
polkaguard --path ./contracts/MyContract.sol disassemble

# Test memory analysis
echo "Testing memory-analysis..."
polkaguard --path ./contracts/MyContract.sol memory-analysis
polkaguard --path ./contracts/MyContract.sol memory-analysis --stack-size 65536 --heap-size 131072

# Test help and version
echo "Testing help and version..."
polkaguard --help
polkaguard --version