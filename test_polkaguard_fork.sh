#!/bin/bash

# Simple PolkaGuard Fork Mode Test
# Exactly matches the user's requested command

set -e

echo "🌟 PolkaGuard PolkaVM Fork Mode Simple Test"
echo "═══════════════════════════════════════════"
echo

# Create test directory and run the exact command
echo "📁 Creating test directory..."
cd /tmp
mkdir -p polkaguard-fork-test
cd polkaguard-fork-test

echo "🚀 Running PolkaGuard fork mode test..."
echo "Command: /home/rtb/Developer/PolkaGuardOrg/PolkaGuard/target/debug/polkaguard --path . run-fork --auto-install"
echo

# Run the exact command
/home/rtb/Developer/PolkaGuardOrg/PolkaGuard/target/debug/polkaguard --path . run-fork --auto-install

echo
echo "✅ Test completed!"
echo "📁 Test directory: /tmp/polkaguard-fork-test"
echo "🧹 Clean up: rm -rf /tmp/polkaguard-fork-test"
