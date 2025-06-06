# Network Guide

PolkaGuard supports multi-network cost calculations across the Polkadot ecosystem. This guide explains network configurations, cost methodologies, and practical usage patterns.

## 🌐 Supported Networks

### Mainnet Networks

#### Polkadot (DOT)

- **Purpose**: Primary mainnet with highest security
- **Token**: DOT (10 decimals)
- **Cost Calculation**: Real USD values based on DOT price
- **Storage Deposit**: 1,000,000,000 plancks per byte (highest cost)
- **Use Case**: Production deployments with accurate cost estimation

```bash
polkaguard --path contract.sol --network polkadot analyze
```

#### Kusama (KSM)

- **Purpose**: Canary network for testing cutting-edge features
- **Token**: KSM (12 decimals)
- **Cost Calculation**: Real USD values based on KSM price
- **Storage Deposit**: 100,000,000 plancks per byte
- **Use Case**: Pre-production testing with realistic costs

```bash
polkaguard --path contract.sol --network kusama analyze
```

### Testnet Networks

#### Westend (WND)

- **Purpose**: Polkadot testnet for stable testing
- **Token**: WND (12 decimals, no USD value)
- **Cost Calculation**: Token amounts only
- **Storage Deposit**: 100,000,000 plancks per byte
- **Use Case**: Development and testing without real costs

```bash
polkaguard --path contract.sol --network westend analyze
```

#### Rococo (ROC)

- **Purpose**: Polkadot testnet for parachain testing
- **Token**: ROC (12 decimals, no USD value)
- **Cost Calculation**: Token amounts only
- **Storage Deposit**: 100,000,000 plancks per byte
- **Use Case**: Parachain and cross-chain feature testing

```bash
polkaguard --path contract.sol --network rococo analyze
```

### Development Network

#### Local (UNIT)

- **Purpose**: Local development environment
- **Token**: UNIT (12 decimals, no USD value)
- **Cost Calculation**: Token amounts only
- **Storage Deposit**: 100,000,000 plancks per byte
- **Use Case**: Local development and unit testing

```bash
polkaguard --path contract.sol --network local analyze
```

## 💰 Cost Calculation Methodology

### Cost Components

Each network calculates three types of costs:

1. **ref_time Cost**: Computational time units
2. **proof_size Cost**: State proof size in bytes
3. **Storage Deposit**: Persistent storage requirements

### Calculation Formula

```
Total Cost = ref_time_cost + proof_size_cost + storage_deposit
```

Where:

- `ref_time_cost = ref_time_units × network.ref_time_price_per_unit`
- `proof_size_cost = proof_size_bytes × network.proof_size_price_per_byte`
- `storage_deposit = storage_bytes × network.storage_deposit_per_byte`

### Network-Specific Pricing

| Component                      | Polkadot      | Kusama      | Westend     | Rococo      | Local       |
| ------------------------------ | ------------- | ----------- | ----------- | ----------- | ----------- |
| ref_time (plancks/unit)        | 100           | 100         | 100         | 100         | 100         |
| proof_size (plancks/byte)      | 1,000         | 1,000       | 1,000       | 1,000       | 1,000       |
| storage_deposit (plancks/byte) | 1,000,000,000 | 100,000,000 | 100,000,000 | 100,000,000 | 100,000,000 |

### Plancks to Token Conversion

Each network uses different decimal places:

```rust
// Polkadot: 10 decimals
1 DOT = 10^10 plancks = 10,000,000,000 plancks

// Others: 12 decimals
1 KSM = 10^12 plancks = 1,000,000,000,000 plancks
1 WND = 10^12 plancks = 1,000,000,000,000 plancks
1 ROC = 10^12 plancks = 1,000,000,000,000 plancks
1 UNIT = 10^12 plancks = 1,000,000,000,000 plancks
```

## 📊 Cost Comparison Examples

### Sample Contract Analysis

Consider a contract with:

- ref_time: 36,000 units
- proof_size: 1,400 bytes
- storage: 0 bytes

#### Polkadot Network

```
- Computation Cost: 0.000360 DOT (3,600,000 plancks)
- Proof Size Cost: 0.000140 DOT (1,400,000 plancks)
- Storage Deposit: 0.000000 DOT (0 plancks)
- Total: 0.000500 DOT (≈ $0.0035 USD)
```

#### Kusama Network

```
- Computation Cost: 0.000036 KSM (36,000,000 plancks)
- Proof Size Cost: 0.000014 KSM (14,000,000 plancks)
- Storage Deposit: 0.000000 KSM (0 plancks)
- Total: 0.000050 KSM (≈ $0.00125 USD)
```

#### Westend Network

```
- Computation Cost: 0.000036 WND (36,000,000 plancks)
- Proof Size Cost: 0.000014 WND (14,000,000 plancks)
- Storage Deposit: 0.000000 WND (0 plancks)
- Total: 0.000050 WND (testnet - no USD value)
```

### Storage-Heavy Contract Example

Contract with significant storage:

- ref_time: 50,000 units
- proof_size: 2,000 bytes
- storage: 1,000 bytes

#### Polkadot vs Kusama Storage Costs

**Polkadot** (higher storage deposit):

```
- Storage Deposit: 1.000000 DOT (1,000,000,000,000 plancks)
- Total: 1.000700 DOT (≈ $7.005 USD)
```

**Kusama** (lower storage deposit):

```
- Storage Deposit: 0.100000 KSM (100,000,000,000 plancks)
- Total: 0.100064 KSM (≈ $2.502 USD)
```

## 🚀 Practical Usage Patterns

### Development Workflow

1. **Local Development**: Start with local network

```bash
polkaguard --path contract.sol --network local analyze
```

2. **Testnet Testing**: Move to Westend for realistic environment

```bash
polkaguard --path contract.sol --network westend analyze
```

3. **Pre-production**: Test on Kusama for real cost estimation

```bash
polkaguard --path contract.sol --network kusama analyze
```

4. **Production**: Deploy on Polkadot with final cost validation

```bash
polkaguard --path contract.sol --network polkadot analyze
```

### Cost Optimization Strategy

#### Compare Across Networks

```bash
# Quick cost comparison script
echo "=== Cost Comparison ==="
echo "Polkadot:"
polkaguard --path contract.sol --network polkadot analyze | grep "Total Estimated Cost"
echo "Kusama:"
polkaguard --path contract.sol --network kusama analyze | grep "Total Estimated Cost"
echo "Westend:"
polkaguard --path contract.sol --network westend analyze | grep "Total Estimated Cost"
```

#### JSON Output for Analysis

```bash
# Export costs for automated analysis
polkaguard --path contract.sol --network polkadot --format json analyze > polkadot_costs.json
polkaguard --path contract.sol --network kusama --format json analyze > kusama_costs.json
```

### Batch Network Analysis

```bash
#!/bin/bash
# analyze_all_networks.sh

CONTRACT_PATH="$1"
NETWORKS=("polkadot" "kusama" "westend" "rococo" "local")

echo "🌐 Multi-Network Analysis for: $CONTRACT_PATH"
echo "================================================"

for network in "${NETWORKS[@]}"; do
    echo -e "\n📊 $network Network:"
    polkaguard --path "$CONTRACT_PATH" --network "$network" analyze | grep -A 10 "Cost Implications"
done
```

## 🔧 Advanced Network Features

### Custom Network Configuration

While built-in networks cover most use cases, you can reference network configurations for understanding:

```rust
// Understanding network configuration structure
pub struct NetworkConfig {
    pub name: String,
    pub token_symbol: String,
    pub token_decimals: u8,
    pub ref_time_price_per_unit: u64,
    pub proof_size_price_per_byte: u64,
    pub storage_deposit_per_byte: u64,
    pub token_price_usd: f64,
}
```

### Network-Specific Output Formatting

Each network provides detailed cost breakdowns:

```bash
# Example: Detailed Polkadot output
Network: Polkadot (DOT)
- Computation Cost: 0.000360 DOT (3600000 plancks)
- Proof Size Cost: 0.000140 DOT (1400000 plancks)
- Storage Deposit: 0.000000 DOT (0 plancks)
- Total Estimated Cost: 0.000500 DOT (≈ $0.00 USD)

📊 Cost Calculation Methodology:
  • ref_time: 36000 units × 100 plancks/unit = 3600000 plancks
  • proof_size: 1400 bytes × 1000 plancks/byte = 1400000 plancks
  • storage_deposit: 0 bytes × 1000000000 plancks/byte = 0 plancks
  • 1 DOT = 10^10 plancks
```

## 📈 Cost Trends and Monitoring

### Price Volatility Considerations

Token prices fluctuate, affecting USD estimates:

| Token    | Typical Range | Impact                                      |
| -------- | ------------- | ------------------------------------------- |
| DOT      | $4-12 USD     | High volatility affects production planning |
| KSM      | $15-40 USD    | Higher price but lower storage deposits     |
| Testnets | $0 USD        | No financial impact                         |

### Monitoring Best Practices

1. **Regular Cost Checks**: Monitor costs during development
2. **Network Comparison**: Compare costs before deployment decisions
3. **Storage Optimization**: Consider storage usage for cost reduction
4. **Price Tracking**: Monitor token prices for production planning

## 🛡️ Security Considerations

### Network-Specific Security Levels

| Network  | Security Level | Finality    | Validator Count |
| -------- | -------------- | ----------- | --------------- |
| Polkadot | Highest        | ~60 seconds | 297+            |
| Kusama   | High           | ~60 seconds | 1000+           |
| Westend  | Medium         | ~60 seconds | Variable        |
| Rococo   | Medium         | ~60 seconds | Variable        |
| Local    | Low            | Instant     | 1               |

### Deployment Recommendations

- **Production contracts**: Polkadot mainnet only
- **Testing contracts**: Start with testnets, validate on Kusama
- **Development**: Local network for rapid iteration

## 🔮 Future Network Support

PolkaGuard is designed to easily support additional networks:

- **Parachains**: Individual parachain networks
- **Custom Networks**: Enterprise or private networks
- **Layer 2 Solutions**: Scaling solutions on Polkadot

Network configuration can be extended to support new ecosystems as they emerge in the Polkadot ecosystem.
