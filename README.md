# Long-Term Integrity Verification System

A Java Spring Boot application for testing and comparing file integrity verification methods:

- Evidence Records
- Advanced Electronic Signatures
- Raft-based Distributed System
- Ethereum Blockchain Hash Anchoring

## Run

```
./mvnw spring-boot:run
```

## Ethereum Blockchain Setup

This guide sets up a local Ethereum test node to deploy the `FileIntegrity` smart contract using Hardhat.

### Prerequisites

- Node.js 18+ installed globally

---

### 1. Clone the Deployment Project

Hardhat requires a local installation and does not support global installs. Clone the deployment project from `https://github.com/Turtoise1/integrity-hardhat-deployment`.

```bash
git clone git@github.com:Turtoise1/integrity-hardhat-deployment.git
```

Install node dependencies with pnpm.

```bash
cd integrity-hardhat-deployment
pnpm ci
```

---

### 2. Start the Local Ethereum Node

Open a terminal and keep it running:

```bash
npx hardhat node
```

Hardhat will print 20 test accounts with their private keys.

Example output:

```
Account #0:  0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266 (10000 ETH)
Private Key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
```

Add one of the private keys in the `application.properties` file to the key `blockchain.deployer.private-key`.

```properties
# Ethereum blockchain configuration
blockchain.deployer.private-key=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
```

---

### 3. Compile and Deploy the Contract

Deploy the contract:

```bash
pnpm hardhat ignition deploy ignition/modules/FileIntegrity.ts --network localhost
```

The console will print the deployed contract address, for example:

```
Deployed Addresses

FileIntegrityModule#FileIntegrity - 0x5FbDB2315678afecb367f032d93F642f64180aa3
```

Add the address to the blockchain configuration in `application.properties`:

```properties
# Ethereum blockchain configuration
blockchain.contract.address=0x5FbDB2315678afecb367f032d93F642f64180aa3
```

---

### Restarting the Node

The Hardhat node does not persist state between restarts. If you stop and restart it, you must redeploy the contract (step 3) and update `blockchain.contract.address` in `application.properties` with the new address. The private keys remain the same across restarts.
