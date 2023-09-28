# zkSync Era audit details
- $1,100,000 total maximum award pot, including **$##,###** gas optimizations pot
- Join [C4 Discord](https://discord.gg/code4rena) to register
- Submit findings [using the C4 form](https://code4rena.com/contests/2023-10-zksync/submit)
- [Read our guidelines for more details](https://docs.code4rena.com/roles/wardens)
- Starts October 2, 2023 20:00 UTC 
- Ends October 20:00 UTC 

How the &#36;1,100,000 maximum pot works:
- Contest minimum pot is &#36;330,000 (including **&#36;##k** gas optimization pot).
- If ANY valid medium severity issue is found, contest pot increases to &#36;770,000.
- If ANY valid high severity issue is found, contest pot increases to &#36;1,100,000.

## Automated Findings / Publicly Known Issues

Automated findings output for the audit can be found [here](https://github.com/code-423n4/2023-10-zksync/bot-report.md) within 24 hours of audit opening.

*Note for C4 wardens: Anything included in the automated findings output is considered a publicly known issue and is ineligible for awards.*


# Overview

# **zkSync Protocol Overview & Documentation**

zkSync Era is a fully-fledged Layer-2 scaling solution, combining a set of smart contracts on Ethereum mainnet and zkEVM for enabling Ethereum virtual machine-compatible smart contract execution.

This repository contains comprehensive documentation and code related to the Smart Contracts, VM, and zk-circuits sections of the zkSync Era Protocol. Below is a high-level summary of each section along with relevant documentation links. Please refer to these before and during the audit for a thorough understanding of the protocol.

## **📁 Sections**

### **1. Smart Contract Section**

Relevant Documentation:

- **[System Contracts/Bootloader Description (VM v1.4.0)](https://github.com/code-423n4/2023-10-zksync/blob/main/docs/Smart%20contract%20Section/System%20contracts%20bootloader%20description%20(VM%20v1%204%200).md)**
- **[zkSync Fee Model](https://github.com/code-423n4/2023-10-zksync/blob/main/docs/Smart%20contract%20Section/zkSync%20fee%20model.md)**
- **[Handling L1→L2 Ops on zkSync](https://github.com/code-423n4/2023-10-zksync/blob/main/docs/Smart%20contract%20Section/Handling%20L1%E2%86%92L2%20ops%20on%20zkSync.md)**
- **[Elliptic Curve Precompiles](https://github.com/code-423n4/2023-10-zksync/blob/main/docs/Smart%20contract%20Section/Elliptic%20curve%20precompiles.md)**
- **[Batches & L2 Blocks on zkSync](https://github.com/code-423n4/2023-10-zksync/blob/main/docs/Smart%20contract%20Section/Batches%20%26%20L2%20blocks%20on%20zkSync.md)**
- **[Handling Pubdata in Boojum](https://www.notion.so/Handling-pubdata-in-Boojum-07dd1bd2ec9041faab21898acd24334e?pvs=21)**

### **2. VM Section**

The VM section is related to the zkSync Era Virtual Machine.

- **[ZkSync Era Virtual Machine Primer](https://github.com/code-423n4/2023-10-zksync/blob/main/docs/VM%20Section/ZkSync%20Era%20Virtual%20Machine%20primer.md)**
    - This primer is designed to provide auditors with a foundational understanding of the zkSync Era Virtual Machine. It offers insights into the operational mechanics and integral components of zkSync EVM, serving as an essential guide for those seeking to explore the zkSync EVM environment.
- **[zkSync Era: The Equivalence Compiler Documentation](https://github.com/code-423n4/2023-10-zksync/blob/main/docs/VM%20Section/compiler-equivalence-docs/zkSync%20Era%20-%20The%20Equivalence%20Compiler%20Documentation.md)**
    - zkSync Era is a layer 2 rollup that uses zero-knowledge proofs to scale Ethereum without compromising on security or decentralization. As it's EVM-compatible (with Solidity/Vyper), 99% of Ethereum projects can redeploy without needing to refactor or re-audit any code. zkSync Era also uses an LLVM-based compiler that will eventually enable developers to write smart contracts in popular languages such as C++ and Rust.
- **[spec.pdf](https://github.com/code-423n4/2023-10-zksync/blob/main/docs/VM%20Section/spec.pdf)**
    - This document is a highly technical and detailed specification, providing an in-depth exploration of the zkSync protocol and its underlying architecture. It’s a comprehensive resource for those who desire a deeper and more formal understanding of the protocol's design and functionalities. While it’s not a required read for understanding the basic structure and operations of the protocol, it is an invaluable resource for those wishing to delve into the finer details and theoretical underpinnings of zkSync.

### **3. Circuits Section**

Circuit Documentation:

- **How does ZK work? (high level)**
   - [Intro to zkSync’s ZK](https://github.com/code-423n4/2023-10-zksync/blob/main/docs/Circuits%20Section/Intro%20to%20zkSync%E2%80%99s%20ZK.md)
   - [ZK Terminology](https://github.com/code-423n4/2023-10-zksync/blob/main/docs/Circuits%20Section/ZK%20Terminology.md)
   - [Getting Started](https://github.com/code-423n4/2023-10-zksync/blob/main/docs/Circuits%20Section/Getting%20Started.md)
- **Examples and Tests**
   - [Circuit Testing](https://github.com/code-423n4/2023-10-zksync/blob/main/docs/Circuits%20Section/Circuit%20testing.md)
- **Advanced**
   - [Boojum gadgets](https://github.com/code-423n4/2023-10-zksync/blob/main/docs/Circuits%20Section/Boojum%20gadgets.md)
   - [Circuits](https://www.notion.so/Circuits-c2e39db21b4446aa8f06318ae404d34f?pvs=21)
   - [Boojum function: check_if_satisfied](https://github.com/code-423n4/2023-10-zksync/blob/sampkaML/Circuits%20Section/Boojum%20function%20check_if_satisfied.md)

## **🚨 Audit & Code Freeze**

Be advised that a code freeze will be in effect for the duration of the audit to ensure a level playing field. All participants are required to review and adhere to the final versions of contracts and documentation added in this repository at least 48 business hours prior to the audit start time.

## **🚀 Getting Started for Auditors**

- Ensure to go through each section and related documents thoroughly.
- Keep in mind the overall working of the zkSync protocol while reviewing individual components.
- Review the code and documentation with a focus on security, correctness, and optimization, particularly concerning gas consumption.

## **📢 Communication**

For any clarifications, doubts, or discussion, please contact Code4rena staff, and we will address your concerns promptly.

## Links

- **Documentation:** https://era.zksync.io/docs/
- **Website:** https://zksync.io/
- **Twitter:** https://twitter.com/zksync
- **Discord:** https://join.zksync.dev/


# Scope

## L1 contracts

### zkSync

| Contract | SLOC | Libraries used |  
| ----------- | ----------- | ----------- |
|  | | |
| [ethereum/contracts/zksync/Verifier.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/Verifier.sol) | 1123 | |
| [ethereum/contracts/zksync/facets/Executor.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/facets/Executor.sol) | 326 | |  
| [ethereum/contracts/zksync/facets/Mailbox.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/facets/Mailbox.sol) | 273 | |
| [ethereum/contracts/zksync/libraries/Diamond.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/libraries/Diamond.sol) | 185 | |
| [ethereum/contracts/zksync/facets/Getters.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/facets/Getters.sol) | 132 | |
| [ethereum/contracts/zksync/interfaces/IMailbox.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/interfaces/IMailbox.sol) | 88 | |
| [ethereum/contracts/zksync/libraries/TransactionValidator.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/libraries/TransactionValidator.sol) | 88 | |
| [ethereum/contracts/zksync/ValidatorTimelock.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/ValidatorTimelock.sol) | 84 | |
| [ethereum/contracts/zksync/facets/Admin.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/facets/Admin.sol) | 67 | |
| [ethereum/contracts/zksync/Storage.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/Storage.sol) | 64 | |
| [ethereum/contracts/zksync/interfaces/IExecutor.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/interfaces/IExecutor.sol) | 56 | | 
| [ethereum/contracts/zksync/DiamondInit.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/DiamondInit.sol) | 53 | |
| [ethereum/contracts/zksync/libraries/PriorityQueue.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/libraries/PriorityQueue.sol) | 42 | |
| [ethereum/contracts/zksync/Config.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/Config.sol) | 40 | |
| [ethereum/contracts/zksync/interfaces/IGetters.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/interfaces/IGetters.sol) | 39 | |
| [ethereum/contracts/zksync/DiamondProxy.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/DiamondProxy.sol) | 30 | |
| [ethereum/contracts/zksync/libraries/Merkle.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/libraries/Merkle.sol) | 30 | |
| [ethereum/contracts/zksync/libraries/LibMap.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/libraries/LibMap.sol) | 27 | |
| [ethereum/contracts/zksync/interfaces/IAdmin.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/interfaces/IAdmin.sol]) | 25 | |
| [ethereum/contracts/zksync/facets/Base.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/facets/Base.sol) | 20 | |
| [ethereum/contracts/zksync/interfaces/ILegacyGetters.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/interfaces/ILegacyGetters.sol) | 10 | |
| [ethereum/contracts/zksync/interfaces/IVerifier.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/interfaces/IVerifier.sol) | 9 | |
| [ethereum/contracts/zksync/interfaces/IZkSync.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/interfaces/IZkSync.sol) | 6 | |
| [ethereum/contracts/zksync/interfaces/IBase.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/interfaces/IBase.sol) | 4 | |

### Bridges

| Contract | SLOC | Libraries used |  
| ----------- | ----------- | ----------- |
| [ethereum/contracts/bridge/L1ERC20Bridge.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/bridge/L1ERC20Bridge.sol) | 204 | |
| [ethereum/contracts/bridge/L1WethBridge.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/bridge/L1WethBridge.sol) | 175 | |
| [ethereum/contracts/bridge/interfaces/IL1Bridge.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/bridge/interfaces/IL1Bridge.sol) | 39 | |
| [ethereum/contracts/bridge/libraries/BridgeInitializationHelper.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/contracts/bridge/libraries/BridgeInitializationHelper.sol) | 37 | |
| [ethereum/contracts/bridge/interfaces/IL2Bridge.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/bridge/interfaces/IL2Bridge.sol) | 18 | |
| [ethereum/contracts/bridge/interfaces/IL1BridgeLegacy.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/bridge/interfaces/IL1BridgeLegacy.sol) | 10 | |
| [ethereum/contracts/bridge/interfaces/IL2ERC20Bridge.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/bridge/interfaces/IL2ERC20Bridge.sol) | 8 | |
| [ethereum/contracts/bridge/interfaces/IL2WethBridge.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/bridge/interfaces/IL2WethBridge.sol) | 8 | |
| [ethereum/contracts/bridge/interfaces/IWETH9.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/bridge/interfaces/IWETH9.sol) | 5 | |

### Other

| Contract | SLOC | Libraries used |  
| ----------- | ----------- | ----------- |
| [ethereum/contracts/common/AllowList.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/common/AllowList.sol) | 72 | |
| [ethereum/contracts/common/interfaces/IAllowList.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/common/interfaces/IAllowList.sol) | 45 | |
| [ethereum/contracts/common/libraries/L2ContractHelper.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/common/libraries/L2ContractHelper.sol) | 33 | |
| [ethereum/contracts/common/ReentrancyGuard.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/common/ReentrancyGuard.sol) | 32 | |
| [ethereum/contracts/common/libraries/UnsafeBytes.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/common/libraries/UnsafeBytes.sol) | 27 | |
| [ethereum/contracts/common/interfaces/IL2ContractDeployer.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/common/interfaces/IL2ContractDeployer.sol) | 16 | |
| [ethereum/contracts/common/libraries/UncheckedMath.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/common/libraries/UncheckedMath.sol) | 13 | |
| [ethereum/contracts/common/AllowListed.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/common/AllowListed.sol) | 10 | |
| [ethereum/contracts/common/L2ContractAddresses.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/common/L2ContractAddresses.sol) | 9 | |
| [ethereum/contracts/common/Dependencies.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/common/Dependencies.sol) | 2 | |

## L2 contracts

### Bridges

| Contract | SLOC | Libraries used |  
| ----------- | ----------- | ----------- |
| [zksync/contracts/bridge/L2ERC20Bridge.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/bridge/L2ERC20Bridge.sol) | 101 | |
| [zksync/contracts/bridge/L2StandardERC20.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/bridge/L2StandardERC20.sol) 78 | |
| [zksync/contracts/bridge/L2WethBridge.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/bridge/L2WethBridge.sol) 66 | | 
| [zksync/contracts/bridge/L2Weth.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/bridge/L2Weth.sol) 55 | |
| [zksync/contracts/bridge/interfaces/IL2Bridge.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/bridge/interfaces/IL2Bridge.sol) 30 | |
| [zksync/contracts/bridge/interfaces/IL1Bridge.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/bridge/interfaces/IL1Bridge.sol) 10 | |
| [zksync/contracts/bridge/interfaces/IL2StandardToken.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/bridge/interfaces/IL2StandardToken.sol) 10 | |
| [zksync/contracts/bridge/interfaces/IL2Weth.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/bridge/interfaces/IL2Weth.sol) 8 | |

### Other

| Contract | SLOC | Libraries used |
| ----------- | ----------- | ----------- |
| [zksync/contracts/SystemContractsCaller.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/SystemContractsCaller.sol) 108 | |
| [zksync/contracts/L2ContractHelper.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/L2ContractHelper.sol) 64 | |
| [zksync/contracts/TestnetPaymaster.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/TestnetPaymaster.sol) 51 | |
| [zksync/contracts/interfaces/IPaymaster.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/interfaces/IPaymaster.sol) 22 | |
| [zksync/contracts/vendor/AddressAliasHelper.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/vendor/AddressAliasHelper.sol]) 14 | |
| [zksync/contracts/interfaces/IPaymasterFlow.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/interfaces/IPaymasterFlow.sol) 9 | |
| [zksync/contracts/ForceDeployUpgrader.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/ForceDeployUpgrader.sol) 7 | |
| [zksync/contracts/Dependencies.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/Dependencies.sol) 2 | |

## Out of scope

| Contract | SLOC | Libraries used |  
| ----------- | ----------- | ----------- |

## Out of scope

*List any files/contracts that are out of scope for this audit.*

## Attack ideas (Where to look for bugs)
*List specific areas to address - see [this blog post](https://medium.com/code4rena/the-security-council-elections-within-the-arbitrum-dao-a-comprehensive-guide-aa6d001aae60#9adb) for an example*


## Scoping Details 
[ ⭐️ SPONSORS: please confirm/edit the information below. ]

```
- If you have a public code repo, please share it here:  
- How many contracts are in scope?:   
- Total SLoC for these contracts?:  
- How many external imports are there?:  
- How many separate interfaces and struct definitions are there for the contracts within scope?:  
- Does most of your code generally use composition or inheritance?:   
- How many external calls?:   
- What is the overall line coverage percentage provided by your tests?:
- Is this an upgrade of an existing system?:
- Check all that apply (e.g. timelock, NFT, AMM, ERC20, rollups, etc.): 
- Is there a need to understand a separate part of the codebase / get context in order to audit this part of the protocol?:   
- Please describe required context:   
- Does it use an oracle?:  
- Describe any novel or unique curve logic or mathematical models your code uses: 
- Is this either a fork of or an alternate implementation of another project?:   
- Does it use a side-chain?:
- Describe any specific areas you would like addressed:
```

# Tests

*Provide every step required to build the project from a fresh git clone, as well as steps to run the tests with a gas report.* 

*Note: Many wardens run Slither as a first pass for testing.  Please document any known errors with no workaround.* 
