# zkSync Era audit details
- $1,100,000 total maximum prize pool
- Join [C4 Discord](https://discord.gg/code4rena) to register
- Submit findings [using the C4 form](https://code4rena.com/contests/2023-10-zksync-era/submit)
- [Read our guidelines for more details](https://docs.code4rena.com/roles/wardens)
- Starts October 2, 2023 20:00 UTC 
- Ends October 23, 2023 20:00 UTC 

How the &#36;1,100,000 maximum pot works:
- Audit minimum pot is &#36;330,000 (including **&#36;7.5k** gas optimization pot). ❗️Please note, only L1 contracts are included in gas optimization pool.
  - HM awards: $250,000 USDC
  - Analysis awards: $15,000 USDC
  - QA awards: $7,500 USDC
  - Bot Race awards: $20,000 USDC
  - Gas awards: $7,500 USDC
  - Judge awards: $18,000 USDC
  - Lookout awards: $12,000 USDC
  - Scout awards: $500 USDC
- If ANY valid Medium severity issue is found, audit pot increases to &#36;770,000.
- If ANY valid High severity issue is found, audit pot increases to &#36;1,100,000.

## Automated Findings / Publicly Known Issues

Automated findings output for the audit can be found [here](https://github.com/code-423n4/2023-10-zksync/blob/main/bot-report.md) within 24 hours of audit opening.

*Note for C4 wardens: Anything included in the automated findings output is considered a publicly known issue and is ineligible for awards.*

### DefaultAccount does not always return successfully

[DefaultAccount](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/DefaultAccount.sol), while it should always behave as an EOA (i.e. any call to it should return `success(0,0)`), if called with a selector of one of its methods and incorrect ABI-encoding of its parameters, will fail with empty error. This happens due to the fact that the ABI decoding fails before the modifier is triggered.

### Known differences from Ethereum

More known differences from Ethereum can be found in our [documentation](https://era.zksync.io/docs/reference/architecture/differences-with-ethereum.html).

# Overview

# **zkSync Protocol Overview & Documentation**

zkSync Era is a fully-fledged Layer-2 scaling solution, combining a set of smart contracts on Ethereum mainnet and zkEVM for enabling Ethereum virtual machine-compatible smart contract execution.

This repository contains comprehensive documentation and code related to the Smart Contracts, VM, and zk-circuits sections of the zkSync Era Protocol. Below is a high-level summary of each section along with relevant documentation links. Please refer to these before and during the audit for a thorough understanding of the protocol.

## **📁 Sections**

### **1. Smart Contracts Section**

Relevant Documentation:

- **[L1 smart contracts](https://github.com/code-423n4/2023-10-zksync/blob/main/docs/Smart%20contract%20Section/L1%20smart%20contracts.md)**
- **[System Contracts/Bootloader Description](https://github.com/code-423n4/2023-10-zksync/blob/main/docs/Smart%20contract%20Section/System%20contracts%20bootloader%20description.md)**
- **[zkSync Era Fee Model](https://github.com/code-423n4/2023-10-zksync/blob/main/docs/Smart%20contract%20Section/zkSync%20fee%20model.md)**
- **[Handling L1→L2 Ops on zkSync](https://github.com/code-423n4/2023-10-zksync/blob/main/docs/Smart%20contract%20Section/Handling%20L1→L2%20ops%20on%20zkSync.md)**
- **[Batches & L2 Blocks on zkSync](https://github.com/code-423n4/2023-10-zksync/blob/main/docs/Smart%20contract%20Section/Batches%20&%20L2%20blocks%20on%20zkSync.md)**
- **[Elliptic Curve Precompiles](https://github.com/code-423n4/2023-10-zksync/blob/main/docs/Smart%20contract%20Section/Elliptic%20curve%20precompiles.md)**
- **[Handling Pubdata in Boojum](https://github.com/code-423n4/2023-10-zksync/blob/main/docs/Smart%20contract%20Section/Handling%20pubdata%20in%20Boojum.md)**

### **2. VM Section**

The VM section is related to the zkSync Era Virtual Machine.

- **[ZkSync Era Virtual Machine Primer](https://github.com/code-423n4/2023-10-zksync/blob/main/docs/VM%20Section/ZkSync%20Era%20Virtual%20Machine%20primer.md)**
    - This primer is designed to provide auditors with a foundational understanding of the zkSync Era Virtual Machine. It offers insights into the operational mechanics and integral components of EraVM, serving as an essential guide for those seeking to explore the zkSync EraVM environment.
- **[zkSync Era: The Equivalence Compiler Documentation](https://github.com/code-423n4/2023-10-zksync/blob/main/docs/VM%20Section/How%20compiler%20works/overview.md)**
    - The document describes how zkSync Solidity compiler represents high-level programming language constructions into low-level EraVM instruction set, how to use unique features without extending Solidity language with new syntax and why system contracts are needed.
- **[EraVM Formal specification](https://github.com/code-423n4/2023-10-zksync/blob/main/docs/VM%20Section/EraVM%20Formal%20specification.pdf)**
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
   - [Circuits](https://github.com/code-423n4/2023-10-zksync/blob/main/docs/Circuits%20Section/Circuits.md)
   - [Boojum function: check_if_satisfied](https://github.com/code-423n4/2023-10-zksync/blob/main/docs/Circuits%20Section/Boojum%20function%20check_if_satisfied.md)

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
- **Previous Audits:** https://era.zksync.io/docs/reference/troubleshooting/audit-bug-bounty.html


# Scope

## L1 contracts

### zkSync

| Contract | SLOC | Libraries used |  
| ----------- | ----------- | ----------- |
|  | | |
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
| [ethereum/contracts/zksync/interfaces/IAdmin.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/interfaces/IAdmin.sol) | 25 | |
| [ethereum/contracts/zksync/facets/Base.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/facets/Base.sol) | 20 | |
| [ethereum/contracts/zksync/interfaces/ILegacyGetters.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/interfaces/ILegacyGetters.sol) | 10 | |
| [ethereum/contracts/zksync/interfaces/IZkSync.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/interfaces/IZkSync.sol) | 6 | |
| [ethereum/contracts/zksync/interfaces/IBase.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/interfaces/IBase.sol) | 4 | |

### Bridges

| Contract | SLOC | Libraries used |  
| ----------- | ----------- | ----------- |
| [ethereum/contracts/bridge/L1ERC20Bridge.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/bridge/L1ERC20Bridge.sol) | 204 | |
| [ethereum/contracts/bridge/L1WethBridge.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/bridge/L1WethBridge.sol) | 175 | |
| [ethereum/contracts/bridge/interfaces/IL1Bridge.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/bridge/interfaces/IL1Bridge.sol) | 39 | |
| [ethereum/contracts/bridge/libraries/BridgeInitializationHelper.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/bridge/libraries/BridgeInitializationHelper.sol) | 37 | |
| [ethereum/contracts/bridge/interfaces/IL2Bridge.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/bridge/interfaces/IL2Bridge.sol) | 18 | |
| [ethereum/contracts/bridge/interfaces/IL1BridgeLegacy.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/bridge/interfaces/IL1BridgeLegacy.sol) | 10 | |
| [ethereum/contracts/bridge/interfaces/IL2ERC20Bridge.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/bridge/interfaces/IL2ERC20Bridge.sol) | 8 | |
| [ethereum/contracts/bridge/interfaces/IL2WethBridge.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/bridge/interfaces/IL2WethBridge.sol) | 8 | |
| [ethereum/contracts/bridge/interfaces/IWETH9.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/bridge/interfaces/IWETH9.sol) | 5 | |

### Governance

| Contract | SLOC | Libraries used |  
| ----------- | ----------- | ----------- |
| [ethereum/contracts/governance/Governance.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/governance/Governance.sol) | 120 | |
| [ethereum/contracts/governance/IGovernance.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/governance/IGovernance.sol) | 38 | |

### Upgrades

| Contract | SLOC | Libraries used |  
| ----------- | ----------- | ----------- |
| [ethereum/contracts/upgrades/BaseZkSyncUpgrade.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/upgrades/BaseZkSyncUpgrade.sol) | 135 | |
| [ethereum/contracts/upgrades/DefaultUpgrade.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/upgrades/DefaultUpgrade.sol) | 24 | |

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
| [ethereum/contracts/vendor/AddressAliasHelper.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/vendor/AddressAliasHelper.sol) | 14 | |


## L2 contracts

### Bootloader

| Contract | SLOC | Libraries used |  
| ----------- | ----------- | ----------- |
| [system-contracts/bootloader/bootloader.yul](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/bootloader/bootloader.yul) | 3825 | |

### System Contracts

| Contract | SLOC | Libraries used |
| ----------- | ----------- | ----------- |
| [system-contracts/contracts/libraries/TransactionHelper.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/libraries/TransactionHelper.sol) | 258 | |
| [system-contracts/contracts/BootloaderUtilities.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/BootloaderUtilities.sol) | 233 | |
| [system-contracts/contracts/SystemContext.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/SystemContext.sol) | 232 | |
| [system-contracts/contracts/L1Messenger.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/L1Messenger.sol) | 219 | |
| [system-contracts/contracts/ContractDeployer.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/ContractDeployer.sol) | 204 | |
| [system-contracts/contracts/libraries/SystemContractHelper.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/libraries/SystemContractHelper.sol) | 200 | |
| [system-contracts/contracts/openzeppelin/utils/Address.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/openzeppelin/utils/Address.sol) | 160 | |
| [system-contracts/contracts/libraries/EfficientCall.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/libraries/EfficientCall.sol) | 151 | |
| [system-contracts/contracts/libraries/SystemContractsCaller.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/) | 144 | |
| [system-contracts/contracts/Compressor.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/Compressor.sol) | 139 | |
| [system-contracts/contracts/DefaultAccount.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/DefaultAccount.sol) | 115 | |
| [system-contracts/contracts/NonceHolder.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/NonceHolder.sol) | 82 | |
| [system-contracts/contracts/libraries/RLPEncoder.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/libraries/RLPEncoder.sol) | 75 | |
| [system-contracts/contracts/L2EthToken.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/L2EthToken.sol) | 71 | |
| [system-contracts/contracts/Constants.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/Constants.sol) | 65 | |
| [system-contracts/contracts/AccountCodeStorage.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/AccountCodeStorage.sol) | 62 | |
| [system-contracts/contracts/interfaces/IContractDeployer.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/interfaces/IContractDeployer.sol) | 54 | |
| [system-contracts/contracts/libraries/Utils.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/libraries/Utils.sol) | 51 | |
| [system-contracts/contracts/KnownCodesStorage.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/KnownCodesStorage.sol) | 45 | |
| [system-contracts/contracts/MsgValueSimulator.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/MsgValueSimulator.sol) | 31 | |
| [system-contracts/contracts/libraries/UnsafeBytesCalldata.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/libraries/UnsafeBytesCalldata.sol) | 31 | |
| [system-contracts/contracts/interfaces/ISystemContract.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/interfaces/ISystemContract.sol) | 27 | |
| [system-contracts/contracts/interfaces/IAccount.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/interfaces/IAccount.sol) | 26 | |
| [system-contracts/contracts/interfaces/ISystemContext.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/interfaces/ISystemContext.sol) | 25 | |
| [system-contracts/contracts/interfaces/IPaymaster.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/interfaces/IPaymaster.sol) | 22 | |
| [system-contracts/contracts/interfaces/IEthToken.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/interfaces/IEthToken.sol) | 21 | |
| [system-contracts/contracts/ImmutableSimulator.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/ImmutableSimulator.sol) | 20 | |
| [system-contracts/contracts/interfaces/IL1Messenger.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/interfaces/IL1Messenger.sol) | 20 | |
| [system-contracts/contracts/interfaces/ICompressor.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/interfaces/ICompressor.sol) | 16 | |
| [system-contracts/contracts/ComplexUpgrader.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/ComplexUpgrader.sol) | 15 | |
| [system-contracts/contracts/interfaces/INonceHolder.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/interfaces/INonceHolder.sol) | 14 | |
| [system-contracts/contracts/test-contracts/MockKnownCodesStorage.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/test-contracts/MockKnownCodesStorage.sol) | 11 | |
| [system-contracts/contracts/interfaces/IMailbox.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/interfaces/IMailbox.sol) | 10 | |
| [system-contracts/contracts/interfaces/IAccountCodeStorage.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/interfaces/IAccountCodeStorage.sol) | 9 | |
| [system-contracts/contracts/interfaces/IImmutableSimulator.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/interfaces/IImmutableSimulator.sol) | 9 | |
| [system-contracts/contracts/interfaces/IL2StandardToken.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/interfaces/IL2StandardToken.sol) | 9 | |
| [system-contracts/contracts/interfaces/IBootloaderUtilities.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/interfaces/IBootloaderUtilities.sol) | 7 | |
| [system-contracts/contracts/interfaces/IKnownCodesStorage.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/interfaces/IKnownCodesStorage.sol]) | 7 | |
| [system-contracts/contracts/interfaces/ISystemContextDeprecated.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/interfaces/ISystemContextDeprecated.sol) | 6 | |
| [system-contracts/contracts/EmptyContract.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/EmptyContract.sol) | 5 | |
| [system-contracts/contracts/interfaces/IPaymasterFlow.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/interfaces/IPaymasterFlow.sol) | 5 | |
| [system-contracts/contracts/interfaces/IComplexUpgrader.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/interfaces/IComplexUpgrader.sol) | 4 | |
| [system-contracts/contracts/EventWriter.yul](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/EventWriter.yul) | 168 | |
| [system-contracts/contracts/precompiles/EcAdd.yul](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/precompiles/EcAdd.yul) | 439 | |
| [system-contracts/contracts/precompiles/EcMul.yul](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/precompiles/EcMul.yul) | 493 | |
| [system-contracts/contracts/precompiles/Ecrecover.yul](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/precompiles/Ecrecover.yul) | 98 | |
| [system-contracts/contracts/precompiles/Keccak256.yul](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/precompiles/Keccak256.yul) | 126 | |
| [system-contracts/contracts/precompiles/SHA256.yul](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/precompiles/SHA256.yul) | 101 | |

### Bridges

| Contract | SLOC | Libraries used |  
| ----------- | ----------- | ----------- |
| [zksync/contracts/bridge/L2ERC20Bridge.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/bridge/L2ERC20Bridge.sol) | 101 | |
| [zksync/contracts/bridge/L2StandardERC20.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/bridge/L2StandardERC20.sol) | 78 | |
| [zksync/contracts/bridge/L2WethBridge.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/bridge/L2WethBridge.sol) | 66 | | 
| [zksync/contracts/bridge/L2Weth.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/bridge/L2Weth.sol) | 55 | |
| [zksync/contracts/bridge/interfaces/IL2Bridge.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/bridge/interfaces/IL2Bridge.sol) | 30 | |
| [zksync/contracts/bridge/interfaces/IL1Bridge.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/bridge/interfaces/IL1Bridge.sol) | 10 | |
| [zksync/contracts/bridge/interfaces/IL2StandardToken.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/bridge/interfaces/IL2StandardToken.sol) | 10 | |
| [zksync/contracts/bridge/interfaces/IL2Weth.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/bridge/interfaces/IL2Weth.sol) | 8 | |

### Other

| Contract | SLOC | Libraries used |
| ----------- | ----------- | ----------- |
| [zksync/contracts/SystemContractsCaller.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/SystemContractsCaller.sol) | 108 | |
| [zksync/contracts/L2ContractHelper.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/L2ContractHelper.sol) | 64 | |
| [zksync/contracts/interfaces/IPaymaster.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/interfaces/IPaymaster.sol) | 22 | |
| [zksync/contracts/vendor/AddressAliasHelper.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/vendor/AddressAliasHelper.sol]) | 14 | |
| [zksync/contracts/interfaces/IPaymasterFlow.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/interfaces/IPaymasterFlow.sol) | 9 | |
| [zksync/contracts/ForceDeployUpgrader.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/ForceDeployUpgrader.sol) | 7 | |
| [zksync/contracts/Dependencies.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/Dependencies.sol) | 2 | |

## ZK Circuits
| Circuits & circuit structures | SLOC | Purpose |
| ----------- | ----------- | ----------- |
| [era-zkevm_circuits/src/base_structures](https://github.com/matter-labs/era-zkevm_circuits/tree/main/src/base_structures) | 1971 | Structures for circuits |
| [era-zkevm_circuits/src/code_unpacker_sha256](https://github.com/matter-labs/era-zkevm_circuits/tree/main/src/code_unpacker_sha256) | 704 | Unpacks code into memory |
| [era-zkevm_circuits/src/demux_log_queue](https://github.com/matter-labs/era-zkevm_circuits/tree/main/src/demux_log_queue) | 868 | Demultiplexes logs into their appropriate circuits |
| [era-zkevm_circuits/src/ecrecover](https://github.com/matter-labs/era-zkevm_circuits/tree/main/src/ecrecover) | 1342 | Ecrecover precompile |
| [era-zkevm_circuits/src/fsm_input_output](https://github.com/matter-labs/era-zkevm_circuits/tree/main/src/fsm_input_output) | 352 | Validates the outputs of one circuit match the inputs of the next |
| [era-zkevm_circuits/src/keccak_round_function](https://github.com/matter-labs/era-zkevm_circuits/tree/main/src/keccak256_round_function) | 531 | Keccak hash function precompile|
| [era-zkevm_circuits/src/sha256_round_function](https://github.com/matter-labs/era-zkevm_circuits/tree/main/src/sha256_round_function) | 464 | SHA256 hash function precompile|
| [era-zkevm_circuits/src/linear_hasher](https://github.com/matter-labs/era-zkevm_circuits/tree/main/src/linear_hasher) | 224 | Creates commitment using Keccak |
| [era-zkevm_circuits/src/log_sorter](https://github.com/matter-labs/era-zkevm_circuits/tree/main/src/log_sorter) | 798 | Sort and deduplicate logs |
| [era-zkevm_circuits/src/main_vm](https://github.com/matter-labs/era-zkevm_circuits/tree/main/src/main_vm) | 7673 | Main VM circuit |
| [era-zkevm_circuits/src/ram_permutation](https://github.com/matter-labs/era-zkevm_circuits/tree/main/src/ram_permutation) | 657 | Circuit for RAM reads+writes |
| [era-zkevm_circuits/src/sort_decommitment_requests](https://github.com/matter-labs/era-zkevm_circuits/tree/main/src/sort_decommittment_requests) | 1358 | Sort and duplicate code decommitments |
| [era-zkevm_circuits/src/storage_application](https://github.com/matter-labs/era-zkevm_circuits/tree/main/src/storage_application) | 686 | Circuit related to storage. Handles the sorting and deduplication of code cancellation requests |
| [era-zkevm_circuits/src/storage_validity_by_grand_product](https://github.com/matter-labs/era-zkevm_circuits/tree/main/src/storage_validity_by_grand_product) | 1670 | Circuit is sorting and deduplicating storage requests |
| [era-zkevm_circuits/src/tables](https://github.com/matter-labs/era-zkevm_circuits/tree/main/src/tables) | 206 | Lookup Tables |

## Out of scope

### contracts

| Contract | SLOC | Libraries used |  
| ----------- | ----------- | ----------- |
|  | | |
| [ethereum/contracts/zksync/Verifier.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/Verifier.sol) | 1123 | |
| [ethereum/contracts/zksync/interfaces/IVerifier.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/zksync/interfaces/IVerifier.sol) | 9 | |
| [zksync/contracts/TestnetPaymaster.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/zksync/contracts/TestnetPaymaster.sol) | 51 | |
| [ethereum/contracts/common/Dependencies.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/common/Dependencies.sol) | 2 | |
| [system-contracts/contracts/test-contracts/TestSystemContract.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/test-contracts/TestSystemContract.sol) | 110 | |
| [system-contracts/contracts/openzeppelin/token/ERC20/utils/SafeERC20.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/openzeppelin/token/ERC20/utils/SafeERC20.sol) | 109 | |
| [system-contracts/contracts/test-contracts/TestSystemContractHelper.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/test-contracts/TestSystemContractHelper.sol) | 69 | |
| [system-contracts/contracts/openzeppelin/token/ERC20/IERC20.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/openzeppelin/token/ERC20/IERC20.sol) | 15 | |
| [system-contracts/contracts/openzeppelin/token/ERC20/extensions/IERC20Permit.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/openzeppelin/token/ERC20/extensions/IERC20Permit.sol) | 14 | |
| [system-contracts/contracts/test-contracts/DummyUpgrade.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/system-contracts/contracts/test-contracts/DummyUpgrade.sol) | 7 | |
| [ethereum/contracts/dev-contracts/Multicall3.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/dev-contracts/Multicall3.sol) | 149 | |
| [ethereum/contracts/dev-contracts/test/DummyExecutor.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/dev-contracts/test/DummyExecutor.sol) | 87 | |
| [ethereum/contracts/dev-contracts/test/VerifierRecursiveTest.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/dev-contracts/test/VerifierRecursiveTest.sol) | 49 | |
| [ethereum/contracts/dev-contracts/test/VerifierTest.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/dev-contracts/test/VerifierTest.sol) | 49 | |
| [ethereum/contracts/dev-contracts/WETH9.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/dev-contracts/WETH9.sol) | 47 | |
| [ethereum/contracts/dev-contracts/Multicall.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/dev-contracts/Multicall.sol) | 37 | |
| [ethereum/contracts/dev-contracts/test/CustomUpgradeTest.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/dev-contracts/test/CustomUpgradeTest.sol) | 27 | |
| [ethereum/contracts/dev-contracts/test/PriorityQueueTest.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/dev-contracts/test/PriorityQueueTest.sol) | 27 | |
| [ethereum/contracts/dev-contracts/test/UnsafeBytesTest.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/dev-contracts/test/UnsafeBytesTest.sol) | 26 | |
| [ethereum/contracts/dev-contracts/test/AdminFacetTest.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/dev-contracts/test/AdminFacetTest.sol) | 22 | |
| [ethereum/contracts/dev-contracts/RevertTransferERC20.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/dev-contracts/RevertTransferERC20.sol) | 16 | |
| [ethereum/contracts/dev-contracts/TestnetERC20Token.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/dev-contracts/TestnetERC20Token.sol) | 15 | |
| [ethereum/contracts/dev-contracts/test/TransactionValidatorTest.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/dev-contracts/test/TransactionValidatorTest.sol) | 14 | |
| [ethereum/contracts/dev-contracts/RevertReceiveAccount.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/dev-contracts/RevertReceiveAccount.sol) | 13 | |
| [ethereum/contracts/dev-contracts/test/DummyERC20BytesTransferReturnValue.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/dev-contracts/test/DummyERC20BytesTransferReturnValue.sol) | 12 | |
| [ethereum/contracts/dev-contracts/test/L1ERC20BridgeTest.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/dev-contracts/test/L1ERC20BridgeTest.sol) | 11 | |
| [ethereum/contracts/dev-contracts/test/MerkleTest.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/dev-contracts/test/MerkleTest.sol) | 11 | |
| [ethereum/contracts/dev-contracts/test/DiamondProxyTest.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/dev-contracts/test/DiamondProxyTest.sol) | 10 | |
| [ethereum/contracts/dev-contracts/Forwarder.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/dev-contracts/Forwarder.sol) | 8 | |
| [ethereum/contracts/dev-contracts/ReturnSomething.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/dev-contracts/ReturnSomething.sol) | 8 | |
| [ethereum/contracts/dev-contracts/SingletonFactory.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/dev-contracts/SingletonFactory.sol) | 8 | |
| [ethereum/contracts/dev-contracts/test/DiamondCutTestContract.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/dev-contracts/test/DiamondCutTestContract.sol) | 8 | |
| [ethereum/contracts/dev-contracts/test/MockExecutor.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/dev-contracts/test/MockExecutor.sol) | 8 | |
| [ethereum/contracts/dev-contracts/ConstructorForwarder.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/dev-contracts/ConstructorForwarder.sol) | 7 | |
| [ethereum/contracts/dev-contracts/RevertFallback.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/dev-contracts/RevertFallback.sol) | 6 | |
| [ethereum/contracts/dev-contracts/test/DummyERC20NoTransferReturnValue.sol](https://github.com/code-423n4/2023-10-zksync/blob/main/code/contracts/ethereum/contracts/dev-contracts/test/DummyERC20NoTransferReturnValue.sol) | 4 | |

### Circuits

| Contract | SLOC | Libraries used |  
| ----------- | ----------- | ----------- |
|  | | |
| [era-zkevm_circuits/src/recursion](https://github.com/matter-labs/era-zkevm_circuits/tree/main/src/recursion) | 876 | |
| [era-zkevm_circuits/src/scheduler](https://github.com/matter-labs/era-zkevm_circuits/tree/main/src/scheduler) | 1333 | |


## Attack ideas (Where to look for bugs)

### Access control and permissions

It is important to examine access control and permissions for any contract that contains potentially dangerous logic (including upgrades). While the assumption is that either governance or security council are not malicious, neither governance, nor the security council should be able to circumvent the limitations imposed on them.

Special scrutiny should be paid to the powers of the operator. While currently the operator is controlled by Matter Labs and is also partially trusted (for instance, it is responsible for supplying the correct L1 gas price), it should never be able to directly steal users' funds or conduct malicious upgrades. An [example](https://github.com/code-423n4/2023-10-zksync/blob/main/docs/Smart%20contract%20Section/Handling%20L1%E2%86%92L2%20ops%20on%20zkSync.md) of such an issue, which was detected and resolved by the team before the contest. 

### Data availability issues 

Another important invariant is that the state of the rollup can be restored based on the pubdata sent to L1. Make sure that for a block that gets executed regardless of what a potentially malicious operator does:

- Users can always get preimages for all the bytecodes that were deployed to the system.
- Users can always recover the leaves of the Merkle tree of L2->L1 logs.
- Users can always recover the storage merkle tree.

In general, there should be always a possibility to have a new operator that fully recovers the state available solely from L1 and is able to execute transactions successfully.

### EVM compatibility attacks

Make sure that access to any dangerous logic is well-constrained. For instance:

- Access to potentially dangerous system contracts' methods is protected by the `isSystemCall` flag, permitting only the contracts that are aware of the zkSync-specific features to call it.
- Using innocent Solidity code without zkSync-specific features should not lead to unexpected behaviour. An [example](https://code4rena.com/reports/2023-03-zksync#h-01-the-call-to-msgvaluesimulator-with-non-zero-msgvalue-will-call-to-sender-itself-which-will-bypass-the-onlyself-check) of a relevant finding.

## Scoping Details 

```
- If you have a public code repo, please share it here:  N/A
- How many contracts are in scope?:   39
- Total SLoC for these contracts?:  6011
- How many external imports are there?:  13
- How many separate interfaces and struct definitions are there for the contracts within scope?:  94
- Does most of your code generally use composition or inheritance?:   Yes
- Is this an upgrade of an existing system?: Yes
- Check all that apply (e.g. timelock, NFT, AMM, ERC20, rollups, etc.): timelock, rollups, zk circuits
- Is there a need to understand a separate part of the codebase / get context in order to audit this part of the protocol?:   No
- Please describe required context:   ZK rollup
- Does it use an oracle?:  No
- Describe any novel or unique curve logic or mathematical models your code uses: No
- Is this either a fork of or an alternate implementation of another project?: No
- Does it use a side-chain?: No
- Describe any specific areas you would like addressed: Missing constraints, logical errors, malicious input for zk circuit or bootloader
```

# Tests

## (Hardhat) L1 contracts one liner

```
rm -Rf 2023-10-zksync || true && git clone https://github.com/code-423n4/2023-10-zksync.git && cd 2023-10-zksync/code/contracts/ethereum && yarn --ignore-engines && yarn test
```

## (Foundry) L1 contracts one liner

```
rm -Rf 2023-10-zksync || true && git clone https://github.com/code-423n4/2023-10-zksync.git && cd 2023-10-zksync/code/contracts/ethereum && yarn --ignore-engines && yarn test:foundry
```

## (Hardhat) L2 System contracts one liner

```
rm -Rf 2023-10-zksync || true && git clone https://github.com/code-423n4/2023-10-zksync.git && cd 2023-10-zksync/code/system-contracts/scripts && yarn --ignore-engines && bash quick-setup.sh
```

## (Hardhat) L2 contracts one liner

```
rm -Rf 2023-10-zksync || true && git clone https://github.com/code-423n4/2023-10-zksync.git && cd 2023-10-zksync/code/contracts/zksync/scripts && yarn --ignore-engines && bash quick-setup.sh
```
