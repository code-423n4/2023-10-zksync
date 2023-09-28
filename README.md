# zkSync Era audit details
- $1,100,000 total maximum award pot, including **$##,###** gas optimizations pot
- Join [C4 Discord](https://discord.gg/code4rena) to register
- Submit findings [using the C4 form](https://code4rena.com/contests/2023-10-zksync/submit)
- [Read our guidelines for more details](https://docs.code4rena.com/roles/wardens)
- Starts October 2, 2023 20:00 UTC 
- Ends October 20:00 UTC 

**IMPORTANT NOTE**: Unlike most public Code4rena contests, prior to receiving payment from this contest you MUST become a Certified Warden (successfully complete KYC and pass screening for OFAC sanctions). You do not have to complete this process before competing or submitting bugs.

How the &#36;1,100,000 maximum pot works:
- Contest minimum pot is &#36;330,000 (including **&#36;##k** gas optimization pot).
- If ANY valid medium severity issue is found, contest pot increases to &#36;770,000.
- If ANY valid high severity issue is found, contest pot increases to &#36;1,100,000.

## Automated Findings / Publicly Known Issues

Automated findings output for the audit can be found [here](https://github.com/code-423n4/2023-10-zksync/bot-report.md) within 24 hours of audit opening.

*Note for C4 wardens: Anything included in the automated findings output is considered a publicly known issue and is ineligible for awards.*


# Overview

# **zkSync Protocol Overview & Documentation**

ZkSync is a fully-fledged Layer-2 scaling solution, combining a set of system contracts on Ethereum mainnet, zkRollup smart contracts for scaling, and zkEVM for enabling Ethereum virtual machine-compatible smart contract execution.

This repository contains comprehensive documentation and code related to the Smart Contracts, Circuits, and VM sections of the zkSync Protocol. Below is a high-level summary of each section along with relevant documentation links. Please refer to these before and during the audit for a thorough understanding of the protocol.

## **📁 Sections**

### **1. Smart Contract Section**

The Smart Contract section encompasses system contracts and bootloader for VM v1.4.0, fee models, and L1→L2 operations handling on zkSync. Here are the relevant documents:

- **[System Contracts/Bootloader Description (VM v1.4.0)](https://github.com/code-423n4/2023-10-zksync/blob/main/Smart%20contract%20Section/System%20contracts%20bootloader%20description%20(VM%20v1%204%200).md)**
- **[zkSync Fee Model](https://github.com/code-423n4/2023-10-zksync/blob/main/Smart%20contract%20Section/zkSync%20fee%20model.md)**
- **[Handling L1→L2 Ops on zkSync](https://github.com/code-423n4/2023-10-zksync/blob/main/Smart%20contract%20Section/Handling%20L1%E2%86%92L2%20ops%20on%20zkSync.md)**
- **[Elliptic Curve Precompiles](https://github.com/code-423n4/2023-10-zksync/blob/main/Smart%20contract%20Section/Elliptic%20curve%20precompiles.md)**
- **[Batches & L2 Blocks on zkSync](https://github.com/code-423n4/2023-10-zksync/blob/main/Smart%20contract%20Section/Batches%20%26%20L2%20blocks%20on%20zkSync.md)**
- **[Handling Pubdata in Boojum](https://www.notion.so/Handling-pubdata-in-Boojum-07dd1bd2ec9041faab21898acd24334e?pvs=21)**

### **2. Circuits Section**

The Circuits section deals with the batches & L2 blocks on zkSync, handling of pubdata in Boojum, and Code4rena circuit documentation.

- **How does ZK work? (high level)**
   - [Intro to zkSync’s ZK](https://github.com/code-423n4/2023-10-zksync/blob/main/Circuits%20Section/Intro%20to%20zkSync%E2%80%99s%20ZK.md)
   - [ZK Terminology](https://github.com/code-423n4/2023-10-zksync/blob/main/Circuits%20Section/ZK%20Terminology.md)
   - [Getting Started](https://github.com/code-423n4/2023-10-zksync/blob/main/Circuits%20Section/Getting%20Started.md)
- **Testing**
   - [Circuit example: Ecrecover test](https://www.notion.so/Circuit-example-Ecrecover-test-4c86cb5d14f9441988f53b0f624c44cc?pvs=21)
   - [Circuit test explained](https://www.notion.so/Circuit-test-explained-152bb55992484051b0711b7e8df919ef?pvs=21)
  
- **[Boojum gadgets](https://www.notion.so/Boojum-gadgets-265047bfa31a4f56b640cb34a732a078?pvs=21)**
- **[Circuits](https://www.notion.so/Circuits-c2e39db21b4446aa8f06318ae404d34f?pvs=21)**
- **[CS implementations](https://www.notion.so/CS-implementations-a288039100034cf489e3bbc417c5e2cf?pvs=21)**

### **3. VM Section**

The VM section is related to the zkSync Era Virtual Machine and contains elliptic curve precompiles and an extensive primer on zkSync EVM.

- **[ZkSync Era Virtual Machine Primer](https://github.com/code-423n4/2023-10-zksync/blob/main/VM%20Section/ZkSync%20Era%20Virtual%20Machine%20primer.md)**
    - This primer is designed to provide auditors with a foundational understanding of the zkSync Era Virtual Machine. It offers insights into the operational mechanics and integral components of zkSync EVM, serving as an essential guide for those seeking to explore the zkSync EVM environment.
- **[zkSync Era: The Equivalence Compiler Documentation](https://github.com/code-423n4/2023-10-zksync/blob/main/VM%20Section/compiler-equivalence-docs/zkSync%20Era%20-%20The%20Equivalence%20Compiler%20Documentation.md)**
    - zkSync Era is a layer 2 rollup that uses zero-knowledge proofs to scale Ethereum without compromising on security or decentralization. As it's EVM-compatible (with Solidity/Vyper), 99% of Ethereum projects can redeploy without needing to refactor or re-audit any code. zkSync Era also uses an LLVM-based compiler that will eventually enable developers to write smart contracts in popular languages such as C++ and Rust.
- **[spec.pdf](https://github.com/code-423n4/2023-10-zksync/blob/main/VM%20Section/spec.pdf)**
    - This document is a highly technical and detailed specification, providing an in-depth exploration of the zkSync protocol and its underlying architecture. It’s a comprehensive resource for those who desire a deeper and more formal understanding of the protocol's design and functionalities. While it’s not a required read for understanding the basic structure and operations of the protocol, it is an invaluable resource for those wishing to delve into the finer details and theoretical underpinnings of zkSync.

## **🚨 Audit & Code Freeze**

Be advised that a code freeze will be in effect for the duration of the audit to ensure a level playing field. All participants are required to review and adhere to the final versions of contracts and documentation added in this repository at least 48 business hours prior to the audit start time.

## **🚀 Getting Started for Auditors**

- Ensure to go through each section and related documents thoroughly.
- Keep in mind the overall working of the zkSync protocol while reviewing individual components.
- Review the code and documentation with a focus on security, correctness, and optimization, particularly concerning gas consumption.

## **📢 Communication**

For any clarifications, doubts, or discussion, please contact Code4rena staff, and we will address your concerns promptly.

## Links

- **Previous audits:** 
- **Documentation:**
- **Website:**
- **Twitter:** 
- **Discord:** 


# Scope

[ ⭐️ SPONSORS: add scoping and technical details here ]

- [ ] In the table format shown below, provide the name of each contract and:
  - [ ] source lines of code (excluding blank lines and comments) in each *For line of code counts, we recommend running prettier with a 100-character line length, and using [cloc](https://github.com/AlDanial/cloc).* 
  - [ ] external contracts called in each
  - [ ] libraries used in each

*List all files in scope in the table below (along with hyperlinks) -- and feel free to add notes here to emphasize areas of focus.*

| Contract | SLOC | Purpose | Libraries used |  
| ----------- | ----------- | ----------- | ----------- |
| [contracts/folder/sample.sol](contracts/folder/sample.sol) | 123 | This contract does XYZ | [`@openzeppelin/*`](https://openzeppelin.com/contracts/) |

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
