# Smart Contract Security Scanner

This project provides a Python script to analyze Solidity smart contracts for common security vulnerabilities. The script uses `Slither` for static analysis and highlights various issues such as uninitialized storage pointers, potential overflow/underflow, missing event emissions, low-level calls, and more.

## Features

### Arbitrary 'from' Address:
    Checks if the from address in a call is used, which may allow unauthorized transactions.

### Default Visibility:
    Checks if functions have default visibility, making them accessible to anyone.

### Potential Reentrancy:
    Checks if payable functions have proper reentrancy guards.

### Insecure Delegatecall:
    Checks if delegatecall is used, which can lead to code execution in the context of the caller contract.

### Blockhash Dependence:
    Checks if block.blockhash is used, which can be manipulated to exploit block hashes.

### Insecure Randomness:
    Checks if block.timestamp or block.difficulty is used for randomness, which is insecure.

### Usage of tx.origin:
    Checks if tx.origin is used, which can be exploited in phishing attacks.

### Low-Level Call:
    Checks if low-level calls (call, delegatecall, send) are used without proper safety and readability.

### Improper Exception Handling:
    Checks if low-level calls are used without proper exception handling mechanisms like require, assert, or revert.

### Unchecked Low-Level Call:
    Checks if low-level calls are used without checking their success.

### Unrestricted Ether Withdrawal:
    Checks if Ether withdrawals can be made without proper restrictions, allowing unauthorized withdrawals.

### Gas Limit Issue:
    Checks if functions have a high number of nodes, potentially causing gas limit issues.

### External Function Call:
    Warns about potentially unsafe external calls.

### Uninitialized Storage Pointer:
    Checks if storage pointers are uninitialized, which can lead to unpredictable behavior.

### Hardcoded Address:
    Checks if addresses are hardcoded, reducing flexibility and security.

### Uninitialized Variable:
    Checks if variables are uninitialized, leading to unpredictable behavior.

### Variable Shadowing:
    Checks if local variables shadow state variables, which can lead to bugs.

### Missing Event Emission:
    Checks if critical state changes are made without emitting events for transparency and tracking.

### Deprecated Function:
    Checks if deprecated functions like suicide or throw are used.

### Missing Function Modifier:
    Checks if critical functions lack necessary modifiers (e.g., onlyOwner).

### Reentrancy with Multiple Calls:
    Checks if functions have multiple high-level calls, potentially leading to reentrancy issues.

### Missing ERC20 Return Value Check:
    Checks if ERC20 operations (e.g., transfer, approve, transferFrom) are used without checking their return values.


## Installation

To use this script, you need to have Python installed along with the necessary libraries. Follow the instructions below to set up your environment.

### Prerequisites

- Python 3.x
- `pip` package manager

### Install Required Libraries

```bash
pip install py-solc-x web3 slither-analyzer colorama
pip install solc-select

When prompted, enter the path to the Solidity contract file you want to test, e.g., /home/kali/redacted.sol
