# Smart Contract Security Scanner

This project provides a Python script to analyze Solidity smart contracts for common security vulnerabilities. The script uses `Slither` for static analysis and highlights various issues such as uninitialized storage pointers, potential overflow/underflow, missing event emissions, low-level calls, and more.

## Features

- Detects uninitialized storage pointers
- Identifies potential overflow/underflow issues
- Checks for missing event emissions
- Finds low-level calls
- Alerts on arbitrary 'from' addresses
- Flags usage of `tx.origin`
- Detects unrestricted ether withdrawals
- Identifies hardcoded addresses

## Installation

To use this script, you need to have Python installed along with the necessary libraries. Follow the instructions below to set up your environment.

### Prerequisites

- Python 3.x
- `pip` package manager

### Install Required Libraries

```bash
pip install py-solc-x web3 slither-analyzer colorama
pip install solc-select

When prompted, enter the path to the Solidity contract file you want to test, e.g., /home/kali/ExenToken.sol
