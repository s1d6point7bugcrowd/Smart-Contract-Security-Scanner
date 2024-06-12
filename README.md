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

pip install web3 py-solc-x slither-analyzer colorama termcolor tabulate





Output:

python3 smart-contract-vuln-scan.py
Enter the path to the Solidity contract file you want to test:
/home/kali/vulnerable-test.sol
Installing solc '0.8.0'...
Version '0.8.0' installed.
Switched global version to 0.8.0
Contract compiled successfully
Issues found:

+--------------------+------------------------+--------------------------------+---------------------------------------------------------------+------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Contract           | Function               | Issue Type                     | Description                                                   | Severity   | Explanation                                                                                                                                                |
+====================+========================+================================+===============================================================+============+============================================================================================================================================================+
| VulnerableContract | constructor            |  Low-Level Call                | Use higher-level functions for better safety and readability. | critical   | Low-level calls like call, delegatecall, and send are error-prone and should be avoided. Use higher-level functions for better safety and readability.     |
+--------------------+------------------------+--------------------------------+---------------------------------------------------------------+------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| VulnerableContract | deposit                |  Low-Level Call                | Use higher-level functions for better safety and readability. | critical   | Low-level calls like call, delegatecall, and send are error-prone and should be avoided. Use higher-level functions for better safety and readability.     |
+--------------------+------------------------+--------------------------------+---------------------------------------------------------------+------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| VulnerableContract | withdraw               |  Low-Level Call                | Use higher-level functions for better safety and readability. | critical   | Low-level calls like call, delegatecall, and send are error-prone and should be avoided. Use higher-level functions for better safety and readability.     |
+--------------------+------------------------+--------------------------------+---------------------------------------------------------------+------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| VulnerableContract | withdraw               |  Low-Level Call                | Use higher-level functions for better safety and readability. | critical   | Low-level calls like call, delegatecall, and send are error-prone and should be avoided. Use higher-level functions for better safety and readability.     |
+--------------------+------------------------+--------------------------------+---------------------------------------------------------------+------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| VulnerableContract | withdraw               |  Low-Level Call                | Use higher-level functions for better safety and readability. | critical   | Low-level calls like call, delegatecall, and send are error-prone and should be avoided. Use higher-level functions for better safety and readability.     |
+--------------------+------------------------+--------------------------------+---------------------------------------------------------------+------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| VulnerableContract | withdraw               |  Unrestricted Ether Withdrawal | This can allow unauthorized withdrawals.                      | critical   | Public functions allowing unrestricted Ether withdrawal can be exploited by anyone to drain the contract's funds. Restrict access to such functions.       |
+--------------------+------------------------+--------------------------------+---------------------------------------------------------------+------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| VulnerableContract | transfer               |  Low-Level Call                | Use higher-level functions for better safety and readability. | critical   | Low-level calls like call, delegatecall, and send are error-prone and should be avoided. Use higher-level functions for better safety and readability.     |
+--------------------+------------------------+--------------------------------+---------------------------------------------------------------+------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| VulnerableContract | transfer               |  Low-Level Call                | Use higher-level functions for better safety and readability. | critical   | Low-level calls like call, delegatecall, and send are error-prone and should be avoided. Use higher-level functions for better safety and readability.     |
+--------------------+------------------------+--------------------------------+---------------------------------------------------------------+------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| VulnerableContract | getRandomNumber        |  Insecure Randomness           | Avoid using block properties for randomness.                  | critical   | Using block properties like timestamp or difficulty for randomness is insecure as they can be predicted or manipulated. Use a secure source of randomness. |
+--------------------+------------------------+--------------------------------+---------------------------------------------------------------+------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| VulnerableContract | getRandomNumber        |  Front-Running Vulnerability   | Avoid using block timestamps for critical logic.              | critical   | Using block timestamps for critical logic can be manipulated by miners to front-run transactions. Avoid using block timestamps for sensitive operations.   |
+--------------------+------------------------+--------------------------------+---------------------------------------------------------------+------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| VulnerableContract | onlyOwner              |  Usage of tx.origin            | This can be exploited in phishing attacks.                    | critical   | Using tx.origin to check for the sender of a transaction can be exploited in phishing attacks. Always use msg.sender for authentication.                   |
+--------------------+------------------------+--------------------------------+---------------------------------------------------------------+------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| VulnerableContract | lowLevelCall           |  Low-Level Call                | Use higher-level functions for better safety and readability. | critical   | Low-level calls like call, delegatecall, and send are error-prone and should be avoided. Use higher-level functions for better safety and readability.     |
+--------------------+------------------------+--------------------------------+---------------------------------------------------------------+------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| VulnerableContract | lowLevelCall           |  Low-Level Call                | Use higher-level functions for better safety and readability. | critical   | Low-level calls like call, delegatecall, and send are error-prone and should be avoided. Use higher-level functions for better safety and readability.     |
+--------------------+------------------------+--------------------------------+---------------------------------------------------------------+------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| VulnerableContract | uncheckedLowLevelCall  |  Low-Level Call                | Use higher-level functions for better safety and readability. | critical   | Low-level calls like call, delegatecall, and send are error-prone and should be avoided. Use higher-level functions for better safety and readability.     |
+--------------------+------------------------+--------------------------------+---------------------------------------------------------------+------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| VulnerableContract | getAnotherRandomNumber |  Insecure Randomness           | Avoid using block properties for randomness.                  | critical   | Using block properties like timestamp or difficulty for randomness is insecure as they can be predicted or manipulated. Use a secure source of randomness. |
+--------------------+------------------------+--------------------------------+---------------------------------------------------------------+------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| VulnerableContract | getAnotherRandomNumber |  Front-Running Vulnerability   | Avoid using block timestamps for critical logic.              | critical   | Using block timestamps for critical logic can be manipulated by miners to front-run transactions. Avoid using block timestamps for sensitive operations.   |
+--------------------+------------------------+--------------------------------+---------------------------------------------------------------+------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| VulnerableContract | flashLoanExploit       |  Low-Level Call                | Use higher-level functions for better safety and readability. | critical   | Low-level calls like call, delegatecall, and send are error-prone and should be avoided. Use higher-level functions for better safety and readability.     |
+--------------------+------------------------+--------------------------------+---------------------------------------------------------------+------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| VulnerableContract | flashLoanExploit       |  Low-Level Call                | Use higher-level functions for better safety and readability. | critical   | Low-level calls like call, delegatecall, and send are error-prone and should be avoided. Use higher-level functions for better safety and readability.     |
+--------------------+------------------------+--------------------------------+---------------------------------------------------------------+------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| VulnerableContract |                        |  Uninitialized Storage Pointer | Can lead to unpredictable behavior.                           | critical   | Uninitialized storage pointers can lead to unpredictable behavior and security issues. Always initialize storage pointers.                                 |
+--------------------+------------------------+--------------------------------+---------------------------------------------------------------+------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| VulnerableContract |                        |  Uninitialized Variable        | Ensure all variables are properly initialized.                | critical   | Uninitialized variables can lead to unexpected behavior and security issues. Ensure all variables are properly initialized.                                |
+--------------------+------------------------+--------------------------------+---------------------------------------------------------------+------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| VulnerableContract |                        |  Uninitialized Storage Pointer | Can lead to unpredictable behavior.                           | critical   | Uninitialized storage pointers can lead to unpredictable behavior and security issues. Always initialize storage pointers.                                 |
+--------------------+------------------------+--------------------------------+---------------------------------------------------------------+------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| VulnerableContract |                        |  Uninitialized Variable        | Ensure all variables are properly initialized.                | critical   | Uninitialized variables can lead to unexpected behavior and security issues. Ensure all variables are properly initialized.                                |
+--------------------+------------------------+--------------------------------+---------------------------------------------------------------+------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| VulnerableContract |                        |  Uninitialized Storage Pointer | Can lead to unpredictable behavior.                           | critical   | Uninitialized storage pointers can lead to unpredictable behavior and security issues. Always initialize storage pointers.                                 |
+--------------------+------------------------+--------------------------------+---------------------------------------------------------------+------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| VulnerableContract |                        |  Uninitialized Variable        | Ensure all variables are properly initialized.                | critical   | Uninitialized variables can lead to unexpected behavior and security issues. Ensure all variables are properly initialized.                                |
+--------------------+------------------------+--------------------------------+---------------------------------------------------------------+------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
                                                                       
Issues saved to /home/kali/smart_contract_vulnerabilities.html

When prompted, enter the path to the Solidity contract file you want to test, e.g., /home/kali/redacted.sol
