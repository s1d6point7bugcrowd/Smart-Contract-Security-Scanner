import os
import re
import json
from solcx import compile_standard, install_solc, set_solc_version
from web3 import Web3
from slither import Slither
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Define directory paths
base_dir = os.path.dirname(os.path.abspath(__file__))
contracts_dir = os.path.join(base_dir, 'contracts')
tests_dir = os.path.join(base_dir, 'tests')

# Create directories if they do not exist
if not os.path.exists(contracts_dir):
    os.makedirs(contracts_dir)
if not os.path.exists(tests_dir):
    os.makedirs(tests_dir)

# Function to extract the Solidity compiler version from the contract
def extract_solidity_version(contract_path):
    with open(contract_path, 'r') as file:
        content = file.read()
        match = re.search(r'pragma solidity \^?([0-9.]+);', content)
        if match:
            return match.group(1)
        else:
            raise ValueError("Solidity version pragma not found in the contract.")

# Function to compile the Solidity contract
def compile_contract(contract_path, solc_version):
    set_solc_version(solc_version)
    with open(contract_path, 'r') as file:
        contract_source = file.read()

    compiled_sol = compile_standard({
        "language": "Solidity",
        "sources": {
            contract_path: {
                "content": contract_source
            }
        },
        "settings": {
            "outputSelection": {
                "*": {
                    "*": ["abi", "metadata", "evm.bytecode", "evm.sourceMap"]
                }
            }
        }
    })

    return compiled_sol

# Function to detect issues using Slither
def detect_issues(contract_path):
    slither = Slither(contract_path)

    issues = []

    # Detect Arbitrary From
    for contract in slither.contracts:
        for function in contract.functions:
            for node in function.nodes:
                if node.type == "HighLevelCall" and node.expression:
                    if "from" in str(node.expression):
                        issues.append(Fore.RED + f"Arbitrary 'from' address found in function {function.name} in contract {contract.name}")

    # Detect Functions Default Visibility
    for contract in slither.contracts:
        for function in contract.functions:
            if function.visibility == "default":
                issues.append(Fore.YELLOW + f"Function {function.name} in contract {contract.name} has default visibility")

    # Detect Uninitialized Storage Pointer
    for contract in slither.contracts:
        for variable in contract.state_variables:
            if variable.is_stored and variable.uninitialized:
                issues.append(Fore.RED + f"Uninitialized storage pointer found in contract {contract.name}")

    # Detect Reentrancy
    for contract in slither.contracts:
        for function in contract.functions:
            for node in function.nodes:
                if node.type == "HighLevelCall" and function.is_payable:
                    issues.append(Fore.RED + f"Potential reentrancy in function {function.name} in contract {contract.name}")

    # Detect Delegatecall
    for contract in slither.contracts:
        for function in contract.functions:
            for node in function.nodes:
                if node.type == "HighLevelCall" and node.expression and "delegatecall" in str(node.expression):
                    issues.append(Fore.RED + f"Insecure delegatecall in function {function.name} in contract {contract.name}")

    # Detect Blockhash Dependence
    for contract in slither.contracts:
        for function in contract.functions:
            for node in function.nodes:
                if node.expression and "block.blockhash" in str(node.expression):
                    issues.append(Fore.RED + f"Blockhash dependence found in function {function.name} in contract {contract.name}")

    # Detect Insecure Randomness
    for contract in slither.contracts:
        for function in contract.functions:
            for node in function.nodes:
                if node.expression and ("block.timestamp" in str(node.expression) or "block.difficulty" in str(node.expression)):
                    issues.append(Fore.RED + f"Insecure randomness source found in function {function.name} in contract {contract.name}")

    # Detect usage of tx.origin
    for contract in slither.contracts:
        for function in contract.functions:
            for node in function.nodes:
                if node.expression and "tx.origin" in str(node.expression):
                    issues.append(Fore.RED + f"Usage of tx.origin found in function {function.name} in contract {contract.name}")

    # Detect unrestricted ether withdrawal
    for contract in slither.contracts:
        for function in contract.functions:
            if function.name == "withdraw" and function.visibility == "public":
                issues.append(Fore.RED + f"Unrestricted ether withdrawal found in function {function.name} in contract {contract.name}")

    # Detect integer overflows and underflows
    for contract in slither.contracts:
        for function in contract.functions:
            for node in function.nodes:
                if node.expression and ("+" in str(node.expression) or "-" in str(node.expression)):
                    issues.append(Fore.RED + f"Potential overflow/underflow in function {function.name} in contract {contract.name}")

    # Detect hardcoded addresses
    for contract in slither.contracts:
        for variable in contract.state_variables:
            if variable.type == "address" and variable.value:
                issues.append(Fore.YELLOW + f"Hardcoded address found in contract {contract.name}")

    # Detect missing event emissions
    for contract in slither.contracts:
        for function in contract.functions:
            if function.visibility in ["public", "external"]:
                state_change = any(node.state_variables_written for node in function.nodes)
                emits_event = any(node.type == "EmitStatement" for node in function.nodes)
                if state_change and not emits_event:
                    issues.append(Fore.YELLOW + f"Missing event emission in function {function.name} in contract {contract.name}")

    # Detect low-level calls
    for contract in slither.contracts:
        for function in contract.functions:
            for node in function.nodes:
                if node.expression and ("call" in str(node.expression) or "delegatecall" in str(node.expression) or "send" in str(node.expression)):
                    issues.append(Fore.RED + f"Low-level call found in function {function.name} in contract {contract.name}")

    return issues

# Main function to run the script
def main():
    print(Fore.CYAN + "Enter the path to the Solidity contract file you want to test:")
    contract_path = input().strip()

    # Ensure the contract file exists
    if not os.path.exists(contract_path):
        print(Fore.RED + f"Error: The contract file {contract_path} does not exist.")
        return

    try:
        # Extract and install the required Solidity version
        solc_version = extract_solidity_version(contract_path)
        install_solc(solc_version)
        
        # Set the SOLC_VERSION environment variable using solc-select
        os.system(f'solc-select install {solc_version}')
        os.system(f'solc-select use {solc_version}')
        
    except ValueError as e:
        print(Fore.RED + f"Error: {e}")
        return

    # Compile the contract
    compiled_contract = compile_contract(contract_path, solc_version)
    print(Fore.GREEN + "Contract compiled successfully")

    # Detect issues
    issues = detect_issues(contract_path)
    if issues:
        print(Fore.YELLOW + "Issues found:")
        for issue in issues:
            print(issue)
    else:
        print(Fore.GREEN + "No issues found")

if __name__ == "__main__":
    main()
