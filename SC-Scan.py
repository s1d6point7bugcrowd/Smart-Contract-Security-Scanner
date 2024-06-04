import os
import re
import json
from collections import defaultdict
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

    issues = defaultdict(list)

    def add_issue(issue_type, description, severity, contract, function=None):
        color = Fore.RED if severity == "critical" else Fore.YELLOW if severity == "warning" else Fore.BLUE
        issue_message = color + f"{issue_type}: {description}"
        if function:
            issues[contract].append(f"{issue_message} (Function: {function})")
        else:
            issues[contract].append(issue_message)

    # Detect Arbitrary From
    for contract in slither.contracts:
        for function in contract.functions:
            for node in function.nodes:
                if node.type == "HighLevelCall" and node.expression:
                    if "from" in str(node.expression):
                        add_issue(
                            "Arbitrary 'from' Address",
                            "Uses 'from' in a call, which may allow unauthorized transactions.",
                            "critical",
                            contract.name,
                            function.name
                        )

    # Detect Functions Default Visibility
    for contract in slither.contracts:
        for function in contract.functions:
            if function.visibility == "default":
                add_issue(
                    "Default Visibility",
                    "Has default visibility, making it accessible to anyone.",
                    "warning",
                    contract.name,
                    function.name
                )

    # Detect Uninitialized Storage Pointer
    for contract in slither.contracts:
        for variable in contract.state_variables:
            if variable.is_stored and variable.uninitialized:
                add_issue(
                    "Uninitialized Storage Pointer",
                    "Can lead to unpredictable behavior.",
                    "critical",
                    contract.name
                )

    # Detect Reentrancy
    for contract in slither.contracts:
        for function in contract.functions:
            for node in function.nodes:
                if node.type == "HighLevelCall" and function.is_payable:
                    add_issue(
                        "Potential Reentrancy",
                        "Ensure proper reentrancy guards are in place.",
                        "critical",
                        contract.name,
                        function.name
                    )

    # Detect Delegatecall
    for contract in slither.contracts:
        for function in contract.functions:
            for node in function.nodes:
                if node.type == "HighLevelCall" and node.expression and "delegatecall" in str(node.expression):
                    add_issue(
                        "Insecure Delegatecall",
                        "Delegatecalls can lead to code execution in the context of the caller contract.",
                        "critical",
                        contract.name,
                        function.name
                    )

    # Detect Blockhash Dependence
    for contract in slither.contracts:
        for function in contract.functions:
            for node in function.nodes:
                if node.expression and "block.blockhash" in str(node.expression):
                    add_issue(
                        "Blockhash Dependence",
                        "This can be exploited to manipulate block hashes.",
                        "critical",
                        contract.name,
                        function.name
                    )

    # Detect Insecure Randomness
    for contract in slither.contracts:
        for function in contract.functions:
            for node in function.nodes:
                if node.expression and ("block.timestamp" in str(node.expression) or "block.difficulty" in str(node.expression)):
                    add_issue(
                        "Insecure Randomness",
                        "Avoid using block properties for randomness.",
                        "critical",
                        contract.name,
                        function.name
                    )

    # Detect usage of tx.origin
    for contract in slither.contracts:
        for function in contract.functions:
            for node in function.nodes:
                if node.expression and "tx.origin" in str(node.expression):
                    add_issue(
                        "Usage of tx.origin",
                        "This can be exploited in phishing attacks.",
                        "critical",
                        contract.name,
                        function.name
                    )

    # Detect unrestricted ether withdrawal
    for contract in slither.contracts:
        for function in contract.functions:
            if function.name == "withdraw" and function.visibility == "public":
                add_issue(
                    "Unrestricted Ether Withdrawal",
                    "This can allow unauthorized withdrawals.",
                    "critical",
                    contract.name,
                    function.name
                )

    # Detect integer overflows and underflows
    for contract in slither.contracts:
        for function in contract.functions:
            for node in function.nodes:
                if node.expression and ("+" in str(node.expression) or "-" in str(node.expression)):
                    add_issue(
                        "Potential Overflow/Underflow",
                        "Use safe math libraries to prevent this.",
                        "critical",
                        contract.name,
                        function.name
                    )

    # Detect hardcoded addresses
    for contract in slither.contracts:
        for variable in contract.state_variables:
            if variable.type == "address" and variable.value:
                add_issue(
                    "Hardcoded Address",
                    "Avoid using hardcoded addresses for better flexibility and security.",
                    "warning",
                    contract.name
                )

    # Detect missing event emissions
    for contract in slither.contracts:
        for function in contract.functions:
            if function.visibility in ["public", "external"]:
                state_change = any(node.state_variables_written for node in function.nodes)
                emits_event = any(node.type == "EmitStatement" for node in function.nodes)
                if state_change and not emits_event:
                    add_issue(
                        "Missing Event Emission",
                        "Emit events for critical state changes.",
                        "warning",
                        contract.name,
                        function.name
                    )

    # Detect low-level calls
    for contract in slither.contracts:
        for function in contract.functions:
            for node in function.nodes:
                if node.expression and ("call" in str(node.expression) or "delegatecall" in str(node.expression) or "send" in str(node.expression)):
                    add_issue(
                        "Low-Level Call",
                        "Use higher-level functions for better safety and readability.",
                        "critical",
                        contract.name,
                        function.name
                    )

    # Detect access control issues
    for contract in slither.contracts:
        for function in contract.functions:
            if function.visibility in ["public", "external"] and not function.is_constructor:
                has_access_control = any("onlyOwner" in str(node.expression) or "onlyAdmin" in str(node.expression) for node in function.nodes if node.expression)
                if not has_access_control:
                    add_issue(
                        "Access Control Issue",
                        "Ensure access control is properly implemented.",
                        "critical",
                        contract.name,
                        function.name
                    )

    # Detect use of deprecated functions
    deprecated_functions = ["suicide", "throw"]
    for contract in slither.contracts:
        for function in contract.functions:
            for node in function.nodes:
                if node.expression and any(func in str(node.expression) for func in deprecated_functions):
                    add_issue(
                        "Deprecated Function",
                        "Replace deprecated functions with their modern equivalents.",
                        "critical",
                        contract.name,
                        function.name
                    )

    # Detect improper handling of exceptions
    for contract in slither.contracts:
        for function in contract.functions:
            for node in function.nodes:
                if node.type == "LowLevelCall" and not any(handler in str(node.expression) for handler in ["require", "assert", "revert"]):
                    add_issue(
                        "Improper Exception Handling",
                        "Ensure proper exception handling mechanisms are in place.",
                        "critical",
                        contract.name,
                        function.name
                    )

    # Detect front-running vulnerabilities
    for contract in slither.contracts:
        for function in contract.functions:
            for node in function.nodes:
                if node.expression and "block.timestamp" in str(node.expression):
                    add_issue(
                        "Front-Running Vulnerability",
                        "Avoid using block timestamps for critical logic.",
                        "critical",
                        contract.name,
                        function.name
                    )

    # Detect gas limit issues
    for contract in slither.contracts:
        for function in contract.functions:
            if len(function.nodes) > 20:  # Arbitrary threshold for complexity
                add_issue(
                    "Gas Limit Issue",
                    "Optimize the function to reduce gas consumption.",
                    "critical",
                    contract.name,
                    function.name
                )

    # Detect timestamp dependence
    for contract in slither.contracts:
        for function in contract.functions:
            for node in function.nodes:
                if node.expression and "block.timestamp" in str(node.expression):
                    add_issue(
                        "Timestamp Dependence",
                        "Avoid using block timestamps for time-sensitive logic.",
                        "critical",
                        contract.name,
                        function.name
                    )

    # Detect shadowing variables
    for contract in slither.contracts:
        for function in contract.functions:
            for variable in function.variables:
                if any(state_var.name == variable.name for state_var in contract.state_variables):
                    add_issue(
                        "Shadowing Variable",
                        "Avoid variable shadowing to prevent bugs.",
                        "critical",
                        contract.name,
                        function.name
                    )

    # Detect reentrancy with multiple calls
    for contract in slither.contracts:
        for function in contract.functions:
            call_count = sum(1 for node in function.nodes if node.type == "HighLevelCall")
            if call_count > 1:
                add_issue(
                    "Reentrancy with Multiple Calls",
                    "Ensure proper reentrancy guards are in place.",
                    "critical",
                    contract.name,
                    function.name
                )

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
        print(Fore.YELLOW + "Issues found:\n")
        for contract, contract_issues in issues.items():
            print(Fore.BLUE + f"Contract: {contract}")
            for issue in contract_issues:
                print(f"  - {issue}")
            print()  # New line for better readability
    else:
        print(Fore.GREEN + "No issues found")

if __name__ == "__main__":
    main()
