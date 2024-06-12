import os
import re
from collections import defaultdict
from solcx import compile_standard, install_solc, set_solc_version
from slither import Slither
from colorama import Fore, Style, init
from termcolor import colored
from tabulate import tabulate

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
        explanation = get_explanation(issue_type)
        issue_message = f"{Fore.RED if severity == 'critical' else Fore.YELLOW} {issue_type}: {description}\n{Fore.WHITE}Explanation: {explanation}"
        if function:
            issues[contract].append((issue_message, function, severity))
        else:
            issues[contract].append((issue_message, "", severity))

    # Detect various issues
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
                if function.visibility == "default":
                    add_issue(
                        "Default Visibility",
                        "Has default visibility, making it accessible to anyone.",
                        "warning",
                        contract.name,
                        function.name
                    )
                if node.type == "HighLevelCall" and function.is_payable:
                    add_issue(
                        "Potential Reentrancy",
                        "Ensure proper reentrancy guards are in place.",
                        "critical",
                        contract.name,
                        function.name
                    )
                if node.type == "HighLevelCall" and node.expression and "delegatecall" in str(node.expression):
                    add_issue(
                        "Insecure Delegatecall",
                        "Delegatecalls can lead to code execution in the context of the caller contract.",
                        "critical",
                        contract.name,
                        function.name
                    )
                if node.expression and "block.blockhash" in str(node.expression):
                    add_issue(
                        "Blockhash Dependence",
                        "This can be exploited to manipulate block hashes.",
                        "critical",
                        contract.name,
                        function.name
                    )
                if node.expression and ("block.timestamp" in str(node.expression) or "block.difficulty" in str(node.expression)):
                    add_issue(
                        "Insecure Randomness",
                        "Avoid using block properties for randomness.",
                        "critical",
                        contract.name,
                        function.name
                    )
                if node.expression and "tx.origin" in str(node.expression):
                    add_issue(
                        "Usage of tx.origin",
                        "This can be exploited in phishing attacks.",
                        "critical",
                        contract.name,
                        function.name
                    )
                if node.expression and ("call" in str(node.expression) or "delegatecall" in str(node.expression) or "send" in str(node.expression)):
                    add_issue(
                        "Low-Level Call",
                        "Use higher-level functions for better safety and readability.",
                        "critical",
                        contract.name,
                        function.name
                    )
                if node.type == "LowLevelCall" and not any(handler in str(node.expression) for handler in ["require", "assert", "revert"]):
                    add_issue(
                        "Improper Exception Handling",
                        "Ensure proper exception handling mechanisms are in place.",
                        "critical",
                        contract.name,
                        function.name
                    )
                if node.expression and "block.timestamp" in str(node.expression):
                    add_issue(
                        "Front-Running Vulnerability",
                        "Avoid using block timestamps for critical logic.",
                        "critical",
                        contract.name,
                        function.name
                    )
                if node.type == "LowLevelCall" and not node.expression.contains("success"):
                    add_issue(
                        "Unchecked Low-Level Call",
                        "Ensure the success of low-level calls is checked.",
                        "critical",
                        contract.name,
                        function.name
                    )

            if function.name == "withdraw" and function.visibility == "public":
                add_issue(
                    "Unrestricted Ether Withdrawal",
                    "This can allow unauthorized withdrawals.",
                    "critical",
                    contract.name,
                    function.name
                )
            if len(function.nodes) > 20:
                add_issue(
                    "Gas Limit Issue",
                    "Optimize the function to reduce gas consumption.",
                    "critical",
                    contract.name,
                    function.name
                )
            if any(node.type == "HighLevelCall" for node in function.nodes):
                add_issue(
                    "External Function Call",
                    "Ensure external calls are safe and necessary.",
                    "warning",
                    contract.name,
                    function.name
                )

        for variable in contract.state_variables:
            if variable.is_stored and variable.uninitialized:
                add_issue(
                    "Uninitialized Storage Pointer",
                    "Can lead to unpredictable behavior.",
                    "critical",
                    contract.name
                )
            if variable.type == "address" and variable.value:
                add_issue(
                    "Hardcoded Address",
                    "Avoid using hardcoded addresses for better flexibility and security.",
                    "warning",
                    contract.name
                )
            if variable.uninitialized:
                add_issue(
                    "Uninitialized Variable",
                    "Ensure all variables are properly initialized.",
                    "critical",
                    contract.name
                )

        for variable in function.variables:
            if any(state_var.name == variable.name for state_var in contract.state_variables):
                add_issue(
                    "Shadowing Variable",
                    "Avoid variable shadowing to prevent bugs.",
                    "critical",
                    contract.name,
                    function.name
                )

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

        deprecated_functions = ["suicide", "throw"]
        for node in function.nodes:
            if node.expression and any(func in str(node.expression) for func in deprecated_functions):
                add_issue(
                    "Deprecated Function",
                    "Replace deprecated functions with their modern equivalents.",
                    "critical",
                    contract.name,
                    function.name
                )

        for modifier in function.modifiers:
            if modifier == "onlyOwner" and not function.is_restricted:
                add_issue(
                    "Missing Function Modifier",
                    "Ensure critical functions have the necessary modifiers.",
                    "critical",
                    contract.name,
                    function.name
                )

        call_count = sum(1 for node in function.nodes if node.type == "HighLevelCall")
        if call_count > 1:
            add_issue(
                "Reentrancy with Multiple Calls",
                "Ensure proper reentrancy guards are in place.",
                "critical",
                contract.name,
                function.name
            )

        for function in contract.functions:
            if any("ERC20" in var.type.__str__() for var in function.variables) and not any(check in function.name for check in ["require", "assert"]):
                add_issue(
                    "Missing ERC20 Return Value Check",
                    "Check the return value of ERC20 operations.",
                    "critical",
                    contract.name,
                    function.name
                )

    return issues

# Function to get explanations for each issue type
def get_explanation(issue_type):
    explanations = {
        "Arbitrary 'from' Address": "Using 'from' in a call can allow unauthorized transactions if the caller can set the 'from' address arbitrarily. This can lead to unauthorized fund transfers or other malicious actions.",
        "Default Visibility": "Functions with default visibility are accessible to anyone, which may not be intended. Always specify the visibility to avoid unauthorized access.",
        "Potential Reentrancy": "Reentrancy attacks occur when an external call is made to another contract before updating the state. The external contract can call back into the original function, leading to multiple executions and potential loss of funds.",
        "Insecure Delegatecall": "Delegatecalls can execute code in the context of the caller contract. If not used carefully, it can lead to code injection and execution of malicious code.",
        "Blockhash Dependence": "Using block hashes for critical logic can be manipulated by miners to achieve a favorable outcome, leading to unfair or predictable behavior.",
        "Insecure Randomness": "Using block properties like timestamp or difficulty for randomness is insecure as they can be predicted or manipulated. Use a secure source of randomness.",
        "Usage of tx.origin": "Using tx.origin to check for the sender of a transaction can be exploited in phishing attacks. Always use msg.sender for authentication.",
        "Low-Level Call": "Low-level calls like call, delegatecall, and send are error-prone and should be avoided. Use higher-level functions for better safety and readability.",
        "Improper Exception Handling": "Ensure proper exception handling mechanisms like require, assert, or revert are in place to handle errors gracefully.",
        "Front-Running Vulnerability": "Using block timestamps for critical logic can be manipulated by miners to front-run transactions. Avoid using block timestamps for sensitive operations.",
        "Unchecked Low-Level Call": "Ensure the success of low-level calls is checked to avoid unexpected behavior or loss of funds.",
        "Unrestricted Ether Withdrawal": "Public functions allowing unrestricted Ether withdrawal can be exploited by anyone to drain the contract's funds. Restrict access to such functions.",
        "Gas Limit Issue": "Functions with high gas consumption can hit the gas limit, causing transactions to fail. Optimize the function to reduce gas consumption.",
        "External Function Call": "Ensure external calls to other contracts are safe and necessary. External calls can introduce vulnerabilities like reentrancy.",
        "Uninitialized Storage Pointer": "Uninitialized storage pointers can lead to unpredictable behavior and security issues. Always initialize storage pointers.",
        "Hardcoded Address": "Avoid using hardcoded addresses for better flexibility and security. Use configuration or contract parameters instead.",
        "Uninitialized Variable": "Uninitialized variables can lead to unexpected behavior and security issues. Ensure all variables are properly initialized.",
        "Shadowing Variable": "Variable shadowing can lead to bugs and unexpected behavior. Avoid variable shadowing by using distinct names for variables.",
        "Missing Event Emission": "Emit events for critical state changes to enable tracking and monitoring of the contract's state. Missing events can make it harder to detect issues.",
        "Deprecated Function": "Replace deprecated functions like suicide and throw with their modern equivalents like selfdestruct and revert.",
        "Missing Function Modifier": "Ensure critical functions have the necessary modifiers to restrict access and protect the contract from unauthorized actions.",
        "Reentrancy with Multiple Calls": "Ensure proper reentrancy guards are in place to prevent reentrancy attacks when multiple external calls are made in a function.",
        "Missing ERC20 Return Value Check": "Check the return value of ERC20 operations to ensure they succeeded. Failure to do so can lead to loss of funds or incorrect behavior."
    }
    return explanations.get(issue_type, "No explanation available.")

# Function to display issues in a table
def display_issues(issues):
    headers = ["Contract", "Function", "Issue Type", "Description", "Severity", "Explanation"]
    rows = []
    for contract, contract_issues in issues.items():
        for issue, function, severity in contract_issues:
            issue_info = issue.split(": ", 1)
            issue_type = issue_info[0].strip()
            description = issue_info[1].split("\n")[0].strip()
            explanation = issue_info[1].split("Explanation: ")[1].strip()
            color = "red" if severity == "critical" else "yellow" if severity == "warning" else "blue"
            rows.append([contract, function, colored(issue_type, color), colored(description, color), severity, explanation])

    print(tabulate(rows, headers, tablefmt="grid"))

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
        display_issues(issues)
    else:
        print(Fore.GREEN + "No issues found")

if __name__ == "__main__":
    main()
