import os
import re
import urllib.error
from collections import defaultdict
from solcx import compile_standard, install_solc, set_solc_version
from slither.slither import Slither
from colorama import Fore, Style, init
from termcolor import colored
from tabulate import tabulate
import html

# Initialize colorama
init(autoreset=True)

# List of supported EVM versions
SUPPORTED_EVM_VERSIONS = [
    "homestead", "tangerineWhistle", "spuriousDragon",
    "byzantium", "constantinople", "petersburg", "istanbul",
    "berlin", "london", "paris", "shanghai", "cancun", "prague"
]

# Function to extract the Solidity compiler version from the contract
def extract_solidity_version(contract_path):
    with open(contract_path, 'r') as file:
        content = file.read()
        match = re.search(r'pragma solidity\s+([0-9.]+);', content)
        if match:
            return match.group(1)
        else:
            raise ValueError("Solidity version pragma not found in the contract.")

# Function to compile the Solidity contract
def compile_contract(contract_path, solc_version, remappings_file, evm_version, additional_contracts):
    if evm_version not in SUPPORTED_EVM_VERSIONS:
        raise ValueError(f"Invalid EVM version specified: {evm_version}. Supported versions: {SUPPORTED_EVM_VERSIONS}")

    set_solc_version(solc_version)
    with open(contract_path, 'r') as file:
        contract_source = file.read()

    # Read remappings from the remappings file
    remappings = []
    if os.path.exists(remappings_file):
        with open(remappings_file, 'r') as file:
            remappings = file.readlines()
        remappings = [line.strip() for line in remappings]

    print(Fore.CYAN + "Remappings applied:")
    for remap in remappings:
        print(Fore.CYAN + remap)

    # Include local files and node_modules in the sources
    sources = {os.path.basename(contract_path): {"content": contract_source}}
    base_path = os.path.dirname(contract_path)

    # Add remappings as sources
    for remap in remappings:
        prefix, path = remap.split('=')
        full_path = os.path.join(base_path, path)
        if os.path.isdir(full_path):
            for root, _, files in os.walk(full_path):
                for file in files:
                    if file.endswith('.sol'):
                        rel_dir = os.path.relpath(root, base_path)
                        rel_file = os.path.join(rel_dir, file)
                        with open(os.path.join(root, file), 'r') as f:
                            sources[rel_file] = {'content': f.read()}

    # Explicitly include additional contract files if not already included by remappings
    for additional_contract in additional_contracts:
        additional_contract_path = os.path.join(base_path, additional_contract)
        if os.path.exists(additional_contract_path) and os.path.basename(additional_contract_path) not in sources:
            with open(additional_contract_path, 'r') as f:
                sources[os.path.basename(additional_contract_path)] = {'content': f.read()}

    compiled_sol = compile_standard({
        "language": "Solidity",
        "sources": sources,
        "settings": {
            "remappings": remappings,
            "outputSelection": {
                "*": {
                    "*": ["abi", "metadata", "evm.bytecode", "evm.sourceMap"]
                }
            },
            "evmVersion": evm_version  # Use user-provided EVM version
        }
    })

    return compiled_sol

# Function to detect issues using Slither
def detect_issues(contract_path, solc_version, evm_version):
    try:
        # Recompile the contract with the correct EVM version
        slither = Slither(contract_path, solc_args=["--evm-version", evm_version])

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
                function_checked_issues = set()
                function_code = "".join(str(node.expression) for node in function.nodes if node.expression)
                for node in function.nodes:
                    if node.type == "HighLevelCall" and node.expression:
                        if "from" in str(node.expression) and "Arbitrary 'from' Address" not in function_checked_issues:
                            add_issue(
                                "Arbitrary 'from' Address",
                                "Uses 'from' in a call, which may allow unauthorized transactions.",
                                "critical",
                                contract.name,
                                function.name
                            )
                            function_checked_issues.add("Arbitrary 'from' Address")
                    if function.visibility == "default" and "Default Visibility" not in function_checked_issues:
                        add_issue(
                            "Default Visibility",
                            "Has default visibility, making it accessible to anyone.",
                            "warning",
                            contract.name,
                            function.name
                        )
                        function_checked_issues.add("Default Visibility")
                    if function.payable and any(n.type == "HighLevelCall" for n in function.nodes) and "Potential Reentrancy" not in function_checked_issues:
                        add_issue(
                            "Potential Reentrancy",
                            "Ensure proper reentrancy guards are in place.",
                            "critical",
                            contract.name,
                            function.name
                        )
                        function_checked_issues.add("Potential Reentrancy")
                    if node.type == "HighLevelCall" and node.expression and "delegatecall" in str(node.expression) and "Insecure Delegatecall" not in function_checked_issues:
                        add_issue(
                            "Insecure Delegatecall",
                            "Delegatecalls can lead to code execution in the context of the caller contract.",
                            "critical",
                            contract.name,
                            function.name
                        )
                        function_checked_issues.add("Insecure Delegatecall")
                    if node.expression and "block.blockhash" in str(node.expression) and "Blockhash Dependence" not in function_checked_issues:
                        add_issue(
                            "Blockhash Dependence",
                            "This can be exploited to manipulate block hashes.",
                            "critical",
                            contract.name,
                            function.name
                        )
                        function_checked_issues.add("Blockhash Dependence")
                    if node.expression and ("block.timestamp" in str(node.expression) or "block.difficulty" in str(node.expression)) and "Insecure Randomness" not in function_checked_issues:
                        add_issue(
                            "Insecure Randomness",
                            "Avoid using block properties for randomness.",
                            "critical",
                            contract.name,
                            function.name
                        )
                        function_checked_issues.add("Insecure Randomness")
                    if node.expression and "tx.origin" in str(node.expression) and "Usage of tx.origin" not in function_checked_issues:
                        add_issue(
                            "Usage of tx.origin",
                            "This can be exploited in phishing attacks.",
                            "critical",
                            contract.name,
                            function.name
                        )
                        function_checked_issues.add("Usage of tx.origin")
                    if node.type == "LowLevelCall" and not any(handler in str(node.expression) for handler in ["require", "assert", "revert"]) and "Improper Exception Handling" not in function_checked_issues:
                        add_issue(
                            "Improper Exception Handling",
                            "Ensure proper exception handling mechanisms are in place.",
                            "critical",
                            contract.name,
                            function.name
                        )
                        function_checked_issues.add("Improper Exception Handling")
                    if node.expression and "block.timestamp" in str(node.expression) and "Front-Running Vulnerability" not in function_checked_issues:
                        add_issue(
                            "Front-Running Vulnerability",
                            "Avoid using block timestamps for critical logic.",
                            "critical",
                            contract.name,
                            function.name
                        )
                        function_checked_issues.add("Front-Running Vulnerability")
                    if node.type == "LowLevelCall" and not "success" in str(node.expression) and "Unchecked Low-Level Call" not in function_checked_issues:
                        add_issue(
                            "Unchecked Low-Level Call",
                            "Ensure the success of low-level calls is checked.",
                            "critical",
                            contract.name,
                            function.name
                        )
                        function_checked_issues.add("Unchecked Low-Level Call")

                if function.name == "withdraw" and function.visibility == "public" and "Unrestricted Ether Withdrawal" not in function_checked_issues:
                    add_issue(
                        "Unrestricted Ether Withdrawal",
                        "This can allow unauthorized withdrawals.",
                        "critical",
                        contract.name,
                        function.name
                    )
                    function_checked_issues.add("Unrestricted Ether Withdrawal")
                if len(function.nodes) > 20 and "Gas Limit Issue" not in function_checked_issues:
                    add_issue(
                        "Gas Limit Issue",
                        "Optimize the function to reduce gas consumption.",
                        "critical",
                        contract.name,
                        function.name
                    )
                    function_checked_issues.add("Gas Limit Issue")
                if any(node.type == "HighLevelCall" for node in function.nodes) and "External Function Call" not in function_checked_issues:
                    add_issue(
                        "External Function Call",
                        "Ensure external calls are safe and necessary.",
                        "warning",
                        contract.name,
                        function.name
                    )
                    function_checked_issues.add("External Function Call")

            for variable in contract.state_variables:
                if variable.is_stored and variable.uninitialized and "Uninitialized Storage Pointer" not in function_checked_issues:
                    add_issue(
                        "Uninitialized Storage Pointer",
                        "Can lead to unpredictable behavior.",
                        "critical",
                        contract.name
                    )
                    function_checked_issues.add("Uninitialized Storage Pointer")
                if variable.type == "address" and variable.value and "Hardcoded Address" not in function_checked_issues:
                    add_issue(
                        "Hardcoded Address",
                        "Avoid using hardcoded addresses for better flexibility and security.",
                        "warning",
                        contract.name
                    )
                    function_checked_issues.add("Hardcoded Address")
                if variable.uninitialized and "Uninitialized Variable" not in function_checked_issues:
                    add_issue(
                        "Uninitialized Variable",
                        "Ensure all variables are properly initialized.",
                        "critical",
                        contract.name
                    )
                    function_checked_issues.add("Uninitialized Variable")

            for variable in function.variables:
                if any(state_var.name == variable.name for state_var in contract.state_variables) and "Shadowing Variable" not in function_checked_issues:
                    add_issue(
                        "Shadowing Variable",
                        "Avoid variable shadowing to prevent bugs.",
                        "critical",
                        contract.name,
                        function.name
                    )
                    function_checked_issues.add("Shadowing Variable")

            state_change = any(node.state_variables_written for node in function.nodes)
            emits_event = any(node.type == "EmitStatement" for node in function.nodes)
            if state_change and not emits_event and "Missing Event Emission" not in function_checked_issues:
                add_issue(
                    "Missing Event Emission",
                    "Emit events for critical state changes.",
                    "warning",
                    contract.name,
                    function.name
                )
                function_checked_issues.add("Missing Event Emission")

            deprecated_functions = ["suicide", "throw"]
            for node in function.nodes:
                if node.expression and any(func in str(node.expression) for func in deprecated_functions) and "Deprecated Function" not in function_checked_issues:
                    add_issue(
                        "Deprecated Function",
                        "Replace deprecated functions with their modern equivalents.",
                        "critical",
                        contract.name,
                        function.name
                    )
                    function_checked_issues.add("Deprecated Function")

            for modifier in function.modifiers:
                if modifier == "onlyOwner" and not function.is_restricted and "Missing Function Modifier" not in function_checked_issues:
                    add_issue(
                        "Missing Function Modifier",
                        "Ensure critical functions have the necessary modifiers.",
                        "critical",
                        contract.name,
                        function.name
                    )
                    function_checked_issues.add("Missing Function Modifier")

            call_count = sum(1 for node in function.nodes if node.type == "HighLevelCall")
            if call_count > 1 and "Reentrancy with Multiple Calls" not in function_checked_issues:
                add_issue(
                    "Reentrancy with Multiple Calls",
                    "Ensure proper reentrancy guards are in place.",
                    "critical",
                    contract.name,
                    function.name
                )
                function_checked_issues.add("Reentrancy with Multiple Calls")

            for function in contract.functions:
                if any("ERC20" in var.type.__str__() for var in function.variables) and not any(check in function.name for check in ["require", "assert"]) and "Missing ERC20 Return Value Check" not in function_checked_issues:
                    add_issue(
                        "Missing ERC20 Return Value Check",
                        "Check the return value of ERC20 operations.",
                        "critical",
                        contract.name,
                        function.name
                    )
                    function_checked_issues.add("Missing ERC20 Return Value Check")

            # Additional checks for the specified vulnerabilities
            if "selfdestruct" in function_code:
                add_issue(
                    "Self Destruct",
                    "Usage of selfdestruct can lead to loss of contract state.",
                    "critical",
                    contract.name,
                    function.name
                )

            if "tx.origin" in function_code:
                add_issue(
                    "Phishing with tx.origin",
                    "Usage of tx.origin can lead to phishing attacks.",
                    "critical",
                    contract.name,
                    function.name
                )

            if any(op in function_code for op in ["+", "-", "*", "/", "%"]):
                add_issue(
                    "Arithmetic Overflow and Underflow",
                    "Ensure proper checks are in place to prevent arithmetic overflow and underflow.",
                    "critical",
                    contract.name,
                    function.name
                )

            if "block.timestamp" in function_code:
                add_issue(
                    "Block Timestamp Manipulation",
                    "Usage of block.timestamp can be manipulated by miners.",
                    "critical",
                    contract.name,
                    function.name
                )

            if any(keyword in function_code for keyword in ["require", "assert", "revert"]):
                add_issue(
                    "Denial of Service",
                    "Ensure proper handling of require/assert/revert to prevent denial of service.",
                    "critical",
                    contract.name,
                    function.name
                )

            if "signature" in function_code and "replay" in function_code:
                add_issue(
                    "Signature Replay",
                    "Ensure proper handling of signatures to prevent replay attacks.",
                    "critical",
                    contract.name,
                    function.name
                )

            if "delegatecall" in function_code:
                add_issue(
                    "Delegatecall",
                    "Usage of delegatecall can lead to code execution in the context of the caller contract.",
                    "critical",
                    contract.name,
                    function.name
                )

            if "address(this).balance" in function_code:
                add_issue(
                    "Vault Inflation Attack",
                    "Ensure proper handling of address(this).balance to prevent vault inflation attacks.",
                    "critical",
                    contract.name,
                    function.name
                )

            if "permit" in function_code and "WETH" in function_code:
                add_issue(
                    "WETH Permit",
                    "Ensure proper handling of WETH permits to prevent unauthorized transactions.",
                    "critical",
                    contract.name,
                    function.name
                )

            if "contractSize" in function_code:
                add_issue(
                    "Bypass Contract Size Check",
                    "Ensure proper handling of contract size checks to prevent bypassing.",
                    "critical",
                    contract.name,
                    function.name
                )

            if "create2" in function_code:
                add_issue(
                    "Deploy Different Contracts at Same Address",
                    "Ensure proper handling of create2 to prevent deploying different contracts at the same address.",
                    "critical",
                    contract.name,
                    function.name
                )

            if any(keyword in function_code for keyword in ["honeypot", "trap"]):
                add_issue(
                    "Honeypot",
                    "Ensure proper detection and handling of honeypots.",
                    "critical",
                    contract.name,
                    function.name
                )

        return issues
    except Exception as e:
        raise Exception(f"Error detecting issues: {str(e)}")

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
        "Missing ERC20 Return Value Check": "Check the return value of ERC20 operations to ensure they succeeded. Failure to do so can lead to loss of funds or incorrect behavior.",
        "Self Destruct": "Usage of selfdestruct can lead to loss of contract state. Ensure it is used carefully.",
        "Phishing with tx.origin": "Usage of tx.origin can lead to phishing attacks. Avoid using tx.origin for authentication.",
        "Arithmetic Overflow and Underflow": "Ensure proper checks are in place to prevent arithmetic overflow and underflow. Use SafeMath library or equivalent.",
        "Block Timestamp Manipulation": "Usage of block.timestamp can be manipulated by miners. Avoid using block.timestamp for critical logic.",
        "Denial of Service": "Ensure proper handling of require/assert/revert to prevent denial of service. Avoid unbounded loops and excessive gas consumption.",
        "Signature Replay": "Ensure proper handling of signatures to prevent replay attacks. Use nonce or equivalent mechanism.",
        "Vault Inflation Attack": "Ensure proper handling of address(this).balance to prevent vault inflation attacks.",
        "WETH Permit": "Ensure proper handling of WETH permits to prevent unauthorized transactions.",
        "Bypass Contract Size Check": "Ensure proper handling of contract size checks to prevent bypassing. Use code size limit checks if necessary.",
        "Deploy Different Contracts at Same Address": "Ensure proper handling of create2 to prevent deploying different contracts at the same address. Use unique salt values.",
        "Honeypot": "Ensure proper detection and handling of honeypots. Verify contract behavior before interaction."
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
    return headers, rows

# Function to save issues to an HTML file
def save_issues_to_html(headers, rows, output_path):
    html_content = f"""
    <html>
    <head>
    <title>Smart Contract Vulnerabilities</title>
    <style>
    table {{
    width: 100%;
    border-collapse: collapse;
    }}
    th, td {{
    border: 1px solid black;
    padding: 8px;
    text-align: left;
    }}
    th {{
    background-color: #f2f2f2;
    }}
    </style>
    </head>
    <body>
    <h2>Smart Contract Vulnerabilities</h2>
    <table>
    <thead>
    <tr>
    {''.join(f'<th>{header}</th>' for header in headers)}
    </tr>
    </thead>
    <tbody>
    {''.join('<tr>' + ''.join(f'<td>{html.escape(str(cell))}</td>' for cell in row) + '</tr>' for row in rows)}
    </tbody>
    </table>
    </body>
    </html>
    """
    with open(output_path, 'w') as file:
        file.write(html_content)

# Main function to run the script
def main():
    print(Fore.CYAN + "Enter the path to the Solidity contract file you want to test:")
    contract_path = input().strip()

    print(Fore.CYAN + "Enter the path to the remappings file:")
    remappings_file = input().strip()

    print(Fore.CYAN + "Enter the EVM version you want to use (e.g., istanbul, berlin, london):")
    evm_version = input().strip()

    print(Fore.CYAN + "Enter any additional contract files (comma-separated, if any):")
    additional_contracts = input().strip().split(',')

    # Ensure the contract file exists
    if not os.path.exists(contract_path):
        print(Fore.RED + f"Error: The contract file {contract_path} does not exist.")
        return

    # Ensure the remappings file exists
    if not os.path.exists(remappings_file):
        print(Fore.RED + f"Error: The remappings file {remappings_file} does not exist.")
        return

    try:
        # Extract and install the required Solidity version
        solc_version = extract_solidity_version(contract_path)
        try:
            install_solc(solc_version)
        except urllib.error.URLError as e:
            print(Fore.RED + f"Network error: {e}. Ensure you have an active internet connection and try again.")
            return
        
        # Set the SOLC_VERSION environment variable using solc-select
        os.system(f'solc-select install {solc_version}')
        os.system(f'solc-select use {solc_version}')
        
    except ValueError as e:
        print(Fore.RED + f"Error: {e}")
        return

    # Compile the contract
    try:
        compiled_contract = compile_contract(contract_path, solc_version, remappings_file, evm_version, additional_contracts)
        print(Fore.GREEN + "Contract compiled successfully")
    except Exception as e:
        print(Fore.RED + f"Error compiling contract: {e}")
        return

    # Detect issues
    try:
        issues = detect_issues(contract_path, solc_version, evm_version)
    except Exception as e:
        print(Fore.RED + f"Error detecting issues: {str(e)}")
        return

    if issues:
        print(Fore.YELLOW + "Issues found:\n")
        headers, rows = display_issues(issues)
        output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'smart_contract_vulnerabilities.html')
        save_issues_to_html(headers, rows, output_path)
        print(Fore.GREEN + f"Issues saved to {output_path}")
    else:
        print(Fore.GREEN + "No issues found")

if __name__ == "__main__":
    main()
