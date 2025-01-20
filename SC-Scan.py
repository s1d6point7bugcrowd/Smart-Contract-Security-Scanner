import os
import re
import urllib.error
from collections import defaultdict
from solcx import compile_standard, install_solc, set_solc_version, get_installed_solc_versions
from slither.slither import Slither
from colorama import Fore, Style, init
from termcolor import colored
from tabulate import tabulate
import html
import argparse
import logging
import subprocess
import json

# Initialize colorama
init(autoreset=True)

# Configure logging
logging.basicConfig(filename='vulnerability_analyzer.log',
                    filemode='a',
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    level=logging.INFO)

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
        match = re.search(r'pragma solidity\s+([^;]+);', content)
        if match:
            return match.group(1).strip()
        else:
            raise ValueError("Solidity version pragma not found in the contract.")

# Function to compile the Solidity contract
def compile_contract(contract_path, solc_version, evm_version):
    set_solc_version(solc_version)
    with open(contract_path, 'r') as file:
        contract_source = file.read()

    compiled_sol = compile_standard({
        "language": "Solidity",
        "sources": {
            os.path.basename(contract_path): {
                "content": contract_source
            }
        },
        "settings": {
            "outputSelection": {
                "*": {
                    "*": ["abi", "metadata", "evm.bytecode", "evm.sourceMap"]
                }
            },
            "evmVersion": evm_version
        }
    }, allow_paths="./")  # Adjust allow_paths as necessary

    return compiled_sol

# Function to detect custom issues
def detect_custom_issues(slither, issues):
    for contract in slither.contracts:
        for function in contract.functions:
            # Define critical functions that require access control
            critical_functions = ["withdraw", "transferOwnership", "selfDestructContract", "changeOwner"]
            if function.name in critical_functions:
                has_modifier = any(modifier.name == "onlyOwner" for modifier in function.modifiers)
                if not has_modifier:
                    issue_type = "Missing Access Control"
                    description = f"The function '{function.name}' lacks access control modifiers, allowing unrestricted access."
                    severity = "high"
                    explanation = (
                        f"The function '{function.name}' performs critical operations without restricting access. "
                        "This can be exploited by malicious actors to manipulate the contract's state or drain funds."
                    )
                    issue_message = f"{issue_type}: {description}\nExplanation: {explanation}"
                    issues[contract.name].append((issue_message, function.name, severity))
    return issues

# Function to detect issues using Slither
def detect_issues(contract_path, solc_version, evm_version):
    try:
        slither = Slither(contract_path, solc_args=["--evm-version", evm_version])

        issues = defaultdict(list)

        # Utilize Slither's built-in detectors
        for detector in slither.detectors:
            for result in detector.execute():
                contract = result.contract_name
                function = result.function_name if result.function_name else ""
                issue_type = detector.NAME
                description = result.description
                severity = result.severity.name.lower()

                explanation = get_explanation(issue_type)

                issue_message = f"{issue_type}: {description}\nExplanation: {explanation}"
                issues[contract].append((issue_message, function, severity))

        # Apply custom vulnerability checks
        issues = detect_custom_issues(slither, issues)

        return issues

    except Exception as e:
        raise Exception(f"Error detecting issues: {str(e)}")

# Function to get explanations for each issue type
def get_explanation(issue_type):
    explanations = {
        "Reentrancy": (
            "Reentrancy vulnerabilities allow attackers to repeatedly call a function before the previous invocation completes. "
            "This can lead to multiple withdrawals or unauthorized state changes, potentially draining contract funds."
        ),
        "UnusedReturn": (
            "Ignoring the return value of a function can lead to unexpected behaviors. For instance, failing to check "
            "the return value of an external call might allow the contract to proceed under the false assumption that the call was successful."
        ),
        "Timestamp": (
            "Using block timestamps (`block.timestamp`) for critical logic can be manipulated by miners, allowing them to influence the outcome of time-dependent functions."
        ),
        "Delegatecall": (
            "Using `delegatecall` executes code in the context of the caller's storage. If not handled carefully, it can lead to code injection and unauthorized state changes, compromising contract integrity."
        ),
        "Arithmetic Overflow": (
            "Arithmetic overflows occur when operations exceed the maximum value of a data type, causing unexpected behavior. For example, adding 1 to the maximum `uint256` value wraps around to zero."
        ),
        "Arithmetic Underflow": (
            "Arithmetic underflows happen when operations result in values below the minimum limit of a data type, leading to incorrect calculations. For instance, subtracting 1 from zero in an unsigned integer wraps around to the maximum value."
        ),
        "Hardcoded Address": (
            "Using hardcoded addresses reduces flexibility and can introduce security risks. If the hardcoded address is compromised or needs to change, updating the contract becomes cumbersome and error-prone."
        ),
        "Missing Event Emission": (
            "Events are crucial for logging significant state changes, facilitating off-chain monitoring and debugging. Missing event emissions can hinder transparency and make it difficult to track contract activities."
        ),
        "Unchecked Low-Level Call": (
            "Low-level calls like `call`, `delegatecall`, and `send` are error-prone. Failing to check their return values can result in undetected failures, leading to inconsistent contract states or loss of funds."
        ),
        "Self Destruct": (
            "Using `selfdestruct` can permanently remove a contract from the blockchain, leading to loss of contract state and functionality. It should be used cautiously, ensuring only authorized entities can trigger it."
        ),
        "Missing Access Control": (
            "Functions performing critical operations without proper access control can be exploited by unauthorized users to manipulate the contract's state or drain funds."
        ),
        "Arithmetic Overflow and Underflow": (
            "Arithmetic operations without proper checks can lead to overflows or underflows, resulting in unexpected behavior and potential vulnerabilities."
        ),
        # Add more detailed explanations for other issue types as needed
    }
    return explanations.get(issue_type, "No detailed explanation available for this issue.")

# Function to display issues in a table
def display_issues(issues):
    headers = ["Contract", "Function", "Issue Type", "Description", "Severity", "Explanation"]
    rows = []
    for contract, contract_issues in issues.items():
        for issue, function, severity in contract_issues:
            issue_info = issue.split(": ", 1)
            if len(issue_info) < 2:
                continue  # Skip malformed entries
            issue_type = issue_info[0].strip()
            description_part = issue_info[1].split("\nExplanation: ")
            if len(description_part) < 2:
                description = description_part[0].strip()
                explanation = "No detailed explanation available."
            else:
                description = description_part[0].strip()
                explanation = description_part[1].strip()
            color = "red" if severity == "high" else "yellow" if severity == "medium" else "blue"
            rows.append([
                contract,
                function,
                colored(issue_type, color),
                colored(description, color),
                severity.capitalize(),
                explanation
            ])

    print(tabulate(rows, headers, tablefmt="grid"))
    return headers, rows

# Function to save issues to an HTML file
def save_issues_to_html(headers, rows, output_path):
    # Enhanced styling with Bootstrap and interactive table using DataTables
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Smart Contract Vulnerabilities</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
        <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.13.4/css/dataTables.bootstrap5.min.css"/>
        <script src="https://code.jquery.com/jquery-3.5.1.js"></script>
        <script type="text/javascript" src="https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js"></script>
        <script type="text/javascript" src="https://cdn.datatables.net/1.13.4/js/dataTables.bootstrap5.min.js"></script>
    </head>
    <body>
        <div class="container mt-5">
            <h2>Smart Contract Vulnerabilities</h2>
            <table id="issuesTable" class="table table-striped">
                <thead>
                    <tr>
                        {''.join(f'<th>{html.escape(header)}</th>' for header in headers)}
                    </tr>
                </thead>
                <tbody>
                    {''.join('<tr>' + ''.join(f'<td>{html.escape(str(cell))}</td>' for cell in row) + '</tr>' for row in rows)}
                </tbody>
            </table>
        </div>
        <script>
            $(document).ready(function() {{
                $('#issuesTable').DataTable();
            }});
        </script>
    </body>
    </html>
    """
    with open(output_path, 'w') as file:
        file.write(html_content)

# Function to generate Echidna configuration
def generate_echidna_config(contract_path, properties, config_path='echidna_config.yaml'):
    with open(config_path, 'w') as file:
        file.write(f"contract: {os.path.basename(contract_path)}\n")
        file.write("test-mode: assertion\n")
        file.write("verbosity: 3\n")
        file.write("concurrency: 1\n")
        file.write("properties:\n")
        for prop in properties:
            file.write(f"  - {prop}\n")
    return config_path

# Function to run Echidna fuzzing
def run_echidna(contract_path, config_path):
    try:
        # Using Docker to run Echidna
        cmd = [
            'docker', 'run', '--rm',
            '-v', f"{os.path.abspath(contract_path)}:/contracts/{os.path.basename(contract_path)}",
            '-v', f"{os.path.abspath(config_path)}:/config/echidna_config.yaml",
            'ghcr.io/crytic/echidna:latest',
            '/bin/sh', '-c',
            f"echidna-test /contracts/{os.path.basename(contract_path)} --config-file /config/{os.path.basename(config_path)}"
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(Fore.RED + "Echidna fuzzing failed.")
        logging.error(f"Echidna error: {e.stderr}")
        return e.stdout + e.stderr

# Function to parse Echidna results
def parse_echidna_results(echidna_output):
    issues = []
    lines = echidna_output.split('\n')
    for line in lines:
        if 'FAILURE:' in line or 'ERROR:' in line:
            issues.append(line.strip())
    return issues

# Function to run Mythril symbolic execution
def run_mythril(contract_path):
    try:
        cmd = [
            'myth', 'analyze',
            contract_path,
            '--solv', 'auto',
            '--json',
            '--verbosity', '0'
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(Fore.RED + "Mythril analysis failed.")
        logging.error(f"Mythril error: {e.stderr}")
        return e.stdout + e.stderr

# Function to parse Mythril results
def parse_mythril_results(mythril_output):
    issues = []
    try:
        results = json.loads(mythril_output)
        for issue in results.get('issues', []):
            contract = issue.get('contract')
            function = issue.get('function', '')
            issue_type = issue.get('title')
            description = issue.get('description')
            severity = issue.get('severity').lower()  # 'high', 'medium', 'low'

            explanation = get_explanation(issue_type)

            issue_message = f"{issue_type}: {description}\nExplanation: {explanation}"
            issues.append((contract, function, issue_message, severity))
    except json.JSONDecodeError:
        print(Fore.RED + "Failed to parse Mythril output.")
        logging.error("Mythril output is not valid JSON.")
    return issues

# Function to parse Echidna results and add to issues
def add_echidna_issues(issues, echidna_issues):
    for issue in echidna_issues:
        # Example parsing; adjust based on actual Echidna output format
        if 'FAILURE:' in issue:
            parts = issue.split('FAILURE:')
            if len(parts) > 1:
                description = parts[1].strip()
                issue_type = "Echidna Failure"
                severity = "high"
                explanation = "Echidna detected a property violation during fuzzing. Review the contract's properties and ensure they are correctly implemented."
                issue_message = f"{issue_type}: {description}\nExplanation: {explanation}"
                # Assuming the failure is related to the contract
                contract = os.path.splitext(os.path.basename(args.contract))[0]
                issues[contract].append((issue_message, "N/A", severity))
    return issues

# Function to parse Mythril results and add to issues
def add_mythril_issues(issues, mythril_issues):
    for issue in mythril_issues:
        contract, function, issue_message, severity = issue
        issues[contract].append((issue_message, function, severity))
    return issues

# Function to parse Echidna results and add to issues
def add_echidna_issues(issues, echidna_issues):
    for issue in echidna_issues:
        # Example parsing; adjust based on actual Echidna output format
        if 'FAILURE:' in issue:
            parts = issue.split('FAILURE:')
            if len(parts) > 1:
                description = parts[1].strip()
                issue_type = "Echidna Property Failure"
                severity = "high"
                explanation = (
                    "Echidna detected a property violation during fuzzing. "
                    "Review the contract's properties and ensure they are correctly implemented."
                )
                issue_message = f"{issue_type}: {description}\nExplanation: {explanation}"
                # Assuming the failure is related to the contract
                contract = os.path.splitext(os.path.basename(args.contract))[0]
                issues[contract].append((issue_message, "N/A", severity))
    return issues

# Function to parse Mythril results and add to issues
def add_mythril_issues(issues, mythril_issues):
    for issue in mythril_issues:
        contract, function, issue_message, severity = issue
        issues[contract].append((issue_message, function, severity))
    return issues

# Function to parse and add Mythril issues
def process_mythril(issues, mythril_output):
    mythril_issues = parse_mythril_results(mythril_output)
    if mythril_issues:
        print(Fore.YELLOW + "Symbolic Execution Issues Found:\n")
        for issue in mythril_issues:
            contract, function, issue_message, severity = issue
            print(Fore.YELLOW + issue_message)
            logging.warning(f"Mythril Issue in {contract}.{function}: {issue_message}")
        issues = add_mythril_issues(issues, mythril_issues)
    else:
        print(Fore.GREEN + "No issues found during symbolic execution.")
        logging.info("No issues found during symbolic execution.")
    return issues

# Function to parse and add Echidna issues
def process_echidna(issues, echidna_output):
    echidna_issues = parse_echidna_results(echidna_output)
    if echidna_issues:
        print(Fore.YELLOW + "Dynamic Analysis Issues Found:\n")
        for issue in echidna_issues:
            print(Fore.YELLOW + issue)
            logging.warning(f"Echidna Issue: {issue}")
        issues = add_echidna_issues(issues, echidna_issues)
    else:
        print(Fore.GREEN + "No issues found during dynamic analysis.")
        logging.info("No issues found during dynamic analysis.")
    return issues

# Function to display issues in a table
def display_issues(issues):
    headers = ["Contract", "Function", "Issue Type", "Description", "Severity", "Explanation"]
    rows = []
    for contract, contract_issues in issues.items():
        for issue, function, severity in contract_issues:
            issue_info = issue.split(": ", 1)
            if len(issue_info) < 2:
                continue  # Skip malformed entries
            issue_type = issue_info[0].strip()
            description_part = issue_info[1].split("\nExplanation: ")
            if len(description_part) < 2:
                description = description_part[0].strip()
                explanation = "No detailed explanation available."
            else:
                description = description_part[0].strip()
                explanation = description_part[1].strip()
            color = "red" if severity == "high" else "yellow" if severity == "medium" else "blue"
            rows.append([
                contract,
                function,
                colored(issue_type, color),
                colored(description, color),
                severity.capitalize(),
                explanation
            ])

    print(tabulate(rows, headers, tablefmt="grid"))
    return headers, rows

# Function to save issues to an HTML file
def save_issues_to_html(headers, rows, output_path):
    # Enhanced styling with Bootstrap and interactive table using DataTables
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Smart Contract Vulnerabilities</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
        <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.13.4/css/dataTables.bootstrap5.min.css"/>
        <script src="https://code.jquery.com/jquery-3.5.1.js"></script>
        <script type="text/javascript" src="https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js"></script>
        <script type="text/javascript" src="https://cdn.datatables.net/1.13.4/js/dataTables.bootstrap5.min.js"></script>
    </head>
    <body>
        <div class="container mt-5">
            <h2>Smart Contract Vulnerabilities</h2>
            <table id="issuesTable" class="table table-striped">
                <thead>
                    <tr>
                        {''.join(f'<th>{html.escape(header)}</th>' for header in headers)}
                    </tr>
                </thead>
                <tbody>
                    {''.join('<tr>' + ''.join(f'<td>{html.escape(str(cell))}</td>' for cell in row) + '</tr>' for row in rows)}
                </tbody>
            </table>
        </div>
        <script>
            $(document).ready(function() {{
                $('#issuesTable').DataTable();
            }});
        </script>
    </body>
    </html>
    """
    with open(output_path, 'w') as file:
        file.write(html_content)

# Function to parse command-line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="Solidity Smart Contract Vulnerability Analyzer")
    parser.add_argument("-c", "--contract", required=True, help="Path to the Solidity contract file")
    parser.add_argument("-r", "--remappings", default="", help="Path to the remappings file")
    parser.add_argument("-e", "--evm", required=True, choices=SUPPORTED_EVM_VERSIONS, help="EVM version to use")
    parser.add_argument("-a", "--additional", default="", help="Comma-separated additional contract files")
    parser.add_argument("-o", "--output", default="smart_contract_vulnerabilities.html", help="Output HTML report path")
    return parser.parse_args()

# Function to generate Echidna configuration
def generate_echidna_config(contract_path, properties, config_path='echidna_config.yaml'):
    with open(config_path, 'w') as file:
        file.write(f"contract: {os.path.basename(contract_path)}\n")
        file.write("test-mode: assertion\n")
        file.write("verbosity: 3\n")
        file.write("concurrency: 1\n")
        file.write("properties:\n")
        for prop in properties:
            file.write(f"  - {prop}\n")
    return config_path

# Function to run Echidna fuzzing
def run_echidna(contract_path, config_path):
    try:
        # Using Docker to run Echidna
        cmd = [
            'docker', 'run', '--rm',
            '-v', f"{os.path.abspath(contract_path)}:/contracts/{os.path.basename(contract_path)}",
            '-v', f"{os.path.abspath(config_path)}:/config/echidna_config.yaml",
            'ghcr.io/crytic/echidna:latest',
            '/bin/sh', '-c',
            f"echidna-test /contracts/{os.path.basename(contract_path)} --config-file /config/{os.path.basename(config_path)}"
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(Fore.RED + "Echidna fuzzing failed.")
        logging.error(f"Echidna error: {e.stderr}")
        return e.stdout + e.stderr

# Function to parse Echidna results
def parse_echidna_results(echidna_output):
    issues = []
    lines = echidna_output.split('\n')
    for line in lines:
        if 'FAILURE:' in line or 'ERROR:' in line:
            issues.append(line.strip())
    return issues

# Function to run Mythril symbolic execution
def run_mythril(contract_path):
    try:
        cmd = [
            'myth', 'analyze',
            contract_path,
            '--solv', 'auto',
            '--json',
            '--verbosity', '0'
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(Fore.RED + "Mythril analysis failed.")
        logging.error(f"Mythril error: {e.stderr}")
        return e.stdout + e.stderr

# Function to parse Mythril results
def parse_mythril_results(mythril_output):
    issues = []
    try:
        results = json.loads(mythril_output)
        for issue in results.get('issues', []):
            contract = issue.get('contract')
            function = issue.get('function', '')
            issue_type = issue.get('title')
            description = issue.get('description')
            severity = issue.get('severity').lower()  # 'high', 'medium', 'low'

            explanation = get_explanation(issue_type)

            issue_message = f"{issue_type}: {description}\nExplanation: {explanation}"
            issues.append((contract, function, issue_message, severity))
    except json.JSONDecodeError:
        print(Fore.RED + "Failed to parse Mythril output.")
        logging.error("Mythril output is not valid JSON.")
    return issues

# Function to add Echidna issues to the issues dictionary
def add_echidna_issues(issues, echidna_issues):
    for issue in echidna_issues:
        if 'FAILURE:' in issue:
            parts = issue.split('FAILURE:')
            if len(parts) > 1:
                description = parts[1].strip()
                issue_type = "Echidna Property Failure"
                severity = "high"
                explanation = (
                    "Echidna detected a property violation during fuzzing. "
                    "Review the contract's properties and ensure they are correctly implemented."
                )
                issue_message = f"{issue_type}: {description}\nExplanation: {explanation}"
                # Assuming the failure is related to the contract
                contract = os.path.splitext(os.path.basename(args.contract))[0]
                issues[contract].append((issue_message, "N/A", severity))
    return issues

# Function to add Mythril issues to the issues dictionary
def add_mythril_issues(issues, mythril_issues):
    for issue in mythril_issues:
        contract, function, issue_message, severity = issue
        issues[contract].append((issue_message, function, severity))
    return issues

# Function to add Echidna issues to the issues dictionary
def add_echidna_issues(issues, echidna_issues):
    for issue in echidna_issues:
        if 'FAILURE:' in issue:
            parts = issue.split('FAILURE:')
            if len(parts) > 1:
                description = parts[1].strip()
                issue_type = "Echidna Property Failure"
                severity = "high"
                explanation = (
                    "Echidna detected a property violation during fuzzing. "
                    "Review the contract's properties and ensure they are correctly implemented."
                )
                issue_message = f"{issue_type}: {description}\nExplanation: {explanation}"
                # Assuming the failure is related to the contract
                contract = os.path.splitext(os.path.basename(args.contract))[0]
                issues[contract].append((issue_message, "N/A", severity))
    return issues

# Main function to run the script
def main():
    args = parse_arguments()

    contract_path = args.contract
    remappings_file = args.remappings
    evm_version = args.evm
    additional_contracts = [contract.strip() for contract in args.additional.split(',') if contract.strip()]
    output_path = args.output

    # Validate paths
    if not os.path.exists(contract_path):
        print(Fore.RED + f"Error: The contract file {contract_path} does not exist.")
        logging.error(f"Contract file not found: {contract_path}")
        return

    if remappings_file and not os.path.exists(remappings_file):
        print(Fore.RED + f"Error: The remappings file {remappings_file} does not exist.")
        logging.error(f"Remappings file not found: {remappings_file}")
        return

    for additional_contract in additional_contracts:
        if not os.path.exists(additional_contract):
            print(Fore.RED + f"Error: The additional contract file {additional_contract} does not exist.")
            logging.error(f"Additional contract file not found: {additional_contract}")
            return

    try:
        # Extract and install the required Solidity version
        solc_version_spec = extract_solidity_version(contract_path)
        logging.info(f"Extracted Solidity version: {solc_version_spec}")
        # Install solc versions that satisfy the version spec
        installed_versions = get_installed_solc_versions()
        # solcx handles version specs like ^0.8.0 by installing compatible versions
        # Here, we assume the user provides an exact version. For version ranges, additional parsing is needed.
        solc_version = solc_version_spec  # This may need refinement based on version spec
        if solc_version not in installed_versions:
            install_solc(solc_version)
            logging.info(f"Installed Solidity version: {solc_version}")
        else:
            logging.info(f"Solidity version {solc_version} already installed.")
        
    except ValueError as e:
        print(Fore.RED + f"Error: {e}")
        logging.error(f"Version extraction error: {e}")
        return
    except urllib.error.URLError as e:
        print(Fore.RED + f"Network error: {e}. Ensure you have an active internet connection and try again.")
        logging.error(f"Network error during solc installation: {e}")
        return
    except Exception as e:
        print(Fore.RED + f"Unexpected error: {e}")
        logging.error(f"Unexpected error during solc installation: {e}")
        return

    # Compile the contract
    try:
        compiled_contract = compile_contract(contract_path, solc_version, evm_version)
        logging.info("Contract compiled successfully.")
        print(Fore.GREEN + "Contract compiled successfully")
    except Exception as e:
        print(Fore.RED + f"Error compiling contract: {e}")
        logging.error(f"Compilation error: {e}")
        return

    # Detect issues using Slither
    try:
        issues = detect_issues(contract_path, solc_version, evm_version)
        logging.info("Static analysis (Slither) completed.")
    except Exception as e:
        print(Fore.RED + f"Error detecting issues: {str(e)}")
        logging.error(f"Static analysis error: {e}")
        return

    # Proceed with dynamic analysis using Echidna
    try:
        # Define properties for Echidna based on contract's functions or predefined rules
        # For demonstration, assume properties are predefined
        properties = ["ownerShouldNeverBeZero", "onlyOwnerCanWithdraw"]
        config_path = generate_echidna_config(contract_path, properties)

        print(Fore.CYAN + "Running Echidna fuzzing for dynamic analysis...")
        echidna_output = run_echidna(contract_path, config_path)
        logging.info("Echidna fuzzing completed.")
        print(Fore.GREEN + "Echidna fuzzing completed.")

        issues = process_echidna(issues, echidna_output)

    except Exception as e:
        print(Fore.RED + f"Error during dynamic analysis: {str(e)}")
        logging.error(f"Dynamic analysis error: {e}")
        return

    # Proceed with symbolic execution using Mythril
    try:
        print(Fore.CYAN + "Running Mythril symbolic execution for vulnerability detection...")
        mythril_output = run_mythril(contract_path)
        issues = process_mythril(issues, mythril_output)
    except Exception as e:
        print(Fore.RED + f"Error during symbolic execution: {str(e)}")
        logging.error(f"Symbolic execution error: {e}")
        return

    # Display issues in console
    if issues:
        print(Fore.YELLOW + "Issues found:\n")
        headers, rows = display_issues(issues)
        save_issues_to_html(headers, rows, output_path)
        print(Fore.GREEN + f"Issues saved to {output_path}")
        logging.info(f"Issues saved to {output_path}")
    else:
        print(Fore.GREEN + "No issues found")
        logging.info("No issues found.")

if __name__ == "__main__":
    main()
