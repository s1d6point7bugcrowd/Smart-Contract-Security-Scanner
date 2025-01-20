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

# Function to detect issues using Slither
def detect_issues(contract_path, solc_version, evm_version):
    try:
        slither = Slither(contract_path, solc_args=["--evm-version", evm_version])

        issues = defaultdict(list)

        for detector in slither.detectors:
            for result in detector.execute():
                contract = result.contract_name
                function = result.function_name if result.function_name else ""
                issue_type = detector.NAME
                description = result.description
                severity = result.severity.name.lower()  # 'high', 'medium', 'low'

                explanation = get_explanation(issue_type)

                issue_message = f"{issue_type}: {description}\nExplanation: {explanation}"
                issues[contract].append((issue_message, function, severity))

        return issues

    except Exception as e:
        raise Exception(f"Error detecting issues: {str(e)}")

# Function to get explanations for each issue type
def get_explanation(issue_type):
    explanations = {
        "Reentrancy": "Reentrancy vulnerabilities allow attackers to repeatedly call a function before the previous invocation completes, potentially leading to multiple withdrawals or unauthorized state changes.",
        "UnusedReturn": "Ignoring the return value of a function can lead to unexpected behaviors, especially when dealing with external calls.",
        "Timestamp": "Using block timestamps can be manipulated by miners, leading to potential exploitation in time-dependent functions.",
        "Delegatecall": "Delegatecall allows executing code in the context of the caller, which can lead to code injection and unauthorized state changes if not handled carefully.",
        # Add more explanations as needed based on Slither's detectors
    }
    return explanations.get(issue_type, "No explanation available.")

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
                explanation = "No explanation available."
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

    # Detect issues
    try:
        issues = detect_issues(contract_path, solc_version, evm_version)
        logging.info("Issue detection completed.")
    except Exception as e:
        print(Fore.RED + f"Error detecting issues: {str(e)}")
        logging.error(f"Issue detection error: {e}")
        return

    if issues:
        logging.info(f"Issues found in {len(issues)} contracts.")
        print(Fore.YELLOW + "Issues found:\n")
        headers, rows = display_issues(issues)
        save_issues_to_html(headers, rows, output_path)
        logging.info(f"Issues saved to {output_path}")
        print(Fore.GREEN + f"Issues saved to {output_path}")
    else:
        logging.info("No issues found.")
        print(Fore.GREEN + "No issues found")

if __name__ == "__main__":
    main()
