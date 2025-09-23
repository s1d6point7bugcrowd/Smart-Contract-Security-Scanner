import os
import re
import urllib.error
import argparse
import logging
import subprocess
import json
import html
from collections import defaultdict
from solcx import compile_standard, install_solc_version_pragma, set_solc_version_pragma
from slither.slither import Slither
from colorama import Fore, init
from termcolor import colored
from tabulate import tabulate

# Initialize colorama for colored console output
init(autoreset=True)

# Configure logging to a file
logging.basicConfig(filename='vulnerability_analyzer.log',
                    filemode='a',
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    level=logging.INFO)

# A list of supported EVM versions for command-line argument validation
SUPPORTED_EVM_VERSIONS = [
    "homestead", "tangerineWhistle", "spuriousDragon", "byzantium",
    "constantinople", "petersburg", "istanbul", "berlin", "london",
    "paris", "shanghai", "cancun", "prague"
]

## --- Helper Functions ---

def extract_solidity_version(contract_path):
    """Extracts the solidity version pragma from a contract file."""
    with open(contract_path, 'r') as file:
        content = file.read()
        match = re.search(r'pragma solidity\s+([^;]+);', content)
        if match:
            return match.group(1).strip()
        raise ValueError("Solidity version pragma not found in the contract.")

def get_explanation(issue_type):
    """Provides detailed explanations for common vulnerability types."""
    explanations = {
        "Reentrancy": "Reentrancy allows attackers to repeatedly call a function before the previous invocation completes, which can lead to unauthorized state changes or draining funds.",
        "UnusedReturn": "Ignoring a function's return value can lead to unexpected behavior, as the contract may proceed assuming a call was successful when it failed.",
        "Timestamp": "Using `block.timestamp` for critical logic can be manipulated by miners, allowing them to influence the outcome of time-dependent functions.",
        "Delegatecall": "Careless use of `delegatecall` can lead to code injection and unauthorized state changes, as it executes external code in the caller's context.",
        "Arithmetic Overflow": "When an arithmetic operation exceeds the maximum value for a data type (e.g., uint256), it wraps around to zero, causing unexpected calculations.",
        "Arithmetic Underflow": "When an operation results in a value below the minimum for a data type, it wraps around to the maximum value, leading to incorrect logic.",
        "Missing Access Control": "Functions performing critical operations without proper access control can be exploited by unauthorized users to manipulate the contract's state or drain funds.",
        # Add more explanations as needed
    }
    return explanations.get(issue_type, "No detailed explanation available for this issue.")


## --- Static Analysis (Slither) ---

def detect_custom_issues(slither, issues):
    """Detects custom, user-defined issues like missing access control."""
    critical_functions = ["withdraw", "transferOwnership", "selfDestructContract", "changeOwner"]
    for contract in slither.contracts:
        for function in contract.functions:
            if function.name in critical_functions:
                has_only_owner = any(modifier.name == "onlyOwner" for modifier in function.modifiers)
                if not has_only_owner:
                    issue = {
                        "type": "Missing Access Control",
                        "description": f"The function '{function.name}' lacks access control, allowing unrestricted access.",
                        "explanation": get_explanation("Missing Access Control"),
                        "function": function.name,
                        "severity": "high"
                    }
                    issues[contract.name].append(issue)
    return issues

def run_slither_analysis(contract_path, evm_version):
    """Runs Slither to perform static analysis and aggregates findings."""
    try:
        slither = Slither(contract_path, solc_args=[f"--evm-version {evm_version}"])
        issues = defaultdict(list)

        # Process Slither's built-in detectors
        for detector_class in slither.detectors_classes:
            detector = detector_class(slither)
            results = detector.detect()
            for result in results:
                issue = {
                    "type": result['check'],
                    "description": result['description'],
                    "explanation": get_explanation(result['check']),
                    "function": result['elements'][0].name if result['elements'] else "N/A",
                    "severity": result['impact'].lower()
                }
                issues[result['elements'][0].contract.name].append(issue)

        # Add custom checks
        issues = detect_custom_issues(slither, issues)
        return issues
    except Exception as e:
        raise Exception(f"Error running Slither analysis: {e}")


## --- Dynamic Analysis (Echidna) ---

def generate_echidna_config(contract_path, config_path='echidna_config.yaml'):
    """Generates an advanced Echidna configuration file for fuzzing."""
    with open(config_path, 'w') as f:
        f.write(f"contract: {os.path.basename(contract_path)}\n")
        f.write("testMode: property\n")
        f.write("testLimit: 10000\n") # Number of test cases
        f.write("workerLimit: 4\n")  # Concurrency
        f.write("corpusDir: 'echidna_corpus'\n")
    return config_path

def run_echidna(contract_path, config_path):
    """Runs Echidna fuzzing tool within a Docker container."""
    try:
        cmd = [
            'docker', 'run', '--rm',
            '-v', f"{os.path.abspath(os.path.dirname(contract_path))}:/src",
            'trailofbits/echidna',
            'echidna', f"/src/{os.path.basename(contract_path)}",
            '--config', f"/src/{os.path.basename(config_path)}"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Echidna error: {e.stderr}")
        return e.stdout + e.stderr # Return output even on failure

def process_echidna_results(issues, echidna_output, contract_name):
    """Parses Echidna's output and adds any found issues."""
    echidna_failures = [line for line in echidna_output.split('\n') if 'failed!' in line]
    if not echidna_failures:
        print(Fore.GREEN + "No issues found during dynamic analysis (Echidna).")
        return issues
    
    print(Fore.YELLOW + "Dynamic Analysis Issues Found (Echidna):\n")
    for failure in echidna_failures:
        print(Fore.YELLOW + failure)
        logging.warning(f"Echidna Issue: {failure}")
        issue = {
            "type": "Echidna Property Failure",
            "description": failure.strip(),
            "explanation": "Echidna detected a property violation during fuzzing.",
            "function": "N/A",
            "severity": "high"
        }
        issues[contract_name].append(issue)
    return issues


## --- Symbolic Execution (Mythril) ---

def run_mythril(contract_path):
    """Runs Mythril symbolic execution tool."""
    try:
        cmd = ['myth', 'analyze', contract_path, '--solv', 'auto', '-o', 'json']
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Mythril error: {e.stderr}")
        return e.stdout + e.stderr

def process_mythril_results(issues, mythril_output):
    """Parses Mythril's JSON output and adds any found issues."""
    try:
        results = json.loads(mythril_output)
    except json.JSONDecodeError:
        print(Fore.RED + "Failed to parse Mythril output.")
        logging.error("Mythril output is not valid JSON.")
        return issues

    if not results.get('issues'):
        print(Fore.GREEN + "No issues found during symbolic execution (Mythril).")
        return issues

    print(Fore.YELLOW + "Symbolic Execution Issues Found (Mythril):\n")
    for result in results['issues']:
        print(Fore.YELLOW + result['title'])
        logging.warning(f"Mythril Issue: {result['title']}")
        issue = {
            "type": result['title'],
            "description": result['description'],
            "explanation": get_explanation(result['title']),
            "function": result.get('function', 'N/A'),
            "severity": result['type'].lower()
        }
        # Avoid duplicating issues if Mythril reports for multiple contracts
        contract_name = os.path.basename(result.get('filename', 'UnknownContract'))
        issues[contract_name].append(issue)
    return issues


## --- Reporting ---

def display_issues(issues):
    """Displays all detected vulnerabilities in a formatted table in the console."""
    headers = ["Contract", "Function", "Issue Type", "Description", "Severity", "Explanation"]
    rows = []
    for contract, contract_issues in issues.items():
        for issue in contract_issues:
            severity = issue['severity']
            color = "red" if severity == "high" else "yellow" if severity == "medium" else "blue"
            rows.append([
                contract,
                issue['function'],
                colored(issue['type'], color),
                colored(issue['description'], color, attrs=['bold']),
                severity.capitalize(),
                issue['explanation']
            ])
    print(tabulate(rows, headers, tablefmt="grid"))
    return headers, rows

def save_issues_to_html(headers, rows, output_path):
    """Saves the vulnerability report to an interactive HTML file."""
    # Sanitize rows for HTML output, removing ANSI color codes
    clean_rows = []
    for row in rows:
        clean_row = [re.sub(r'\x1b\[[0-9;]*m', '', str(cell)) for cell in row]
        clean_rows.append(clean_row)

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Smart Contract Vulnerability Report</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
        <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.13.4/css/dataTables.bootstrap5.min.css"/>
        <style>body {{ font-family: Arial, sans-serif; }} .container {{ margin-top: 2rem; }}</style>
    </head>
    <body>
        <div class="container">
            <h2 class="mb-4">Smart Contract Vulnerability Report</h2>
            <table id="issuesTable" class="table table-striped table-bordered" style="width:100%">
                <thead>
                    <tr>{''.join(f'<th>{html.escape(header)}</th>' for header in headers)}</tr>
                </thead>
                <tbody>
                    {''.join('<tr>' + ''.join(f'<td>{html.escape(str(cell))}</td>' for cell in row) + '</tr>' for row in clean_rows)}
                </tbody>
            </table>
        </div>
        <script src="https://code.jquery.com/jquery-3.5.1.js"></script>
        <script type="text/javascript" src="https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js"></script>
        <script type="text/javascript" src="https://cdn.datatables.net/1.13.4/js/dataTables.bootstrap5.min.js"></script>
        <script>$(document).ready(function() {{ $('#issuesTable').DataTable(); }});</script>
    </body>
    </html>
    """
    with open(output_path, 'w') as file:
        file.write(html_content)
    logging.info(f"Report saved to {output_path}")


## --- Main Execution ---

def parse_arguments():
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(description="Solidity Smart Contract Vulnerability Analyzer")
    parser.add_argument("contract", help="Path to the Solidity contract file")
    parser.add_argument("--evm", default="london", choices=SUPPORTED_EVM_VERSIONS, help="EVM version to use for analysis")
    parser.add_argument("-o", "--output", default="vulnerability_report.html", help="Output HTML report path")
    return parser.parse_args()

def main():
    """Main function to orchestrate the vulnerability analysis."""
    args = parse_arguments()
    contract_path = args.contract

    if not os.path.exists(contract_path):
        print(Fore.RED + f"Error: The contract file {contract_path} does not exist.")
        logging.error(f"Contract file not found: {contract_path}")
        return

    try:
        # Step 1: Handle Solidity Compiler Version
        print(Fore.CYAN + "Extracting and setting Solidity compiler version...")
        solc_version_spec = extract_solidity_version(contract_path)
        install_solc_version_pragma(solc_version_spec)
        set_solc_version_pragma(solc_version_spec)
        logging.info(f"Using Solidity version compatible with: {solc_version_spec}")
        print(Fore.GREEN + "Compiler version set successfully.")

        # Step 2: Static Analysis with Slither
        print(Fore.CYAN + "\nRunning static analysis with Slither...")
        all_issues = run_slither_analysis(contract_path, args.evm)
        logging.info("Static analysis (Slither) completed.")
        print(Fore.GREEN + "Slither analysis complete.")

        # Step 3: Dynamic Analysis with Echidna (optional, can be commented out)
        print(Fore.CYAN + "\nRunning dynamic analysis with Echidna...")
        config_path = generate_echidna_config(contract_path)
        echidna_output = run_echidna(contract_path, config_path)
        contract_name = os.path.splitext(os.path.basename(contract_path))[0]
        all_issues = process_echidna_results(all_issues, echidna_output, contract_name)
        logging.info("Dynamic analysis (Echidna) completed.")

        # Step 4: Symbolic Execution with Mythril (optional, can be commented out)
        print(Fore.CYAN + "\nRunning symbolic execution with Mythril...")
        mythril_output = run_mythril(contract_path)
        all_issues = process_mythril_results(all_issues, mythril_output)
        logging.info("Symbolic execution (Mythril) completed.")

        # Step 5: Report Results
        if any(all_issues.values()):
            print(Fore.YELLOW + "\n\n=== Vulnerability Report ===\n")
            headers, rows = display_issues(all_issues)
            save_issues_to_html(headers, rows, args.output)
            print(Fore.GREEN + f"\nFull report saved to {args.output}")
        else:
            print(Fore.GREEN + "\n\n✅ No vulnerabilities found by any tool.")
            logging.info("Analysis complete. No issues found.")

    except Exception as e:
        print(Fore.RED + f"\nAn error occurred: {e}")
        logging.error(f"An unexpected error terminated the script: {e}")

if __name__ == "__main__":
    main()
