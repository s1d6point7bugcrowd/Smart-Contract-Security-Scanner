#!/usr/bin/env python3
"""
Complete Multi-Tool Vulnerability Analyzer
Integrates: Pattern Detection + Slither + Mythril + Solc Analysis
"""

import os
import re
import subprocess
import json
import argparse
from datetime import datetime
from collections import defaultdict

try:
    from solcx import install_solc, set_solc_version, compile_source
    from colorama import Fore, init
    from tabulate import tabulate
    init(autoreset=True)
    SOLC_AVAILABLE = True
except ImportError:
    SOLC_AVAILABLE = False
    print("Warning: py-solc-x and/or colorama not available, skipping Solidity compilation and color output.")

class MultiToolAnalyzer:
    def __init__(self, contract_path):
        self.contract_path = contract_path
        self.contract_name = os.path.splitext(os.path.basename(contract_path))[0]
        self.issues = defaultdict(list)
        self.tools_used = []

        self.slither_path = "/home/s1d6p01nt7/venv/bin/slither"
        self.echidna_path = "/usr/local/bin/echidna"
        
        with open(contract_path, 'r', encoding='utf-8') as f:
            self.source_code = f.read()
            self.lines = self.source_code.split('\n')
    
    def run_all_tools(self):
        """Run all available security analysis tools"""
        print(f"{Fore.CYAN}🔍 Starting comprehensive analysis...")
        
        print(f"{Fore.CYAN}[1/5] Running pattern-based detection...")
        self.run_pattern_detection()
        
        if SOLC_AVAILABLE:
            print(f"{Fore.CYAN}[2/5] Running Solidity compiler analysis...")
            self.run_solc_analysis()
        
        print(f"{Fore.CYAN}[3/5] Running Slither analysis...")
        self.run_slither_safe()
        
        print(f"{Fore.CYAN}[4/5] Running Echidna fuzzing...")
        self.run_echidna_safe()
        
        print(f"{Fore.CYAN}[5/5] Running Mythril analysis...")
        self.run_mythril_safe()
        
        return self.issues
    
    def run_pattern_detection(self):
        self.tools_used.append("Pattern Detection")
        patterns = [
            {'pattern': r'\.call\{value:\s*\w+\}\([^)]*\).*\n.*balances\[.*\]\s*[-=]', 'name': 'Reentrancy Vulnerability', 'severity': 'HIGH', 'description': 'External call followed by state change - potential reentrancy attack'},
            {'pattern': r'tx\.origin\s*==', 'name': 'tx.origin Usage', 'severity': 'MEDIUM', 'description': 'Using tx.origin for authentication can lead to phishing attacks'},
            {'pattern': r'selfdestruct\(', 'name': 'Self Destruct Usage', 'severity': 'HIGH', 'description': 'Contract can be destroyed - ensure proper access control'},
            {'pattern': r'\.\s*(latestRoundData|getPrice|getReserves)\s*\(', 'name': 'Oracle Usage Detected', 'severity': 'MEDIUM', 'description': 'Flags the use of a price oracle. MANUALLY REVIEW for potential flash loan manipulation.'},
            {'pattern': r'function\s+(execute|propose)\s*.*\s*delegatecall', 'name': 'Governance Delegatecall', 'severity': 'HIGH', 'description': 'A governance function is using delegatecall. This is extremely high-risk and requires a full audit.'},
            {'pattern': r'function\s+(execute|castVote)', 'name': 'Governance Action', 'severity': 'MEDIUM', 'description': 'A governance action function was found. MANUALLY VERIFY that a proper timelock is in place before execution can occur.'},
            {'pattern': r'ecrecover\s*\(', 'name': 'Signature Verification', 'severity': 'MEDIUM', 'description': 'ecrecover is used. MANUALLY VERIFY that nonces and EIP-712 domain separators are used correctly to prevent replay attacks.'},
            {'pattern': r'blockhash\s*\(', 'name': 'Blockhash Dependence', 'severity': 'MEDIUM', 'description': 'Use of blockhash is risky as it only returns recent hashes and can be manipulated by miners.'},
            {'pattern': r'function\s+\w*([Ww]ithdraw|[Ss]et|[Cc]hange|[Rr]emove|[Kk]ill)\(.*\)\s*(public|external)(?!.*\s(onlyOwner|onlyAdmin|modifierName))', 'name': 'Potentially Unrestricted Function', 'severity': 'HIGH', 'description': 'A critical function (withdraw, set, kill, etc.) may be missing access control. MANUALLY VERIFY its modifiers.'},
            {'pattern': r'^(?!.*\brequire\s*\().*\.\s*(transfer|approve|transferFrom)\s*\(', 'name': 'Unchecked ERC20 Return Value', 'severity': 'MEDIUM', 'description': 'An ERC20 call (transfer, approve, etc.) is made without checking the boolean return value. Use require() to wrap the call.'},
            {'pattern': r'\s(0x[a-fA-F0-9]{40})\s', 'name': 'Hardcoded Address', 'severity': 'INFORMATIONAL', 'description': 'A hardcoded address was found. Consider making it a configurable state variable for flexibility and security.'},
            {'pattern': r'(owner|rate|fee|treasury)\s*=\s*\w+;', 'name': 'Potential State Change Without Event', 'severity': 'LOW', 'description': 'A critical variable (owner, rate, etc.) may have been changed without emitting an event. MANUALLY VERIFY.'}
        ]
        for pattern_info in patterns:
            for match in list(re.finditer(pattern_info['pattern'], self.source_code, re.MULTILINE | re.IGNORECASE)):
                line_num = self.source_code[:match.start()].count('\n') + 1
                function_name = self._find_function_context(line_num)
                self.issues[self.contract_name].append({'tool': 'Pattern Detection', 'type': pattern_info['name'], 'description': pattern_info['description'], 'severity': pattern_info['severity'], 'line_number': line_num, 'function': function_name, 'code_snippet': self.lines[line_num - 1].strip()})

    def run_solc_analysis(self):
        try:
            self.tools_used.append("Solidity Compiler")
            version = self._extract_solc_version()
            install_solc(version)
            set_solc_version(version)
            compile_source(self.source_code)
            print(f"{Fore.GREEN}✓ Solidity compiler analysis completed")
        except Exception as e:
            print(f"{Fore.YELLOW}⚠ Solidity compiler analysis failed: {e}")

    def run_slither_safe(self):
        try:
            result = subprocess.run(
                [self.slither_path, self.contract_path, '--json', '-'],
                capture_output=True, text=True, timeout=60
            )
            if result.stdout and '"success": true' in result.stdout:
                self._process_slither_output(result.stdout)
                self.tools_used.append("Slither")
                print(f"{Fore.GREEN}✓ Slither analysis completed")
            else:
                print(f"{Fore.YELLOW}⚠ Slither analysis failed to run.")
                if result.stderr:
                    print(f"{Fore.YELLOW}Slither Error (stderr):\n{result.stderr}")
        except Exception as e:
            print(f"{Fore.YELLOW}⚠ Slither analysis failed with an exception: {e}")

    def _process_slither_output(self, slither_output):
        try:
            data = json.loads(slither_output)
            if data.get('success') and 'results' in data and 'detectors' in data['results']:
                for detector in data['results']['detectors']:
                    issue = {'tool': 'Slither', 'type': detector.get('check', 'Slither Detection'), 'description': detector.get('description').strip(), 'severity': detector.get('impact', 'Informational').upper(), 'line_number': 0, 'function': 'N/A', 'code_snippet': ''}
                    if 'elements' in detector and detector['elements']:
                        element = detector['elements'][0]
                        if 'source_mapping' in element and 'lines' in element['source_mapping']:
                            issue['line_number'] = element['source_mapping']['lines'][0]
                        if 'name' in element:
                            issue['function'] = element.get('name')
                    self.issues[self.contract_name].append(issue)
        except Exception as e:
            print(f"{Fore.YELLOW}⚠ Error processing Slither output: {e}")

    def run_mythril_safe(self):
        try:
            result = subprocess.run(['myth', 'analyze', self.contract_path, '--solv', 'auto', '-o', 'json'], capture_output=True, text=True, timeout=120)
            if result.stdout:
                self._process_mythril_output(result.stdout)
                self.tools_used.append("Mythril")
                print(f"{Fore.GREEN}✓ Mythril analysis completed")
            else:
                print(f"{Fore.YELLOW}⚠ Mythril had no findings")
        except Exception as e:
            print(f"{Fore.YELLOW}⚠ Mythril analysis failed: {e}")

    def _process_mythril_output(self, mythril_output):
        try:
            data = json.loads(mythril_output)
            if data.get('success') and data.get('issues'):
                for issue_data in data['issues']:
                    self.issues[self.contract_name].append({'tool': 'Mythril', 'type': issue_data.get('title', 'Mythril Detection'), 'description': issue_data.get('description'), 'severity': issue_data.get('severity', 'Medium').upper(), 'line_number': issue_data.get('lineno', 0), 'function': issue_data.get('function', 'N/A'), 'code_snippet': issue_data.get('code', '')})
        except Exception as e:
            print(f"{Fore.YELLOW}⚠ Error processing Mythril output: {e}")
            
    def _find_function_context(self, line_num):
        for i in range(line_num - 1, -1, -1):
            if i < len(self.lines):
                line = self.lines[i].strip()
                if match := re.match(r'function\s+(\w+)', line):
                    return match.group(1)
        return "N/A"

    def run_echidna_safe(self):
        try:
            result = subprocess.run(
                [self.echidna_path, self.contract_path, '--test-mode', 'assertion'],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                self.tools_used.append("Echidna")
                print(f"{Fore.GREEN}✓ Echidna fuzzing completed")
            else:
                if "No tests found" not in result.stderr:
                    print(f"{Fore.YELLOW}⚠ Echidna analysis failed or had no findings. Error: {result.stderr.strip()}")
                else:
                    self.tools_used.append("Echidna")
                    print(f"{Fore.GREEN}✓ Echidna fuzzing completed (no assertion tests found)")
        except Exception as e:
            print(f"{Fore.YELLOW}⚠ Echidna analysis failed with an exception: {e}")

    def _extract_solc_version(self):
        if match := re.search(r'pragma solidity\s+\^?([0-9]+\.[0-9]+\.\d+)', self.source_code):
            return match.group(1)
        if match := re.search(r'pragma solidity\s+\^?([0-9]+\.[0-9]+)', self.source_code):
            return f"{match.group(1)}.0"
        return "0.8.19"

    def generate_comprehensive_report(self, output_path):
        total_issues = sum(len(issues) for issues in self.issues.values())
        severity_stats = defaultdict(int)
        for issue_list in self.issues.values():
            for issue in issue_list:
                severity_stats[issue['severity']] += 1
        
        # --- FINAL FIX: Add 'OPTIMIZATION' to the sorting list for the HTML report ---
        severity_order = ['HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL', 'OPTIMIZATION']
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Comprehensive Security Analysis Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f8f9fa; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 30px; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 10px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: #f0f2f5; padding: 20px; border-radius: 10px; text-align: center; border-left: 5px solid #007bff; }}
        .stat-number {{ font-size: 2em; font-weight: bold; }}
        .high {{ color: #dc3545; }}
        .medium {{ color: #fd7e14; }}
        .low {{ color: #20c997; }}
        .info {{ color: #0dcaf0; }}
        .optimization {{ color: #6f42c1; }}
        .issue {{ border: 1px solid #dee2e6; margin: 15px 0; padding: 20px; border-radius: 8px; background: #fff; }}
        .issue-header {{ font-weight: bold; margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; }}
        .severity-badge {{ padding: 5px 10px; border-radius: 20px; color: white; font-size: 0.8em; }}
        .severity-HIGH {{ background: #dc3545; }}
        .severity-MEDIUM {{ background: #fd7e14; }}
        .severity-LOW {{ background: #20c997; }}
        .severity-INFORMATIONAL {{ background: #0dcaf0; }}
        .severity-OPTIMIZATION {{ background: #6f42c1; }}
        .code {{ background: #f8f9fa; padding: 15px; font-family: 'Consolas', monospace; border-radius: 5px; border-left: 4px solid #007bff; white-space: pre-wrap; word-wrap: break-word; }}
        .tool-badge {{ background: #6c757d; color: white; padding: 3px 8px; border-radius: 10px; font-size: 0.7em; }}
        .no-issues {{ text-align: center; padding: 40px; color: #28a745; }}
        .footer {{ text-align: center; margin-top: 30px; color: #6c757d; border-top: 1px solid #dee2e6; padding-top: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Comprehensive Smart Contract Security Report</h1>
            <p>Multi-Tool Analysis Results for {self.contract_name}</p>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        <div class="stats">
            <div class="stat-card"><div class="stat-number">{total_issues}</div><div>Total Issues</div></div>
            <div class="stat-card"><div class="stat-number high">{severity_stats.get('HIGH', 0)}</div><div>High Severity</div></div>
            <div class="stat-card"><div class="stat-number medium">{severity_stats.get('MEDIUM', 0)}</div><div>Medium Severity</div></div>
            <div class="stat-card"><div class="stat-number low">{severity_stats.get('LOW', 0)}</div><div>Low Severity</div></div>
            <div class="stat-card"><div class="stat-number info">{severity_stats.get('INFORMATIONAL', 0)}</div><div>Informational</div></div>
            <div class="stat-card"><div class="stat-number optimization">{severity_stats.get('OPTIMIZATION', 0)}</div><div>Optimization</div></div>
        </div>
        <h3>🔧 Tools Used: {', '.join(self.tools_used)}</h3>
        {'<div class="no-issues"><h2>✅ No Security Issues Found!</h2></div>' if total_issues == 0 else ''}
        {"".join([f'''
            <div class="issue">
                <div class="issue-header">
                    <div>
                        <span class="severity-badge severity-{issue['severity']}">{issue['severity']}</span>
                        <strong> {issue['type']}</strong>
                        <span class="tool-badge">{issue['tool']}</span>
                    </div>
                    <div>Function: {issue['function']} | Line: {issue['line_number']}</div>
                </div>
                <p>{issue['description']}</p>
                {f'<div class="code">{issue["code_snippet"]}</div>' if issue["code_snippet"] else ''}
            </div>
            ''' for issue_list in self.issues.values() for issue in sorted(issue_list, key=lambda i: severity_order.index(i['severity']))])}
        <div class="footer">
            <p>Report generated by Multi-Tool Vulnerability Analyzer</p>
        </div>
    </div>
</body>
</html>""")

def main():
    parser = argparse.ArgumentParser(description="Complete Multi-Tool Vulnerability Analyzer")
    parser.add_argument("contract", help="Path to Solidity contract")
    parser.add_argument("-o", "--output", default="comprehensive_report.html", help="Output report path")
    args = parser.parse_args()
    
    if not os.path.exists(args.contract):
        print(f"{Fore.RED}❌ Contract file not found: {args.contract}")
        return 1
    
    analyzer = MultiToolAnalyzer(args.contract)
    issues = analyzer.run_all_tools()
    
    analyzer.generate_comprehensive_report(args.output)
    
    total_issues = sum(len(i) for i in issues.values())
    
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}🛡️  COMPREHENSIVE SECURITY ANALYSIS COMPLETE")
    print(f"{Fore.CYAN}{'='*60}")
    print(f"\n{Fore.YELLOW}📊 Tools Used: {', '.join(analyzer.tools_used)}")
    
    if not total_issues:
        print(f"{Fore.GREEN}✅ No vulnerabilities detected by any tool!")
    else:
        print(f"{Fore.RED}⚠️  Total Issues Found: {total_issues}")
        severity_counts = defaultdict(int)
        tool_counts = defaultdict(int)
        for issue_list in issues.values():
            for issue in issue_list:
                severity_counts[issue['severity']] += 1
                tool_counts[issue['tool']] += 1
        
        # --- FINAL FIX: Add 'OPTIMIZATION' to the sorting list for the console report ---
        severity_order = ['HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL', 'OPTIMIZATION']
        print(f"\n{Fore.YELLOW}🎯 By Severity:")
        for severity, count in sorted(severity_counts.items(), key=lambda i: severity_order.index(i[0])):
            color = Fore.RED if severity == 'HIGH' else Fore.YELLOW if severity == 'MEDIUM' else Fore.BLUE if severity == 'LOW' else Fore.CYAN
            print(f"  {color}{severity}: {count}")
        
        print(f"\n{Fore.YELLOW}🔧 By Tool:")
        for tool, count in tool_counts.items():
            print(f"  {Fore.CYAN}{tool}: {count}")
    
    print(f"\n{Fore.GREEN}📊 Comprehensive report saved: {args.output}")
    print(f"{Fore.GREEN}🎉 Analysis complete!")
    return 0

if __name__ == "__main__":
    exit(main())
