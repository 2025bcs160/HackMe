"""
Report generation module
"""

import json
import csv
from datetime import datetime
from typing import List, Dict

class Reporter:
    def __init__(self, output_format="text"):
        self.output_format = output_format
        self.timestamp = datetime.now()
    
    def generate_report(self, results: List[Dict], output_file: str = None) -> str:
        """
        Generate report in specified format
        """
        if self.output_format == "json":
            return self._generate_json_report(results, output_file)
        elif self.output_format == "csv":
            return self._generate_csv_report(results, output_file)
        else:
            return self._generate_text_report(results, output_file)
    
    def _generate_text_report(self, results: List[Dict], output_file: str = None) -> str:
        """
        Generate plain text report
        """
        report = []
        report.append("=" * 70)
        report.append("SQL INJECTION VULNERABILITY REPORT")
        report.append("=" * 70)
        report.append(f"Generated: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        if not results:
            report.append("[*] No vulnerabilities found!")
        else:
            report.append(f"[!] Found {len(results)} potential vulnerabilities:\n")
            
            for idx, vuln in enumerate(results, 1):
                report.append(f"\n{idx}. VULNERABILITY FOUND")
                report.append("-" * 70)
                report.append(f"   Type:       {vuln['type']}")
                report.append(f"   Parameter:  {vuln['parameter']}")
                report.append(f"   Payload:    {vuln['payload']}")
                report.append(f"   Status:     {vuln['status_code']}")
                report.append(f"   URL:        {vuln['url']}")
        
        report.append("\n" + "=" * 70)
        report.append("RECOMMENDATIONS:")
        report.append("=" * 70)
        report.append("1. Use parameterized queries/prepared statements")
        report.append("2. Implement input validation and sanitization")
        report.append("3. Use stored procedures with parameters")
        report.append("4. Apply principle of least privilege to database accounts")
        report.append("5. Implement Web Application Firewall (WAF)")
        report.append("6. Regular security audits and penetration testing")
        
        report_text = "\n".join(report)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report_text)
            print(f"\n[*] Report saved to: {output_file}")
        
        return report_text
    
    def _generate_json_report(self, results: List[Dict], output_file: str = None) -> str:
        """
        Generate JSON report
        """
        report = {
            "timestamp": self.timestamp.isoformat(),
            "total_vulnerabilities": len(results),
            "vulnerabilities": results,
            "recommendations": [
                "Use parameterized queries/prepared statements",
                "Implement input validation and sanitization",
                "Use stored procedures with parameters",
                "Apply principle of least privilege to database accounts",
                "Implement Web Application Firewall (WAF)",
                "Regular security audits and penetration testing"
            ]
        }
        
        report_json = json.dumps(report, indent=2)
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n[*] JSON report saved to: {output_file}")
        
        return report_json
    
    def _generate_csv_report(self, results: List[Dict], output_file: str = None) -> str:
        """
        Generate CSV report
        """
        if not output_file:
            output_file = f"sqli_report_{self.timestamp.strftime('%Y%m%d_%H%M%S')}.csv"
        
        with open(output_file, 'w', newline='') as f:
            if results:
                fieldnames = results[0].keys()
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(results)
        
        print(f"\n[*] CSV report saved to: {output_file}")
        return f"Report saved to {output_file}"
