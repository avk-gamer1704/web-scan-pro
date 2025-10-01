# import os
# import json
# from datetime import datetime
# from jinja2 import Environment, FileSystemLoader

# try:
#     from weasyprint import HTML
#     WEASYPRINT_AVAILABLE = True
# except ImportError:
#     WEASYPRINT_AVAILABLE = False
#     print("WeasyPrint not available - PDF generation disabled")

# class Reporter:
#     def __init__(self, target, findings, out_dir='reports'):
#         self.target = target
#         self.findings = findings
#         self.out_dir = out_dir
#         os.makedirs(out_dir, exist_ok=True)
        
#         # Set up template environment - look for templates in project root
#         current_dir = os.path.dirname(os.path.abspath(__file__))
#         project_root = os.path.dirname(os.path.dirname(current_dir))
#         templates_dir = os.path.join(project_root, 'templates')
        
#         if not os.path.exists(templates_dir):
#             templates_dir = os.path.join(project_root, 'templates')
#             if not os.path.exists(templates_dir):
#                 # Fallback to current directory
#                 templates_dir = os.path.dirname(current_dir)
        
#         self.template_env = Environment(loader=FileSystemLoader(templates_dir))
    
#     def normalize_findings(self):
#         """Ensure all findings have consistent structure for reporting"""
#         out = []
#         for f in self.findings:
#             nf = dict(f)
#             # Ensure all required fields exist
#             nf['type'] = nf.get('type', 'Unknown Vulnerability')
#             nf['endpoint'] = nf.get('url') or nf.get('endpoint') or nf.get('action') or '-'
#             nf['parameter'] = nf.get('parameter') or nf.get('field') or nf.get('param', '-')
#             nf['payload'] = nf.get('payload') or nf.get('tested_value') or nf.get('username') or '-'
#             nf['evidence'] = nf.get('evidence') or nf.get('response_snippet') or 'Potential vulnerability detected'
#             nf['severity'] = self.severity_from_type(nf['type'])
#             nf['fix_suggestion'] = nf.get('fix_suggestion', 'Implement proper security controls')
#             out.append(nf)
#         return out

#     def severity_from_type(self, vuln_type):
#         """Determine severity based on vulnerability type"""
#         vuln_type_str = str(vuln_type).lower()
#         if any(xss in vuln_type_str for xss in ['xss', 'cross-site scripting']):
#             return 'High'
#         if any(sqli in vuln_type_str for sqli in ['sqli', 'sql injection']):
#             return 'High'
#         if any(auth in vuln_type_str for auth in ['idor', 'session', 'credentials', 'authentication']):
#             return 'Medium'
#         if any(access in vuln_type_str for access in ['access control', 'privilege']):
#             return 'Medium'
#         return 'Low'

#     def generate_summary_stats(self, findings):
#         """Generate summary statistics for the report"""
#         severity_counts = {'High': 0, 'Medium': 0, 'Low': 0}
#         type_counts = {}
        
#         for f in findings:
#             severity_counts[f['severity']] += 1
#             vuln_type = f['type']
#             type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        
#         return {
#             'severity_counts': severity_counts,
#             'type_counts': type_counts,
#             'total_vulnerabilities': len(findings)
#         }

#     def render_html(self, template_file='report_template.html'):
#         """Generate HTML report"""
#         try:
#             normalized_findings = self.normalize_findings()
#             summary = self.generate_summary_stats(normalized_findings)
            
#             template = self.template_env.get_template(template_file)
#             html_content = template.render(
#                 target=self.target,
#                 date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
#                 findings=normalized_findings,
#                 summary=summary
#             )
            
#             # Create safe filename
#             safe_target = "".join(c for c in self.target if c.isalnum() or c in ('-', '.', '_')).rstrip()
#             html_path = os.path.join(self.out_dir, f"security_report_{safe_target}.html")
            
#             with open(html_path, 'w', encoding='utf-8') as f:
#                 f.write(html_content)
            
#             print(f"✓ HTML report generated: {html_path}")
#             return html_path
            
#         except Exception as e:
#             print(f"✗ Error generating HTML report: {e}")
#             return None

#     def render_pdf(self):
#         """Generate PDF report from HTML"""
#         if not WEASYPRINT_AVAILABLE:
#             print("✗ WeasyPrint not available - install with: pip install weasyprint")
#             return None
            
#         try:
#             html_path = self.render_html()
#             if not html_path:
#                 return None
                
#             safe_target = "".join(c for c in self.target if c.isalnum() or c in ('-', '.', '_')).rstrip()
#             pdf_path = os.path.join(self.out_dir, f"security_report_{safe_target}.pdf")
            
#             HTML(html_path).write_pdf(pdf_path)
#             print(f"✓ PDF report generated: {pdf_path}")
#             return pdf_path
            
#         except Exception as e:
#             print(f"✗ Error generating PDF report: {e}")
#             return None

#     def generate_json_report(self):
#         """Generate JSON report for programmatic access"""
#         try:
#             normalized_findings = self.normalize_findings()
#             summary = self.generate_summary_stats(normalized_findings)
            
#             report_data = {
#                 'target': self.target,
#                 'scan_date': datetime.now().isoformat(),
#                 'summary': summary,
#                 'findings': normalized_findings
#             }
            
#             safe_target = "".join(c for c in self.target if c.isalnum() or c in ('-', '.', '_')).rstrip()
#             json_path = os.path.join(self.out_dir, f"security_report_{safe_target}.json")
            
#             with open(json_path, 'w', encoding='utf-8') as f:
#                 json.dump(report_data, f, indent=2)
            
#             print(f"✓ JSON report generated: {json_path}")
#             return json_path
            
#         except Exception as e:
#             print(f"✗ Error generating JSON report: {e}")
#             return None
import os
import datetime
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

class Reporter:
    """Generates vulnerability reports in HTML and PDF formats."""

    def __init__(self, target, findings):
        """
        Initializes the Reporter.

        Args:
            target (str): The target URL that was scanned.
            findings (list): A list of dictionaries, where each is a vulnerability finding.
        """
        self.target = target
        self.findings = sorted(findings, key=lambda x: {"High": 0, "Medium": 1, "Low": 2}.get(x['severity'], 3))
        self.report_dir = "reports"
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.base_filename = f"report_{self.timestamp}"
        
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)

        self.env = Environment(loader=FileSystemLoader('.'))
        self.template = self.env.get_template('report_template.html')

    def _render_html_content(self):
        """Renders the HTML content from the template."""
        scan_date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Calculate severity counts
        severity_counts = {"High": 0, "Medium": 0, "Low": 0}
        for finding in self.findings:
            severity = finding.get('severity', 'Low')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Calculate type counts to fix the new error
        type_counts = {}
        for finding in self.findings:
            finding_type = finding.get('type', 'Unknown')
            type_counts[finding_type] = type_counts.get(finding_type, 0) + 1
        
        # Create a summary dictionary with all required data
        summary_data = {
            "target": self.target,
            "scan_date": scan_date_str,
            "total_findings": len(self.findings),
            "severity_counts": severity_counts,
            "type_counts": type_counts # Add the vulnerability type counts
        }
        
        return self.template.render(
            target=self.target,
            findings=self.findings,
            scan_date=scan_date_str,
            summary=summary_data
        )

    def render_html(self):
        """Saves the report as an HTML file."""
        html_content = self._render_html_content()
        report_path = os.path.join(self.report_dir, f"{self.base_filename}.html")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return report_path

    def render_pdf(self):
        """Saves the report as a PDF file."""
        html_content = self._render_html_content()
        report_path = os.path.join(self.report_dir, f"{self.base_filename}.pdf")
        try:
            HTML(string=html_content).write_pdf(report_path)
            return report_path
        except Exception as e:
            print(f"    [!] Could not generate PDF report. Error: {e}")
            print("    [!] Make sure you have installed weasyprint dependencies (pango, cairo, etc.).")
            return None