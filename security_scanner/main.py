#!/usr/bin/env python3
"""
Main entry point for the Security Scanner package.
Coordinates crawling, vulnerability testing, and report generation.
"""

import argparse
import sys
import os

# Import your custom scanner modules
from security_scanner.crawler import Crawler
from security_scanner.sqlitester import SQLiTester
from security_scanner.xss import XSSTester
from security_scanner.authentication import AuthenticationTester
from security_scanner.access_control import AccessControlTester
from security_scanner.reporter import Reporter

def main():
    """Main function to run the security scanner."""
    parser = argparse.ArgumentParser(
        description="Security Scanner - A comprehensive web vulnerability scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --url https://example.com --test-sqli
  %(prog)s --url https://test.com --test-all --max-pages 100
  %(prog)s --url https://site.com --test-sqli --test-xss --test-auth --test-access
        """
    )
    
    # Required arguments
    parser.add_argument("-u", "--url", 
                       required=True, 
                       help="Target URL to scan (e.g., https://example.com)")
    
    # Scan configuration
    parser.add_argument("-m", "--max-pages", 
                       type=int, 
                       default=50, 
                       help="Maximum number of pages to crawl (default: 50)")
    parser.add_argument("-d", "--delay", 
                       type=float, 
                       default=0.5, 
                       help="Delay between requests in seconds (default: 0.5)")
    
    # Vulnerability test options
    parser.add_argument("--test-sqli", 
                       action="store_true", 
                       help="Enable SQL injection testing")
    parser.add_argument("--test-xss", 
                       action="store_true", 
                       help="Enable XSS testing")
    parser.add_argument("--test-auth", 
                       action="store_true", 
                       help="Enable authentication testing")
    parser.add_argument("--test-access", 
                       action="store_true", 
                       help="Enable access control testing")
    parser.add_argument("--test-all", 
                       action="store_true", 
                       help="Enable all vulnerability tests")
    
    # Authentication credentials for advanced testing
    parser.add_argument("--auth-username", 
                       help="Username for authentication testing (optional)")
    parser.add_argument("--auth-password", 
                       help="Password for authentication testing (optional)")
    
    args = parser.parse_args()
    
    # If --test-all is specified, enable all tests
    if args.test_all:
        args.test_sqli = True
        args.test_xss = True
        args.test_auth = True
        args.test_access = True
    
    # Check if at least one test is enabled
    if not any([args.test_sqli, args.test_xss, args.test_auth, args.test_access]):
        print("Error: No vulnerability tests selected. Use --test-sqli, --test-xss, --test-auth, --test-access, or --test-all.")
        parser.print_help()
        return 1
    
    try:
        print("🔍 Starting Security Scanner")
        print("=" * 50)
        
        # Step 1: Crawl the target website
        print(f"\n[1/4] Crawling website: {args.url}")
        print(f"    Max pages: {args.max_pages}, Delay: {args.delay}s")
        
        crawler = Crawler(
            base_url=args.url, 
            max_pages=args.max_pages, 
            delay=args.delay
        )
        crawl_results = crawler.crawl()
        
        print(f"    ✓ Found {len(crawl_results['pages'])} pages and {sum(len(forms) for forms in crawl_results['forms'].values())} forms")
        
        # Step 2: Run vulnerability tests
        print(f"\n[2/4] Running vulnerability tests")
        all_findings = []
        
        # SQL Injection Testing
        if args.test_sqli:
            print("    • Testing SQL Injection vulnerabilities...")
            sqli_tester = SQLiTester()
            sqli_findings = sqli_tester.run(crawl_results['pages'], crawl_results['forms'])
            all_findings.extend(sqli_findings)
            print(f"      ✓ Found {len(sqli_findings)} potential SQLi vulnerabilities")
        
        # XSS Testing
        if args.test_xss:
            print("    • Testing XSS vulnerabilities...")
            xss_tester = XSSTester()
            xss_findings = xss_tester.run(crawl_results['pages'], crawl_results['forms'], args.url)
            all_findings.extend(xss_findings)
            print(f"      ✓ Found {len(xss_findings)} potential XSS vulnerabilities")
        
        # Authentication Testing
        if args.test_auth:
            print("    • Testing authentication vulnerabilities...")
            auth_tester = AuthenticationTester()
            
            # Extract login URLs from forms for authentication testing
            login_urls = []
            for url, forms in crawl_results['forms'].items():
                for form in forms:
                    if any(input_field.get('type') == 'password' for input_field in form['inputs']):
                        login_urls.append(form['action'] if form['action'] else url)
            
            if login_urls:
                auth_findings = auth_tester.run(login_urls)
                all_findings.extend(auth_findings)
                print(f"      ✓ Found {len(auth_findings)} authentication issues")
            else:
                print("      ℹ No login forms found for authentication testing")
        
        # Access Control Testing  
        if args.test_access:
            print("    • Testing access control vulnerabilities...")
            access_tester = AccessControlTester()
            access_findings = access_tester.run(crawl_results['pages'], args.url)
            all_findings.extend(access_findings)
            print(f"      ✓ Found {len(access_findings)} access control issues")
        
        # Step 3: Generate Reports
        print(f"\n[3/4] Generating reports")
        if all_findings:
            reporter = Reporter(target=args.url, findings=all_findings)
            
            html_report = reporter.render_html()
            pdf_report = reporter.render_pdf()
            
            print(f"    ✓ HTML Report: {html_report}")
            print(f"    ✓ PDF Report: {pdf_report}")
        else:
            print("    ℹ No vulnerabilities found to report")
        
        # Step 4: Summary
        print(f"\n[4/4] Scan Complete")
        print("=" * 50)
        
        # Count vulnerabilities by severity
        severity_counts = {"High": 0, "Medium": 0, "Low": 0}
        for finding in all_findings:
            severity = finding.get('severity', 'Low')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        total_vulnerabilities = len(all_findings)
        print(f"Total vulnerabilities found: {total_vulnerabilities}")
        print(f"  High: {severity_counts['High']}, Medium: {severity_counts['Medium']}, Low: {severity_counts['Low']}")
        
        if total_vulnerabilities > 0:
            print(f"\n📋 Reports generated in 'reports/' directory")
            return 0  # Success, vulnerabilities found
        else:
            print(f"\n✅ No vulnerabilities detected")
            return 0  # Success, no vulnerabilities found
            
    except KeyboardInterrupt:
        print(f"\n\n❌ Scan interrupted by user")
        return 130
    except Exception as e:
        print(f"\n💥 Error during scanning: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())