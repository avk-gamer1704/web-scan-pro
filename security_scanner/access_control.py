# import time
# import random
# import string
# from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
# import requests

# class AccessControlTester:
#     """Test for access control vulnerabilities including IDOR and privilege escalation."""
    
#     def __init__(self, session=None, timeout=10):
#         self.session = session or requests.Session()
#         self.timeout = timeout
#         self.findings = []
        
#         # Common parameter names that might contain IDs
#         self.id_parameters = [
#             'id', 'user_id', 'userid', 'uid', 'account_id', 'accountid',
#             'document_id', 'doc_id', 'file_id', 'order_id', 'invoice_id',
#             'customer_id', 'client_id', 'patient_id', 'student_id'
#         ]
        
#         # Common administrative endpoints
#         self.admin_endpoints = [
#             '/admin', '/administrator', '/dashboard', '/manage',
#             '/controlpanel', '/cp', '/webadmin', '/sysadmin',
#             '/user/admin', '/api/admin', '/admin.php', '/admin.aspx'
#         ]
        
#         # Common user roles for testing
#         self.user_roles = ['user', 'admin', 'moderator', 'editor', 'guest']

#     def generate_test_ids(self, original_id):
#         """Generate test IDs for IDOR testing."""
#         try:
#             original_num = int(original_id)
#             return [
#                 str(original_num - 1),  # Previous ID
#                 str(original_num + 1),  # Next ID
#                 str(original_num + 100),  # Far ahead ID
#                 '0',  # Zero ID
#                 '-1',  # Negative ID
#                 "1' OR '1'='1",  # SQL injection style
#                 'null',  # Null value
#                 'true',  # Boolean
#                 'false'  # Boolean
#             ]
#         except (ValueError, TypeError):
#             # If not numeric, try other patterns
#             return [
#                 'test', 'admin', 'root', 'guest', 'user',
#                 '../', '../../', '../../../',
#                 '..././..././.../',
#                 '%2e%2e%2f',  # URL encoded ../
#                 '..%2f..%2f..%2f'
#             ]

#     def test_idor_url_parameters(self, pages):
#         """Test for IDOR vulnerabilities in URL parameters."""
#         print("[*] Testing for IDOR vulnerabilities in URL parameters")
        
#         for url, html in pages.items():
#             parsed = urlparse(url)
#             query_dict = parse_qs(parsed.query)
            
#             # Look for ID-like parameters
#             id_params = [param for param in query_dict.keys() 
#                         if any(id_keyword in param.lower() for id_keyword in self.id_parameters)]
            
#             if not id_params:
#                 continue
                
#             print(f"[*] Testing URL: {url}")
#             print(f"    Found ID parameters: {id_params}")
            
#             for param_name in id_params:
#                 original_values = query_dict[param_name]
                
#                 for original_value in original_values:
#                     test_ids = self.generate_test_ids(original_value)
                    
#                     for test_id in test_ids:
#                         # Create test query dict
#                         test_query = query_dict.copy()
#                         test_query[param_name] = [test_id]
                        
#                         # Rebuild URL
#                         new_query = urlencode(test_query, doseq=True)
#                         test_url = urlunparse((
#                             parsed.scheme,
#                             parsed.netloc,
#                             parsed.path,
#                             parsed.params,
#                             new_query,
#                             parsed.fragment
#                         ))
                        
#                         try:
#                             response = self.session.get(test_url, timeout=self.timeout)
                            
#                             # Check if we got access to unauthorized resources
#                             if self.is_unauthorized_access(response, html):
#                                 finding = {
#                                     'type': 'IDOR - Insecure Direct Object Reference',
#                                     'url': test_url,
#                                     'parameter': param_name,
#                                     'original_value': original_value,
#                                     'test_value': test_id,
#                                     'evidence': f"Accessed resource with modified {param_name} parameter",
#                                     'fix_suggestion': 'Implement proper access control checks. Use indirect object references or ensure authorization checks for every resource access.'
#                                 }
#                                 self.findings.append(finding)
#                                 print(f"[!] Potential IDOR vulnerability found in parameter '{param_name}'")
                        
#                         except Exception as e:
#                             print(f"[!] Error testing IDOR on {test_url}: {e}")
                        
#                         time.sleep(0.1)

#     def test_horizontal_escalation(self, base_url, test_user_ids=None):
#         """Test for horizontal privilege escalation."""
#         print("[*] Testing for horizontal privilege escalation")
        
#         if not test_user_ids:
#             test_user_ids = ['1001', '1002', '1003', 'admin', 'test']
        
#         # Common user profile patterns
#         user_profile_patterns = [
#             '/user/profile?id=',
#             '/user/view?id=',
#             '/account/details?id=',
#             '/profile/user?id=',
#             '/api/user/',
#             '/users/'
#         ]
        
#         for pattern in user_profile_patterns:
#             for user_id in test_user_ids:
#                 test_url = f"{base_url.rstrip('/')}{pattern}{user_id}"
                
#                 try:
#                     response = self.session.get(test_url, timeout=self.timeout)
                    
#                     # Check if we can access another user's data
#                     if response.status_code == 200 and self.contains_user_data(response.text):
#                         finding = {
#                             'type': 'Horizontal Privilege Escalation',
#                             'url': test_url,
#                             'user_id': user_id,
#                             'evidence': 'Able to access another user profile/data',
#                             'fix_suggestion': 'Implement proper user session validation. Ensure users can only access their own data.'
#                         }
#                         self.findings.append(finding)
#                         print(f"[!] Potential horizontal escalation vulnerability: {test_url}")
                
#                 except Exception as e:
#                     print(f"[!] Error testing horizontal escalation on {test_url}: {e}")
                
#                 time.sleep(0.1)

#     def test_vertical_escalation(self, base_url):
#         """Test for vertical privilege escalation to admin functions."""
#         print("[*] Testing for vertical privilege escalation")
        
#         for endpoint in self.admin_endpoints:
#             admin_url = f"{base_url.rstrip('/')}{endpoint}"
            
#             try:
#                 response = self.session.get(admin_url, timeout=self.timeout)
                
#                 # Check if we can access admin panel without proper privileges
#                 if response.status_code == 200 and self.is_admin_interface(response.text):
#                     finding = {
#                         'type': 'Vertical Privilege Escalation',
#                         'url': admin_url,
#                         'evidence': 'Able to access admin interface without proper privileges',
#                         'fix_suggestion': 'Implement role-based access control (RBAC). Ensure administrative endpoints require proper authentication and authorization.'
#                     }
#                     self.findings.append(finding)
#                     print(f"[!] Potential vertical escalation vulnerability: {admin_url}")
            
#             except Exception as e:
#                 print(f"[!] Error testing vertical escalation on {admin_url}: {e}")
            
#             time.sleep(0.1)

#     def test_missing_function_level_access_control(self, pages):
#         """Test for missing function level access control."""
#         print("[*] Testing for missing function level access control")
        
#         # Common privileged actions
#         privileged_actions = [
#             '/admin/delete',
#             '/admin/create',
#             '/admin/modify',
#             '/user/delete',
#             '/user/create',
#             '/api/delete',
#             '/api/create',
#             '/config',
#             '/settings'
#         ]
        
#         for url, html in pages.items():
#             for action in privileged_actions:
#                 if action in url:
#                     try:
#                         # Try to access the privileged URL
#                         response = self.session.get(url, timeout=self.timeout)
                        
#                         # Check if we can access privileged functions
#                         if response.status_code == 200 and not self.is_access_denied(response):
#                             finding = {
#                                 'type': 'Missing Function Level Access Control',
#                                 'url': url,
#                                 'evidence': 'Able to access privileged function without proper authorization',
#                                 'fix_suggestion': 'Implement function-level access control. Use role-based checks for every function call.'
#                             }
#                             self.findings.append(finding)
#                             print(f"[!] Missing function level access control: {url}")
                    
#                     except Exception as e:
#                         print(f"[!] Error testing function level access on {url}: {e}")
                    
#                     break  # Move to next URL

#     def is_unauthorized_access(self, response, original_html):
#         """Determine if we gained unauthorized access."""
#         # Simple heuristic based on response differences
#         if response.status_code == 200:
#             # Check if content is significantly different (might indicate different user data)
#             if len(response.text) > len(original_html) * 0.8:  # 80% similar size
#                 # Look for indicators of user-specific data
#                 user_indicators = ['user', 'profile', 'account', 'email', 'address', 'phone']
#                 if any(indicator in response.text.lower() for indicator in user_indicators):
#                     return True
        
#         return False

#     def contains_user_data(self, html):
#         """Check if HTML contains user-specific data."""
#         indicators = [
#             'user', 'profile', 'account', 'email', 'address', 'phone',
#             'birthdate', 'ssn', 'credit', 'bank', 'personal'
#         ]
#         html_lower = html.lower()
#         return any(indicator in html_lower for indicator in indicators)

#     def is_admin_interface(self, html):
#         """Check if the response contains admin interface indicators."""
#         admin_indicators = [
#             'admin', 'administrator', 'dashboard', 'control panel',
#             'user management', 'system settings', 'server status'
#         ]
#         html_lower = html.lower()
#         return any(indicator in html_lower for indicator in admin_indicators)

#     def is_access_denied(self, response):
#         """Check if access was denied."""
#         deny_indicators = [
#             'access denied', 'unauthorized', 'forbidden', 'permission denied',
#             '403', '401', 'login required'
#         ]
#         response_lower = response.text.lower()
#         return any(indicator in response_lower for indicator in deny_indicators) or response.status_code in [401, 403]

#     def suggest_access_control_improvements(self):
#         """Generate comprehensive access control improvement suggestions."""
#         suggestions = [
#             "Implement Role-Based Access Control (RBAC) with clear role definitions",
#             "Use Attribute-Based Access Control (ABAC) for complex scenarios",
#             "Always validate authorization on both client and server side",
#             "Implement proper session management with role information",
#             "Use indirect object references instead of direct database IDs",
#             "Implement proper error handling for unauthorized access attempts",
#             "Regularly audit access control policies and user permissions",
#             "Use principle of least privilege for all user accounts",
#             "Implement proper logging and monitoring of access attempts",
#             "Consider using access control frameworks or libraries"
#         ]
#         return suggestions

#     def run(self, pages, base_url):
#         """Run all access control tests."""
#         print("[*] Starting access control tests")
        
#         # Test IDOR in URL parameters
#         self.test_idor_url_parameters(pages)
        
#         # Test horizontal privilege escalation
#         self.test_horizontal_escalation(base_url)
        
#         # Test vertical privilege escalation
#         self.test_vertical_escalation(base_url)
        
#         # Test missing function level access control
#         self.test_missing_function_level_access_control(pages)
        
#         return self.findings

#     def generate_report(self):
#         """Generate a comprehensive report of access control vulnerabilities."""
#         if not self.findings:
#             print("\n[*] No access control vulnerabilities found.")
#             return
        
#         print("\n" + "="*80)
#         print("ACCESS CONTROL VULNERABILITY REPORT")
#         print("="*80)
        
#         # Group findings by type
#         findings_by_type = {}
#         for finding in self.findings:
#             finding_type = finding.get('type', 'Unknown')
#             if finding_type not in findings_by_type:
#                 findings_by_type[finding_type] = []
#             findings_by_type[finding_type].append(finding)
        
#         # Print findings by type
#         for finding_type, findings in findings_by_type.items():
#             print(f"\n--- {finding_type} ---")
#             for i, finding in enumerate(findings, 1):
#                 print(f"\n{i}. Vulnerability Found:")
#                 print(f"   URL: {finding['url']}")
                
#                 if 'parameter' in finding:
#                     print(f"   Parameter: {finding['parameter']}")
#                 if 'original_value' in finding:
#                     print(f"   Original Value: {finding['original_value']}")
#                 if 'test_value' in finding:
#                     print(f"   Test Value: {finding['test_value']}")
#                 if 'user_id' in finding:
#                     print(f"   User ID: {finding['user_id']}")
                
#                 print(f"   Evidence: {finding['evidence']}")
#                 print(f"   Suggested Fix: {finding.get('fix_suggestion', 'Implement proper access control mechanisms')}")
        
#         # Add general improvement suggestions
#         print(f"\nGeneral Access Control Improvement Suggestions:")
#         for i, suggestion in enumerate(self.suggest_access_control_improvements(), 1):
#             print(f"   {i}. {suggestion}")
        
#         print(f"\nTotal access control vulnerabilities found: {len(self.findings)}")
#         print("="*80)
import requests
from urllib.parse import urljoin

class AccessControlTester:
    """Tests for basic access control issues by checking for common sensitive paths."""
    
    def __init__(self):
        self.sensitive_paths = [
            "admin/",
            "administrator/",
            "login/",
            ".git/config",
            "wp-admin/",
            "robots.txt",
            "sitemap.xml",
            "backup.zip",
            "config.php.bak"
        ]
        self.findings = []

    def run(self, pages, base_url):
        """
        Checks for the existence of sensitive paths.

        Args:
            pages (list): A list of discovered URLs (currently unused, but for future extension).
            base_url (str): The base URL of the target.
        """
        print("    - Checking for sensitive paths...")
        for path in self.sensitive_paths:
            test_url = urljoin(base_url, path)
            try:
                res = requests.get(test_url, timeout=5, allow_redirects=False)
                if res.status_code == 200:
                    finding = {
                        "type": "Access Control",
                        "severity": "Medium" if "robots.txt" in path or "sitemap.xml" in path else "High",
                        "url": test_url,
                        "description": f"Sensitive path '{path}' is publicly accessible at {test_url}."
                    }
                    if finding not in self.findings:
                        self.findings.append(finding)
            except requests.RequestException:
                continue
        
        return self.findings