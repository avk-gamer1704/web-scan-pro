# import requests
# import time
# import hashlib
# import random
# import string
# from urllib.parse import urlparse
# from bs4 import BeautifulSoup

# class AuthenticationTester:
#     """Enhanced authentication testing with weak credentials, insecure cookies, session fixation, brute-force, and session hijacking."""
    
#     def __init__(self, session=None, timeout=10):
#         self.session = session or requests.Session()
#         self.timeout = timeout
#         self.findings = []
        
#         # Enhanced common weak credentials
#         self.common_usernames = [
#             'admin', 'administrator', 'root', 'user', 'test', 'guest', 
#             'demo', 'admin1', 'operator', 'supervisor', 'default',
#             'sysadmin', 'webadmin', 'manager', 'support', 'info'
#         ]
        
#         self.common_passwords = [
#             'admin', 'password', '123456', 'password123', 'admin123', 
#             '12345678', 'qwerty', '123456789', '12345', '1234',
#             '111111', '1234567', 'dragon', '123123', 'abc123',
#             'letmein', 'monkey', 'shadow', 'master', 'passw0rd',
#             '', 'test', 'guest', 'default', '123', '1234', '12345'
#         ]
        
#         # Default credentials for common systems
#         self.default_credentials = {
#             'wordpress': [('admin', 'admin'), ('admin', 'password'), ('wpadmin', 'wpadmin')],
#             'joomla': [('admin', 'admin'), ('administrator', 'administrator')],
#             'drupal': [('admin', 'admin'), ('drupal', 'drupal')],
#             'tomcat': [('tomcat', 'tomcat'), ('admin', 'admin'), ('both', 'tomcat')],
#             'jenkins': [('admin', 'admin'), ('jenkins', 'jenkins')],
#             'router': [('admin', 'admin'), ('admin', 'password'), ('root', 'admin')],
#             'cpanel': [('root', 'cpanel'), ('admin', 'cpanel')],
#             'plesk': [('admin', 'admin'), ('admin', 'plesk')]
#         }

#     def test_weak_default_credentials(self, login_url, username_field='username', password_field='password'):
#         """Test for weak and default credentials with enhanced detection."""
#         print(f"[*] Testing weak and default credentials at: {login_url}")
        
#         tested_combinations = set()
        
#         # Test common weak credentials
#         for username in self.common_usernames:
#             for password in self.common_passwords:
#                 combination = f"{username}:{password}"
#                 if combination in tested_combinations:
#                     continue
                    
#                 tested_combinations.add(combination)
                
#                 if self.test_credential_combination(login_url, username, password, username_field, password_field, "Weak credential"):
#                     return True
        
#         # Test default credentials for common systems
#         for system, credentials in self.default_credentials.items():
#             for username, password in credentials:
#                 combination = f"{username}:{password}"
#                 if combination in tested_combinations:
#                     continue
                    
#                 tested_combinations.add(combination)
                
#                 if self.test_credential_combination(login_url, username, password, username_field, password_field, f"Default {system} credential"):
#                     return True
        
#         # Test empty credentials
#         if self.test_credential_combination(login_url, "", "", username_field, password_field, "Empty credential"):
#             return True
        
#         # Test SQL injection style credentials
#         sql_creds = [
#             ("' OR '1'='1", ""),
#             ("admin'--", ""),
#             ("' OR 1=1--", "")
#         ]
        
#         for username, password in sql_creds:
#             if self.test_credential_combination(login_url, username, password, username_field, password_field, "SQL injection credential"):
#                 return True
        
#         return False

#     def test_credential_combination(self, login_url, username, password, username_field, password_field, cred_type):
#         """Test a specific credential combination."""
#         try:
#             login_data = {
#                 username_field: username,
#                 password_field: password
#             }
            
#             response = self.session.post(login_url, data=login_data, timeout=self.timeout, allow_redirects=False)
            
#             if self.is_login_successful(response):
#                 finding = {
#                     'type': 'Weak/Default Credentials',
#                     'url': login_url,
#                     'username': username,
#                     'password': password,
#                     'credential_type': cred_type,
#                     'evidence': f'Successful login with {cred_type.lower()}',
#                     'fix_suggestion': 'Enforce strong password policies, implement account lockout mechanisms, use multi-factor authentication, and change default credentials'
#                 }
#                 self.findings.append(finding)
#                 print(f"[!] Found vulnerable credentials: {username}/{password} ({cred_type})")
#                 return True
        
#         except Exception as e:
#             print(f"[!] Error testing credentials {username}/{password}: {e}")
        
#         return False

#     def analyze_cookie_security(self, url, cookies):
#         """Comprehensive cookie security analysis."""
#         print(f"[*] Analyzing cookie security for: {url}")
#         insecure_cookies = []
        
#         for cookie in cookies:
#             cookie_issues = []
            
#             # Check for Secure flag
#             if url.startswith('https://') and not cookie.secure:
#                 cookie_issues.append("Missing Secure flag (cookie sent over insecure channel)")
            
#             # Check for HttpOnly flag
#             if not getattr(cookie, 'httponly', False):
#                 cookie_issues.append("Missing HttpOnly flag (accessible via JavaScript)")
            
#             # Check for SameSite attribute
#             samesite = getattr(cookie, 'samesite', None)
#             if not samesite or samesite.lower() not in ['strict', 'lax']:
#                 cookie_issues.append("Missing or weak SameSite attribute")
            
#             # Check expiration
#             if hasattr(cookie, 'expires'):
#                 if cookie.expires and cookie.expires > time.time() + 31536000:  # 1 year
#                     cookie_issues.append("Excessively long expiration time")
#                 elif not cookie.expires:
#                     cookie_issues.append("Session cookie (expires when browser closes)")
            
#             # Check domain scope
#             if cookie.domain and cookie.domain.startswith('.'):
#                 cookie_issues.append("Broad domain scope (accessible by subdomains)")
            
#             # Check for sensitive names
#             sensitive_names = ['session', 'auth', 'token', 'password', 'secret']
#             if any(name in cookie.name.lower() for name in sensitive_names):
#                 if not cookie_issues:  # Only warn if no other issues
#                     cookie_issues.append("Sensitive cookie name without security flags")
            
#             if cookie_issues:
#                 insecure_cookies.append({
#                     'name': cookie.name,
#                     'value_preview': cookie.value[:20] + '...' if len(cookie.value) > 20 else cookie.value,
#                     'domain': cookie.domain,
#                     'path': cookie.path,
#                     'issues': cookie_issues
#                 })
#                 print(f"[!] Insecure cookie: {cookie.name} - {', '.join(cookie_issues)}")
        
#         return insecure_cookies

#     def test_session_fixation(self, login_url, protected_url, username='test', password='test'):
#         """Enhanced session fixation test."""
#         print(f"[*] Testing session fixation at: {login_url}")
        
#         try:
#             # Create a new session and get pre-login cookies
#             pre_login_session = requests.Session()
#             pre_login_session.get(login_url, timeout=self.timeout)
#             pre_login_cookies = dict(pre_login_session.cookies)
            
#             if not pre_login_cookies:
#                 print("    No session cookies found before login")
#                 return
            
#             # Attempt login
#             login_data = {'username': username, 'password': password}
#             login_response = pre_login_session.post(login_url, data=login_data, timeout=self.timeout)
            
#             # Check if we can access protected content
#             protected_response = pre_login_session.get(protected_url, timeout=self.timeout)
            
#             # Analyze if session fixation is possible
#             if protected_response.status_code == 200:
#                 post_login_cookies = dict(pre_login_session.cookies)
                
#                 # Check if session ID remained the same
#                 session_changed = pre_login_cookies != post_login_cookies
                
#                 if not session_changed:
#                     finding = {
#                         'type': 'Session Fixation',
#                         'url': login_url,
#                         'evidence': 'Session ID remained valid after login (no regeneration)',
#                         'fix_suggestion': 'Always regenerate session ID after successful authentication. Invalidate old session tokens.'
#                     }
#                     self.findings.append(finding)
#                     print("[!] Session fixation vulnerability detected")
#                 else:
#                     print("[+] Session ID regenerated after login (secure)")
        
#         except Exception as e:
#             print(f"[!] Error testing session fixation: {e}")

#     def test_brute_force_protection(self, login_url, username_field='username', password_field='password'):
#         """Enhanced brute-force protection testing."""
#         print(f"[*] Testing brute-force protection at: {login_url}")
        
#         attempts = 0
#         start_time = time.time()
#         response_codes = []
#         response_times = []
        
#         # Generate test credentials
#         test_credentials = [
#             (f'test_user_{i}', f'test_pass_{i}') 
#             for i in range(1, 51)  # Test 50 attempts
#         ]
        
#         for username, password in test_credentials:
#             try:
#                 login_data = {
#                     username_field: username,
#                     password_field: password
#                 }
                
#                 request_start = time.time()
#                 response = self.session.post(login_url, data=login_data, timeout=self.timeout)
#                 request_time = time.time() - request_start
                
#                 response_codes.append(response.status_code)
#                 response_times.append(request_time)
#                 attempts += 1
                
#                 # Check for rate limiting
#                 if response.status_code == 429:  # Too Many Requests
#                     finding = {
#                         'type': 'Brute Force Protection - Rate Limiting',
#                         'url': login_url,
#                         'evidence': f'Rate limiting detected after {attempts} attempts (HTTP 429)',
#                         'fix_suggestion': 'Maintain current rate limiting implementation. Consider adding increasing delay for repeated failures.'
#                     }
#                     self.findings.append(finding)
#                     print("[+] Rate limiting protection detected")
#                     break
                
#                 # Check for account lockout
#                 if 'lock' in response.text.lower() or 'block' in response.text.lower():
#                     finding = {
#                         'type': 'Brute Force Protection - Account Lockout',
#                         'url': login_url,
#                         'evidence': 'Account lockout mechanism detected',
#                         'fix_suggestion': 'Maintain current account lockout policy. Consider temporary lockouts with automatic unlock.'
#                     }
#                     self.findings.append(finding)
#                     print("[+] Account lockout mechanism detected")
#                     break
                
#                 time.sleep(0.1)  # Small delay between requests
                
#             except Exception as e:
#                 print(f"[!] Error during brute-force test attempt {attempts}: {e}")
        
#         total_time = time.time() - start_time
        
#         # Analyze results
#         if 429 not in response_codes and attempts >= 20:
#             avg_response_time = sum(response_times) / len(response_times)
            
#             finding = {
#                 'type': 'Brute Force Vulnerability',
#                 'url': login_url,
#                 'evidence': f'No brute-force protection detected. {attempts} attempts in {total_time:.2f}s (avg response: {avg_response_time:.3f}s)',
#                 'fix_suggestion': 'Implement account lockout after 5-10 failed attempts, rate limiting, CAPTCHA challenges, and increasing delay mechanisms'
#             }
#             self.findings.append(finding)
#             print("[!] No brute-force protection detected")

#     def test_session_hijacking(self, login_url, username, password, protected_url):
#         """Comprehensive session hijacking tests."""
#         print(f"[*] Testing session hijacking vulnerabilities at: {login_url}")
        
#         try:
#             # Login to get session cookies
#             login_data = {'username': username, 'password': password}
#             login_response = self.session.post(login_url, data=login_data, timeout=self.timeout)
            
#             if not self.is_login_successful(login_response):
#                 print("    Login failed, cannot test session hijacking")
#                 return
            
#             # Analyze cookie security
#             insecure_cookies = self.analyze_cookie_security(login_url, self.session.cookies)
            
#             for cookie_info in insecure_cookies:
#                 finding = {
#                     'type': 'Insecure Session Cookie',
#                     'url': login_url,
#                     'cookie_name': cookie_info['name'],
#                     'issues': cookie_info['issues'],
#                     'evidence': f"Insecure cookie configuration: {cookie_info['name']}",
#                     'fix_suggestion': 'Set Secure, HttpOnly, and SameSite=Strict flags on all session cookies. Use short expiration times.'
#                 }
#                 self.findings.append(finding)
            
#             # Test session token predictability
#             session_cookies = [
#                 c for c in self.session.cookies 
#                 if any(name in c.name.lower() for name in ['session', 'sess', 'auth', 'token'])
#             ]
            
#             for cookie in session_cookies:
#                 if self.is_token_predictable(cookie.value):
#                     finding = {
#                         'type': 'Predictable Session Token',
#                         'url': login_url,
#                         'cookie': cookie.name,
#                         'token_sample': cookie.value[:20] + '...',
#                         'evidence': f"Predictable session token pattern in cookie: {cookie.name}",
#                         'fix_suggestion': 'Use cryptographically secure random number generators for session tokens. Ensure sufficient token length (min 128 bits).'
#                     }
#                     self.findings.append(finding)
#                     print(f"[!] Predictable session token in cookie: {cookie.name}")
            
#             # Test session expiration
#             self.test_session_expiration(login_url, protected_url)
            
#         except Exception as e:
#             print(f"[!] Error testing session hijacking: {e}")

#     def test_session_expiration(self, login_url, protected_url):
#         """Test session expiration mechanisms."""
#         print("[*] Testing session expiration")
        
#         try:
#             # Access protected resource
#             response1 = self.session.get(protected_url, timeout=self.timeout)
            
#             # Wait and test again
#             time.sleep(2)
#             response2 = self.session.get(protected_url, timeout=self.timeout)
            
#             # Check if session is still valid
#             if response2.status_code == 200 and not self.is_login_required(response2):
#                 print("    Session remains active after 2 seconds")
#                 # In a real test, you might want to test longer expiration times
#         except Exception as e:
#             print(f"[!] Error testing session expiration: {e}")

#     def is_login_successful(self, response):
#         """Enhanced login success detection."""
#         success_indicators = [
#             'logout', 'log out', 'my account', 'dashboard', 'welcome',
#             'successful', 'login successful', 'redirecting'
#         ]
        
#         failure_indicators = [
#             'invalid', 'error', 'failed', 'incorrect', 'try again'
#         ]
        
#         response_lower = response.text.lower()
        
#         # Check success indicators
#         success_score = sum(1 for indicator in success_indicators if indicator in response_lower)
        
#         # Check failure indicators
#         failure_score = sum(1 for indicator in failure_indicators if indicator in response_lower)
        
#         # Redirect after login is a strong indicator
#         has_redirect = len(response.history) > 0 and response.status_code == 200
        
#         # Session cookies set
#         has_session_cookies = any('session' in c.name.lower() for c in response.cookies)
        
#         return (success_score > failure_score) or has_redirect or has_session_cookies

#     def is_login_required(self, response):
#         """Check if response indicates login is required."""
#         login_indicators = [
#             'login', 'sign in', 'username', 'password', 'authenticate'
#         ]
#         response_lower = response.text.lower()
#         return any(indicator in response_lower for indicator in login_indicators)

#     def is_token_predictable(self, token):
#         """Enhanced token predictability detection."""
#         if not token or len(token) < 16:
#             return True
        
#         # Check for simple patterns
#         if token.isdigit() and len(token) < 10:  # Short numeric
#             return True
        
#         if all(c in '0123456789abcdef' for c in token.lower()) and len(token) == 32:  # Possible MD5
#             return True
        
#         # Check for sequential patterns
#         if len(set(token)) < len(token) * 0.3:  # Low entropy
#             return True
        
#         return False

#     def check_https_enforcement(self, url):
#         """Check HTTPS enforcement and configuration."""
#         print(f"[*] Checking HTTPS enforcement for: {url}")
        
#         parsed = urlparse(url)
        
#         if parsed.scheme == 'http':
#             https_url = f"https://{parsed.netloc}{parsed.path}"
            
#             try:
#                 # Test HTTPS availability
#                 response = requests.get(https_url, timeout=self.timeout, verify=False)
                
#                 if response.status_code == 200:
#                     finding = {
#                         'type': 'HTTPS Not Enforced',
#                         'url': url,
#                         'evidence': 'HTTPS is available but HTTP is not redirected to HTTPS',
#                         'fix_suggestion': 'Implement HTTP to HTTPS redirects. Use HSTS headers for additional security.'
#                     }
#                     self.findings.append(finding)
#                     print("[!] HTTPS available but not enforced")
            
#             except Exception as e:
#                 print(f"    HTTPS not available or error: {e}")

#     def run(self, login_urls, protected_urls=None):
#         """Run all authentication security tests."""
#         print("[*] Starting comprehensive authentication security tests")
        
#         for login_url in login_urls:
#             print(f"\n[*] Testing authentication at: {login_url}")
            
#             # Test weak and default credentials
#             self.test_weak_default_credentials(login_url)
            
#             # Test brute force protection
#             self.test_brute_force_protection(login_url)
            
#             # Test session fixation if protected URLs available
#             if protected_urls:
#                 for protected_url in protected_urls:
#                     self.test_session_fixation(login_url, protected_url)
            
#             # Check HTTPS enforcement
#             self.check_https_enforcement(login_url)
        
#         return self.findings

#     def run_advanced_tests(self, login_urls, protected_urls, username, password):
#         """Run advanced authentication tests requiring valid credentials."""
#         print("[*] Starting advanced authentication tests")
        
#         for login_url in login_urls:
#             if protected_urls:
#                 protected_url = protected_urls[0]
                
#                 # Test session hijacking with valid credentials
#                 self.test_session_hijacking(login_url, username, password, protected_url)
                
#                 # Re-test session fixation with valid credentials
#                 self.test_session_fixation(login_url, protected_url, username, password)

#     def generate_report(self):
#         """Generate comprehensive authentication security report."""
#         if not self.findings:
#             print("\n[*] No authentication vulnerabilities found.")
#             return
        
#         print("\n" + "="*80)
#         print("AUTHENTICATION SECURITY REPORT")
#         print("="*80)
        
#         # Security best practices summary
#         best_practices = [
#             "Always use HTTPS for authentication pages",
#             "Implement multi-factor authentication (MFA)",
#             "Enforce strong password policies",
#             "Use secure session management with proper expiration",
#             "Implement account lockout mechanisms",
#             "Regenerate session IDs after login",
#             "Use secure cookie flags (HttpOnly, Secure, SameSite)",
#             "Implement proper logging and monitoring",
#             "Use cryptographically secure random tokens",
#             "Regularly audit and test authentication mechanisms"
#         ]
        
#         print("\nAuthentication Security Best Practices:")
#         for i, practice in enumerate(best_practices, 1):
#             print(f"  {i}. {practice}")
        
#         # Group findings by type
#         findings_by_type = {}
#         for finding in self.findings:
#             finding_type = finding.get('type', 'Unknown')
#             if finding_type not in findings_by_type:
#                 findings_by_type[finding_type] = []
#             findings_by_type[finding_type].append(finding)
        
#         # Print findings by type
#         for finding_type, findings in findings_by_type.items():
#             print(f"\n--- {finding_type} Findings ---")
#             for i, finding in enumerate(findings, 1):
#                 print(f"\n{i}. Vulnerability Found:")
#                 print(f"   URL: {finding['url']}")
                
#                 if 'username' in finding:
#                     print(f"   Username: {finding['username']}")
#                 if 'password' in finding:
#                     print(f"   Password: {finding['password']}")
#                 if 'credential_type' in finding:
#                     print(f"   Type: {finding['credential_type']}")
#                 if 'cookie_name' in finding:
#                     print(f"   Cookie: {finding['cookie_name']}")
#                 if 'issues' in finding:
#                     print(f"   Issues: {', '.join(finding['issues'])}")
#                 if 'token_sample' in finding:
#                     print(f"   Token Sample: {finding['token_sample']}")
                
#                 print(f"   Evidence: {finding['evidence']}")
#                 print(f"   Suggested Fix: {finding.get('fix_suggestion', 'Implement proper authentication security measures')}")
        
#         print(f"\nTotal authentication vulnerabilities found: {len(self.findings)}")
#         print("="*80)
from urllib.parse import urlparse

class AuthenticationTester:
    """Tests for basic authentication vulnerabilities."""

    def run(self, login_urls):
        """
        Runs authentication checks on identified login URLs.

        Args:
            login_urls (list): A list of URLs that appear to be login pages.
        """
        findings = []
        
        for url in login_urls:
            parsed_url = urlparse(url)
            # Check for login forms served over HTTP
            if parsed_url.scheme != 'https':
                findings.append({
                    "type": "Insecure Authentication",
                    "severity": "High",
                    "url": url,
                    "description": f"Login form at {url} is served over an insecure (HTTP) connection. " \
                                   "Credentials could be intercepted."
                })
        
        return findings