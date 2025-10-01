# import time
# from urllib.parse import urlparse, urljoin, urldefrag
# from bs4 import BeautifulSoup
# import requests

# def get_session():
#     """Returns a requests.Session object for making HTTP requests."""
#     session = requests.Session()
#     session.headers.update({
#         'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
#     })
#     return session

# def is_same_domain(base_url, url):
#     """Checks if a given URL is on the same domain as the base URL."""
#     try:
#         return urlparse(base_url).netloc == urlparse(url).netloc
#     except ValueError:
#         return False

# def extract_links(html, page_url):
#     """Extracts all absolute links from a given HTML string."""
#     links = set()
#     soup = BeautifulSoup(html, 'html.parser')
#     for a_tag in soup.find_all('a', href=True):
#         href = a_tag.get('href')
#         absolute_url = urljoin(page_url, href)
#         links.add(absolute_url)
#     return list(links)

# def extract_forms(html, page_url):
#     """Extracts all forms from a given HTML string."""
#     forms = []
#     soup = BeautifulSoup(html, 'html.parser')
#     for form_tag in soup.find_all('form'):
#         form_info = {
#             'method': form_tag.get('method', 'get').lower(),
#             'action': urljoin(page_url, form_tag.get('action', '')),
#             'inputs': []
#         }
#         for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
#             input_info = {
#                 'name': input_tag.get('name'),
#                 'type': input_tag.get('type', 'text').lower(),
#                 'value': input_tag.get('value', '')
#             }
#             form_info['inputs'].append(input_info)
#         forms.append(form_info)
#     return forms

# class Crawler:
#     """A simple web crawler to find links and forms within a single domain."""
#     def __init__(self, base_url, max_pages=200, delay=0.2, session=None):
#         self.base = base_url.rstrip('/')
#         self.max_pages = max_pages
#         self.delay = delay
#         self.session = session or get_session()
#         self.visited = set()
#         self.queue = [self.base]
#         self.pages = {}
#         self.forms = {}
#         print(f"[*] Initializing crawler for base URL: {self.base}")
#         print(f"[*] Max pages to crawl: {self.max_pages}, delay: {self.delay}s")

#     def crawl(self):
#         """Starts the crawling process."""
#         while self.queue and len(self.visited) < self.max_pages:
#             url = self.queue.pop(0).rstrip('/')
            
#             print(f"\n[*] Processing URL: {url}")
            
#             if url in self.visited or not is_same_domain(self.base, url):
#                 print(f"[*] Skipping {url} (already visited or different domain)")
#                 continue

#             try:
#                 print(f"[*] Fetching content from: {url}")
#                 r = self.session.get(url, timeout=10, allow_redirects=True)
#                 r.raise_for_status() 
                
#                 self.pages[url] = r.text
#                 print(f"[+] Successfully fetched {url} (Status: {r.status_code})")
                
#                 forms = extract_forms(r.text, url)
#                 if forms:
#                     self.forms[url] = forms
#                     print(f"  [+] Found {len(forms)} form(s) on this page.")
                
#                 links = extract_links(r.text, url)
#                 print(f"  [+] Found {len(links)} link(s) on this page.")
#                 for l in links:
#                     l = urldefrag(l)[0].rstrip('/')
#                     if l and l not in self.visited and l not in self.queue and is_same_domain(self.base, l):
#                         self.queue.append(l)
#                         print(f"    - Added new link to queue: {l}")

#             except requests.exceptions.RequestException as e:
#                 print(f"[!] Failed to fetch {url}: {e}")
            
#             except Exception as e:
#                 print(f"[!] An unexpected error occurred with {url}: {e}")

#             finally:
#                 self.visited.add(url)
#                 print(f"[*] Visited pages count: {len(self.visited)}")
#                 time.sleep(self.delay)

#         return {'pages': self.pages, 'forms': self.forms}
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time

class Crawler:
    """Crawls a website to discover pages and forms."""
    
    def __init__(self, base_url, max_pages=50, delay=0.5):
        """
        Initializes the Crawler.
        
        Args:
            base_url (str): The starting URL to crawl.
            max_pages (int): The maximum number of pages to visit.
            delay (float): The delay in seconds between requests.
        """
        self.base_url = base_url
        self.max_pages = max_pages
        self.delay = delay
        self.domain = urlparse(base_url).netloc
        self.visited_urls = set()
        self.crawl_results = {
            "pages": [],
            "forms": {}
        }

    def crawl(self):
        """Starts the crawling process."""
        urls_to_visit = [self.base_url]
        
        while urls_to_visit and len(self.visited_urls) < self.max_pages:
            url = urls_to_visit.pop(0)
            if url in self.visited_urls:
                continue
            
            self.visited_urls.add(url)
            print(f"  -> Crawling: {url}")
            
            try:
                response = requests.get(url, timeout=5, allow_redirects=True)
                time.sleep(self.delay)
                
                if response.status_code == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                    self.crawl_results["pages"].append(url)
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    self._discover_links(soup, url, urls_to_visit)
                    self._discover_forms(soup, url)
                    
            except requests.RequestException as e:
                print(f"    [!] Error fetching {url}: {e}")

        return self.crawl_results

    def _discover_links(self, soup, current_url, urls_to_visit):
        """Finds all valid links on the page and adds them to the queue."""
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            full_url = urljoin(current_url, href)
            
            # Ensure the link is within the same domain and not an anchor
            if urlparse(full_url).netloc == self.domain and '#' not in full_url:
                if full_url not in self.visited_urls and full_url not in urls_to_visit:
                    urls_to_visit.append(full_url)

    def _discover_forms(self, soup, current_url):
        """Finds all forms on the page and extracts their details."""
        forms = soup.find_all('form')
        if not forms:
            return

        page_forms = []
        for form in forms:
            action = form.get('action')
            form_action_url = urljoin(current_url, action)
            method = form.get('method', 'get').lower()
            
            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')
                if input_name:
                    inputs.append({'name': input_name, 'type': input_type})
            
            page_forms.append({
                'action': form_action_url,
                'method': method,
                'inputs': inputs
            })
            
        if page_forms:
            self.crawl_results["forms"][current_url] = page_forms