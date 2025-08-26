import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse

class WebVulnScanner:
    def __init__(self, base_url, max_depth=2):
        self.base_url = base_url
        self.session = requests.Session()
        self.visited = set()
        self.max_depth = max_depth
        self.forms = []

    def crawl(self, url=None, depth=0):
        if url is None:
            url = self.base_url
        if depth > self.max_depth or url in self.visited:
            return
        self.visited.add(url)
        print(f'Crawling {url}')
        try:
            resp = self.session.get(url, timeout=10)
            soup = BeautifulSoup(resp.text, 'html.parser')
            # Collect forms
            for form in soup.find_all('form'):
                form_details = self.get_form_details(form, url)
                self.forms.append(form_details)
            # Follow internal links
            for link in soup.find_all('a', href=True):
                href = link['href']
                joined = urljoin(url, href)
                if self.is_internal(joined):
                    self.crawl(joined, depth + 1)
        except Exception as e:
            print(f'Error crawling {url}: {e}')

    def is_internal(self, url):
        base = urlparse(self.base_url)
        target = urlparse(url)
        return base.netloc == target.netloc

    def get_form_details(self, form, page_url):
        details = {
            'action': urljoin(page_url, form.attrs.get('action', '')),
            'method': form.attrs.get('method', 'get').lower(),
            'inputs': [],
            'page': page_url
        }
        for input_tag in form.find_all('input'):
            input_type = input_tag.attrs.get('type', 'text')
            input_name = input_tag.attrs.get('name')
            details['inputs'].append({'type': input_type, 'name': input_name})
        return details

    def scan_xss(self, form):
        xss_payloads = [
            '<script>alert(1)</script>',
            '" onmouseover="alert(1)',
            "'><img src=x onerror=alert(1)>",
        ]
        for payload in xss_payloads:
            data = {}
            for input_field in form['inputs']:
                if input_field['type'] != 'submit' and input_field['name']:
                    data[input_field['name']] = payload
            try:
                if form['method'] == 'post':
                    resp = self.session.post(form['action'], data=data, timeout=10)
                else:
                    resp = self.session.get(form['action'], params=data, timeout=10)
                if payload in resp.text:
                    return True
            except Exception as e:
                print(f'XSS scan error: {e}')
        return False

    def scan_sqli(self, form):
        sqli_payloads = [
            "' OR '1'='1",
            '" OR "1"="1',
            "' OR 1=1--",
            'admin"--',
        ]
        error_patterns = [
            'you have an error in your sql syntax',
            'warning: mysql',
            'unclosed quotation mark after the character string',
            'quoted string not properly terminated',
            'sql syntax',
            'mysql_fetch',
            'syntax error',
            'ORA-01756',
        ]
        for payload in sqli_payloads:
            data = {}
            for input_field in form['inputs']:
                if input_field['type'] != 'submit' and input_field['name']:
                    data[input_field['name']] = payload
            try:
                if form['method'] == 'post':
                    resp = self.session.post(form['action'], data=data, timeout=10)
                else:
                    resp = self.session.get(form['action'], params=data, timeout=10)
                for error in error_patterns:
                    if re.search(error, resp.text, re.IGNORECASE):
                        return True
                # Boolean-based check: see if response changes with payload
                # (very basic, can be improved)
                if 'Welcome' in resp.text or 'admin' in resp.text:
                    return True
            except Exception as e:
                print(f'SQLi scan error: {e}')
        return False

    def scan_csrf(self, form):
        # Look for CSRF tokens in hidden inputs
        token_names = ['csrf', 'token', 'authenticity_token', 'anticsrf']
        has_token = False
        for input_field in form['inputs']:
            if input_field['type'] == 'hidden' and input_field['name']:
                for name in token_names:
                    if name in input_field['name'].lower():
                        has_token = True
        # Only flag forms that are POST/PUT/DELETE and lack a CSRF token
        if form['method'] in ['post', 'put', 'delete'] and not has_token:
            return True
        return False

    def run_all_scans(self):
        self.forms = []
        self.visited = set()
        self.crawl()
        results = []
        for form in self.forms:
            xss = self.scan_xss(form)
            sqli = self.scan_sqli(form)
            csrf = self.scan_csrf(form)
            results.append({'form': form, 'xss': xss, 'sqli': sqli, 'csrf': csrf})
        return results 