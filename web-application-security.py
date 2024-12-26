import requests
import time
from urllib.parse import urljoin

class WebScanner:
    def __init__(self, url):
        self.url = url
        self.session = requests.Session()
       
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()

    def check_security_headers(self):
        """Check for security headers"""
        print("\n[*] Checking Security Headers...")
        try:
            r = self.session.get(self.url)
            headers = r.headers

            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'X-Frame-Options': 'X-Frame-Options',
                'X-XSS-Protection': 'XSS Protection',
                'X-Content-Type-Options': 'X-Content-Type-Options',
                'Content-Security-Policy': 'CSP'
            }

            for header, name in security_headers.items():
                if header in headers:
                    print(f"[+] {name} found: {headers[header]}")
                else:
                    print(f"[-] {name} not found!")

        except Exception as e:
            print(f"[-] Error: {str(e)}")

    def scan_directories(self):
        """Scan for common sensitive directories"""
        print("\n[*] Scanning Sensitive Directories...")
        
        directories = [
            '/admin', '/login', '/wp-admin', '/backup', '/wp-content',
            '/config', '/.env', '/.git', '/api', '/includes', 
            '/upload', '/uploads', '/tmp', '/dev', '/test',
            '/sql', '/db', '/database', '/admin.php', '/wp-login.php',
            '/robots.txt', '/server-status', '/phpinfo.php'
        ]

        for directory in directories:
            try:
                url = urljoin(self.url, directory)
                r = self.session.get(url)
                if r.status_code in [200, 301, 302, 401, 403]:
                    print(f"[+] Found: {url} (Status: {r.status_code})")
            except Exception as e:
                continue

    def test_xss(self):
        """Perform basic XSS tests"""
        print("\n[*] Testing for XSS Vulnerabilities...")
        
        payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><script>alert(1)</script>',
            '"onmouseover="alert(1)',
            '<svg/onload=alert(1)>'
        ]

       
        for payload in payloads:
            try:
                url = f"{self.url}?q={payload}"
                r = self.session.get(url)
                if payload in r.text:
                    print(f"[!] Potential XSS vulnerability found: {url}")
            except:
                continue

    def test_sqli(self):
        """Perform basic SQL injection tests"""
        print("\n[*] Testing for SQL Injection Vulnerabilities...")
        
        payloads = [
            "'", 
            "1' OR '1'='1", 
            "1; DROP TABLE users",
            "' OR '1'='1' --",
            "' UNION SELECT NULL--",
            "admin' --",
            "admin' #",
            "' OR 1=1 #"
        ]
        
        errors = [
            'sql syntax',
            'mysql_fetch_array',
            'sqlite3_query',
            'PostgreSQL',
            'ORA-01756',
            'MySQL Error',
            'SQL Error'
        ]

       
        for payload in payloads:
            try:
                url = f"{self.url}?id={payload}"
                r = self.session.get(url)
                for error in errors:
                    if error.lower() in r.text.lower():
                        print(f"[!] Potential SQL Injection found: {url}")
                        print(f"    Error detected: {error}")
                        break
            except:
                continue

def main():
    banner = """
    ╔═══════════════════════════════════╗
    ║      Web Application Scanner      ║
    ║       Security Testing Tool       ║
    ╚═══════════════════════════════════╝    
    """
    print(banner)


    url = input("[?] Target URL (e.g., http://example.com): ")
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    print(f"\n[+] Target: {url}")
    print("[+] Starting scan...")
    
    scanner = WebScanner(url)
    
    try:
        scanner.check_security_headers()
        scanner.scan_directories()
        scanner.test_xss()
        scanner.test_sqli()
        
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user!")
        exit()
    
    print("\n[+] Scan completed!")

if __name__ == "__main__":
    main()