#!/usr/bin/env python3
# alaa_hisham_scanner.py - Shadow Grade Vulnerability Oracle

import requests
import json
import re
import sys
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional
import time

# ------------------------------
# AI MODULE (replace with your API key or local model)
# ------------------------------
try:
    import openai
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    print("[!] OpenAI library not installed. AI analysis disabled. Install: pip install openai")

class AlaaHishamScanner:
    """Vulnerability scanner with AI reasoning core."""
    
    def __init__(self, domain: str, ai_api_key: str = None):
        self.domain = domain.rstrip('/')
        self.base_url = f"https://{domain}" if not domain.startswith('http') else domain
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'AlaaHisham-Scanner/1.0 (Security Research)'})
        self.vulnerabilities = []
        self.forms = []
        self.params = set()
        
        # AI config
        self.ai_enabled = AI_AVAILABLE and ai_api_key
        if self.ai_enabled:
            openai.api_key = ai_api_key
    
    def discover_forms(self, url: str) -> List[Dict]:
        """Extract all forms and their input fields."""
        try:
            resp = self.session.get(url, timeout=5)
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms_data = []
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                inputs = [inp.get('name') for inp in form.find_all('input') if inp.get('name')]
                forms_data.append({
                    'url': urljoin(url, action),
                    'method': method,
                    'inputs': inputs
                })
            return forms_data
        except Exception as e:
            print(f"[-] Form discovery error: {e}")
            return []
    
    def extract_params_from_url(self, url: str) -> set:
        """Parse query parameters from a URL."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return set(params.keys())
    
    def test_sqli(self, url: str, param: str) -> Dict:
        """Test for basic SQL injection (error-based)."""
        payloads = ["'", "\"", "' OR '1'='1", "1' AND '1'='2"]
        for payload in payloads:
            test_url = url.replace(f"{param}=", f"{param}={payload}")
            try:
                resp = self.session.get(test_url, timeout=3)
                if re.search(r"SQL syntax|mysql_fetch|ORA-[0-9]{5}|PostgreSQL|SQLite", resp.text, re.I):
                    return {"type": "SQL Injection", "param": param, "payload": payload, "evidence": "DB error reflected"}
            except:
                pass
        return None
    
    def test_xss(self, url: str, param: str) -> Dict:
        """Test for reflected XSS."""
        payload = "<script>alert('XSS')</script>"
        test_url = url.replace(f"{param}=", f"{param}={payload}")
        try:
            resp = self.session.get(test_url, timeout=3)
            if payload in resp.text and "<script>" in resp.text:
                return {"type": "Cross-Site Scripting (XSS)", "param": param, "payload": payload, "evidence": "Payload reflected unencoded"}
        except:
            pass
        return None
    
    def scan(self):
        """Main orchestration."""
        print(f"[+] Shadow Scan initiated for: {self.base_url}")
        
        # Step 1: Discover forms
        forms = self.discover_forms(self.base_url)
        for f in forms:
            for inp in f['inputs']:
                self.params.add(inp)
        
        # Step 2: Find URLs with parameters (simple crawl)
        try:
            resp = self.session.get(self.base_url, timeout=5)
            hrefs = re.findall(r'href=["\']([^"\']+)["\']', resp.text)
            for href in hrefs:
                full_url = urljoin(self.base_url, href)
                if self.domain in full_url:
                    params = self.extract_params_from_url(full_url)
                    self.params.update(params)
        except Exception as e:
            print(f"[-] Crawl error: {e}")
        
        print(f"[+] Discovered parameters: {self.params}")
        
        # Step 3: Vulnerability tests
        vulnerabilities_found = []
        for param in self.params:
            # Build a test URL (assumes GET param)
            test_url = f"{self.base_url}?{param}=test"
            # SQLi
            sqli_result = self.test_sqli(test_url, param)
            if sqli_result:
                vulnerabilities_found.append(sqli_result)
            # XSS
            xss_result = self.test_xss(test_url, param)
            if xss_result:
                vulnerabilities_found.append(xss_result)
        
        self.vulnerabilities = vulnerabilities_found
        
        # Step 4: AI analysis
        if self.ai_enabled and self.vulnerabilities:
            self.ai_analyze()
        elif self.ai_enabled and not self.vulnerabilities:
            print("[*] No vulnerabilities found. AI will verify.")
            self.ai_analyze(force=True)
    
    def ai_analyze(self, force=False):
        """Send findings to AI for deeper reasoning."""
        prompt = f"""
        You are an elite web security AI. Analyze these vulnerability scan results for domain {self.domain}.
        Findings: {json.dumps(self.vulnerabilities, indent=2)}.
        If no findings, suggest potential hidden attack surfaces (e.g., blind SQLi, DOM XSS, HTTP header injection).
        Provide a concise, actionable report with severity and recommendation.
        """
        try:
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "system", "content": "You are a cybersecurity AI."},
                          {"role": "user", "content": prompt}],
                temperature=0.3
            )
            ai_advice = response.choices[0].message.content
            self.vulnerabilities.append({"ai_analysis": ai_advice})
        except Exception as e:
            print(f"[!] AI analysis failed: {e}")
    
    def report(self):
        """Generate final output."""
        print("\n" + "="*60)
        print("🔍 SHΔDØW CORE V99 — SCAN REPORT")
        print(f"Target: {self.domain}")
        print(f"Vulnerabilities detected: {len([v for v in self.vulnerabilities if 'ai_analysis' not in v])}")
        print(json.dumps(self.vulnerabilities, indent=2, default=str))
        print("="*60)

# ------------------------------
# EXECUTION ENTRY
# ------------------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python alaa_hisham_scanner.py <domain> [openai_api_key]")
        sys.exit(1)
    
    domain = sys.argv[1]
    api_key = sys.argv[2] if len(sys.argv) > 2 else None
    
    scanner = AlaaHishamScanner(domain, api_key)
    scanner.scan()
    scanner.report()
