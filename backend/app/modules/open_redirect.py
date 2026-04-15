import requests
from .base import AttackModule
import urllib3
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class OpenRedirectModule(AttackModule):
    name = "Open Redirect"
    description = "Detecta vulnerabilidades de redirecionamento aberto"
    severity = "medium"
    
    def run(self, target: str) -> dict:
        session = requests.Session()
        session.verify = False
        headers = {'User-Agent': 'AttackSim/1.0'}
        session.max_redirects = 1  # Não seguir redirects
        
        redirect_payloads = [
            "https://evil.com",
            "//evil.com",
            "https://google.com",
            "//google.com",
        ]
        
        results = []
        
        for payload in redirect_payloads:
            try:
                if '?' in target and '=' in target:
                    base, param = target.split('?', 1)
                    param_name, value = param.split('=', 1)
                    test_url = f"{base}?{param_name}={payload}"
                else:
                    test_url = f"{target}?redirect={payload}"
                
                response = session.get(test_url, headers=headers, timeout=10, allow_redirects=False)
                
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    if payload in location or 'evil.com' in location or 'google.com' in location:
                        results.append({
                            "payload": payload,
                            "evidence": f"Redirects to: {location}",
                            "confidence": "high"
                        })
                        
            except:
                continue
        
        if results:
            return {
                "success": True,
                "severity": "medium",
                "details": f"🎯 Found {len(results)} open redirects!",
                "findings": results[:3],
                "remediation": "Validate redirect URLs against a whitelist."
            }
        
        return {
            "success": False,
            "severity": "info",
            "details": "No open redirect vulnerabilities detected"
        }
