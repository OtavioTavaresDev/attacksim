import requests
from .base import AttackModule
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SecurityHeadersModule(AttackModule):
    name = "Security Headers"
    description = "Analisa headers de segurança HTTP"
    severity = "low"
    
    def run(self, target: str) -> dict:
        session = requests.Session()
        session.verify = False
        headers = {'User-Agent': 'AttackSim/1.0'}
        
        try:
            response = session.get(target, headers=headers, timeout=10)
            resp_headers = response.headers
            
            security_headers = {
                'Strict-Transport-Security': 'HSTS not configured',
                'Content-Security-Policy': 'CSP not configured',
                'X-Frame-Options': 'Clickjacking protection missing',
                'X-Content-Type-Options': 'MIME sniffing protection missing',
                'Referrer-Policy': 'Referrer policy not set',
                'Permissions-Policy': 'Permissions policy not set',
            }
            
            missing_headers = []
            for header, message in security_headers.items():
                if header not in resp_headers:
                    missing_headers.append({
                        "header": header,
                        "issue": message,
                        "severity": "medium" if header in ['Strict-Transport-Security', 'Content-Security-Policy'] else "low"
                    })
            
            score = 100 - (len(missing_headers) * 15)
            
            if missing_headers:
                return {
                    "success": True,
                    "severity": "medium" if len(missing_headers) > 3 else "low",
                    "details": f"Missing {len(missing_headers)} security headers. Score: {score}/100",
                    "findings": missing_headers,
                    "score": score,
                    "remediation": "Configure security headers in your web server"
                }
            
            return {
                "success": False,
                "severity": "info",
                "details": "All security headers properly configured! Score: 100/100",
                "score": 100
            }
            
        except:
            return {"success": False, "severity": "warning", "details": "Could not analyze target"}
