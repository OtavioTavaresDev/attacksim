import requests
from .base import AttackModule
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class BruteForceModule(AttackModule):
    name = "Brute Force"
    description = "Testa força bruta em formulários de login"
    severity = "high"
    
    def run(self, target: str) -> dict:
        session = requests.Session()
        session.verify = False
        headers = {'User-Agent': 'AttackSim/1.0'}
        
        # Credenciais comuns para teste
        common_credentials = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("root", "root"),
            ("test", "test"),
        ]
        
        results = []
        
        for username, password in common_credentials:
            try:
                # Tentar GET (query params)
                if '?' in target:
                    test_url = f"{target}&username={username}&password={password}"
                else:
                    test_url = f"{target}?username={username}&password={password}"
                
                response_get = session.get(test_url, headers=headers, timeout=10)
                
                # Tentar POST (form data)
                data = {
                    'username': username,
                    'password': password,
                    'Login': 'Login'
                }
                response_post = session.post(target, data=data, headers=headers, timeout=10)
                
                # Verificar sucesso em qualquer resposta
                success_indicators = [
                    'login successful',
                    'welcome',
                    'session',
                    'vulnerable',
                    'success',
                    'dashboard',
                    'logout'
                ]
                
                for resp in [response_get, response_post]:
                    content = resp.text.lower()
                    for indicator in success_indicators:
                        if indicator in content:
                            results.append({
                                "username": username,
                                "password": password,
                                "method": "GET" if resp == response_get else "POST",
                                "evidence": f"Login successful with '{username}:{password}'",
                                "confidence": "high"
                            })
                            break
                    
            except Exception as e:
                continue
        
        if results:
            return {
                "success": True,
                "severity": "critical",
                "details": f"🎯 Found {len(results)} weak credentials!",
                "findings": results[:5],
                "remediation": "Implement account lockout, strong password policy, and 2FA"
            }
        
        return {
            "success": False,
            "severity": "info",
            "details": "No weak credentials found with basic wordlist",
            "remediation": "Site appears to have basic brute force protection"
        }
