import importlib
import pkgutil
from typing import List, Dict, Any
from app.modules import base
import docker
from docker.errors import DockerException
import json
import os

class AttackOrchestrator:
    def __init__(self):
        self.modules = self._load_modules()
        self.docker_client = None
        try:
            self.docker_client = docker.from_env()
        except DockerException:
            print("Docker não disponível. Execução sem sandbox (apenas desenvolvimento).")
    
    def _load_modules(self) -> List[base.AttackModule]:
        modules = []
        # Descobre todos os módulos no diretório app/modules
        package = importlib.import_module('app.modules')
        for _, module_name, _ in pkgutil.iter_modules(package.__path__):
            if module_name == 'base':
                continue
            mod = importlib.import_module(f'app.modules.{module_name}')
            for attr_name in dir(mod):
                attr = getattr(mod, attr_name)
                if (isinstance(attr, type) and 
                    issubclass(attr, base.AttackModule) and 
                    attr is not base.AttackModule):
                    modules.append(attr())
        return modules
    
    def run_scan(self, target: str, use_sandbox: bool = True) -> Dict[str, Any]:
        results = []
        for module in self.modules:
            if use_sandbox and self.docker_client:
                result = self._run_in_sandbox(module, target)
            else:
                result = module.run(target)
            results.append({
                "module": module.name,
                "result": result
            })
        
        # Calcular score de risco (simplificado)
        risk_score = self._calculate_risk_score(results)
        return {
            "target": target,
            "risk_score": risk_score,
            "modules": results
        }
    
    def _run_in_sandbox(self, module: base.AttackModule, target: str) -> Dict[str, Any]:
        """Executa o módulo em um container Docker isolado."""
        module_code = f"""
import json
import sys
sys.path.insert(0, '/app')
from app.modules.{module.__class__.__module__.split('.')[-1]} import {module.__class__.__name__}
module = {module.__class__.__name__}()
result = module.run("{target}")
print(json.dumps(result))
"""
        try:
            container = self.docker_client.containers.run(
                image="attacksim-sandbox:latest",
                command=["python", "-c", module_code],
                detach=True,
                remove=True,
                network="none",  # Isolamento de rede total
                mem_limit="256m",
                cpu_quota=50000,  # 50% de um core
                environment={"TARGET": target}
            )
            result = container.wait()
            logs = container.logs().decode('utf-8').strip()
            if logs:
                return json.loads(logs)
            return {"success": False, "details": "Sandbox execution failed", "severity": "error"}
        except Exception as e:
            return {"success": False, "details": str(e), "severity": "error"}
    
    def _calculate_risk_score(self, results: List[Dict]) -> float:
        severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
        total_score = 0
        max_score = 0
        for item in results:
            result = item["result"]
            severity = result.get("severity", "info")
            weight = severity_weights.get(severity, 0)
            total_score += weight * (1 if result.get("success") else 0.5)
            max_score += severity_weights.get("critical", 10)  # máximo possível
        return min(100, (total_score / max_score) * 100) if max_score > 0 else 0

