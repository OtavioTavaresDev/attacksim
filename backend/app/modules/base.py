from abc import ABC, abstractmethod
from typing import Dict, Any

class AttackModule(ABC):
    name: str = "Base Attack"
    description: str = ""
    severity: str = "info"  # info, low, medium, high, critical
    
    @abstractmethod
    def run(self, target: str) -> Dict[str, Any]:
        """Executa o ataque e retorna resultados."""
        pass

