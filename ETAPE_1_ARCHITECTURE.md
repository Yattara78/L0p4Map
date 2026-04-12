# 🏗️ ÉTAPE 1: REFACTORISATION ARCHITECTURE

**Objectif:** Passer d'un monolithe à une architecture modulaire

---

## 📋 CHECKLIST COMPLÈTE

### Phase 1.1: Créer la structure de répertoires

- [ ] Créer `core/engine/` (moteur central)
- [ ] Créer `core/evasion/` (modules évasion)
- [ ] Créer `core/database/` (ORM + BD)
- [ ] Créer `ui/components/` (composants UI)
- [ ] Créer `ui/dialogs/` (dialogues)
- [ ] Créer `workers/` (QThread workers)
- [ ] Créer `utils/` (utilitaires)
- [ ] Créer `config/` (configuration)
- [ ] Créer `plugins/` (système plugins)
- [ ] Créer `reports/` (génération rapports)

### Phase 1.2: Créer les fichiers cœurs

#### Priority 1 - CRITIQUE (Jour 1)
- [ ] `core/engine/scanner_engine.py` - Orchestrateur principal
- [ ] `utils/validators.py` - Validation entrées
- [ ] `utils/sanitizers.py` - Sanitize subprocess
- [ ] `utils/exceptions.py` - Exceptions custom

#### Priority 2 - IMPORTANT (Jour 2-3)
- [ ] `core/engine/analysis_engine.py` - Analyse intelligente
- [ ] `core/engine/risk_calculator.py` - Scoring risque
- [ ] `core/engine/correlation_engine.py` - Corrélation CVE
- [ ] `ui/components/dashboard.py` - Vue d'ensemble

#### Priority 3 - BON À AVOIR (Jour 4-5)
- [ ] `config/settings.py` - Configuration centralisée
- [ ] `utils/logger.py` - Logging sécurisé
- [ ] `workers/scanner_worker.py` - QThread worker
- [ ] `workers/analysis_worker.py` - Worker analyse

---

## 🔧 FICHIERS À CRÉER (Ordre d'importance)

### 1. `core/engine/__init__.py`
```python
"""
Core engine module - Orchestrateur principal
"""
from .scanner_engine import ScannerEngine
from .analysis_engine import AnalysisEngine
from .risk_calculator import RiskCalculator

__all__ = ['ScannerEngine', 'AnalysisEngine', 'RiskCalculator']
```

### 2. `core/engine/scanner_engine.py` (PRIORITY 1)
```python
"""
Orchestrateur central pour tous les scans
Remplace la logique éparpillée dans ui/app.py
"""

from typing import Dict, List, Optional
import asyncio
from concurrent.futures import ThreadPoolExecutor

class ScannerEngine:
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.active_scans = {}
    
    def add_scan(self, scan_id: str, target: str, config: Dict) -> None:
        """Ajouter un scan à la queue"""
        pass
    
    def run_scan(self, target: str, config: Dict) -> Dict:
        """Exécuter un scan"""
        pass
    
    def cancel_scan(self, scan_id: str) -> None:
        """Arrêter un scan"""
        pass
    
    def get_scan_status(self, scan_id: str) -> Dict:
        """Obtenir statut d'un scan"""
        pass

# À implémenter: TCP scan, HTTP probe, SSL info, etc.
```

### 3. `utils/validators.py` (PRIORITY 1 - SÉCURITÉ)
```python
"""
Validation des entrées utilisateur
CRITIQUE pour prévention injection
"""

import ipaddress
import re
from typing import Tuple, List

class InputValidator:
    
    @staticmethod
    def validate_ip(ip: str) -> Tuple[bool, str]:
        """Valider une adresse IP"""
        try:
            ipaddress.ip_address(ip)
            return True, ip
        except ValueError as e:
            return False, f"Invalid IP: {str(e)}"
    
    @staticmethod
    def validate_port(port: int) -> Tuple[bool, str]:
        """Valider un port (1-65535)"""
        if not isinstance(port, int) or port < 1 or port > 65535:
            return False, f"Port must be 1-65535, got {port}"
        return True, str(port)
    
    @staticmethod
    def validate_ports_range(ports: str) -> Tuple[bool, List[int]]:
        """Valider une plage de ports (ex: '80,443,1000-2000')"""
        try:
            result = []
            for part in ports.split(','):
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    result.extend(range(start, end + 1))
                else:
                    result.append(int(part))
            
            # Vérifier tous les ports
            for p in result:
                if p < 1 or p > 65535:
                    return False, f"Port {p} out of range"
            
            return True, sorted(set(result))  # Deduplicate & sort
        except Exception as e:
            return False, f"Invalid port range: {str(e)}"
    
    @staticmethod
    def validate_hostname(hostname: str) -> Tuple[bool, str]:
        """Valider un hostname"""
        pattern = re.compile(
            r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$',
            re.IGNORECASE
        )
        if pattern.match(hostname):
            return True, hostname
        return False, f"Invalid hostname: {hostname}"
    
    @staticmethod
    def validate_cidr(cidr: str) -> Tuple[bool, str]:
        """Valider une plage CIDR"""
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True, cidr
        except ValueError as e:
            return False, f"Invalid CIDR: {str(e)}"


# Usage:
# valid, result = InputValidator.validate_ip("192.168.1.1")
# if not valid:
#     raise ValueError(result)
```

### 4. `utils/sanitizers.py` (PRIORITY 1 - SÉCURITÉ)
```python
"""
Sanitization pour prévenir injection command
ABSOLUMENT CRITIQUE
"""

import subprocess
import shlex
from typing import List, Optional, Dict
import logging

logger = logging.getLogger(__name__)

class SubprocessSanitizer:
    
    @staticmethod
    def run_command(
        command: List[str],
        timeout: int = 30,
        cwd: str = "/tmp",
        **kwargs
    ) -> Dict:
        """
        Exécuter une commande de façon SÛRE
        
        ✅ BON:
        run_command(['nmap', '-p', '80', '192.168.1.1'])
        
        ❌ MAUVAIS:
        os.system(f"nmap -p 80 {host}")  # Injection possible!
        """
        try:
            result = subprocess.run(
                command,
                timeout=timeout,
                cwd=cwd,
                capture_output=True,
                text=True,
                **kwargs
            )
            
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        
        except subprocess.TimeoutExpired:
            logger.error(f"Command timeout: {' '.join(command)}")
            return {
                'success': False,
                'error': 'Command timeout',
                'stdout': '',
                'stderr': ''
            }
        
        except Exception as e:
            logger.error(f"Command failed: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'stdout': '',
                'stderr': ''
            }
    
    @staticmethod
    def validate_command(command: List[str]) -> bool:
        """Valider une commande avant exécution"""
        # ✅ Vérifier que ce n'est pas une string (qui pourrait être injectée)
        if isinstance(command, str):
            logger.error("Command must be a list, not string")
            return False
        
        # ✅ Vérifier que ce sont des strings
        if not all(isinstance(arg, str) for arg in command):
            logger.error("All command arguments must be strings")
            return False
        
        return True


# Usage:
# result = SubprocessSanitizer.run_command(['nmap', '-p', '80', '192.168.1.1'])
# if result['success']:
#     print(result['stdout'])
```

### 5. `utils/exceptions.py` (PRIORITY 1)
```python
"""
Exceptions custom pour L0p4Map
"""

class L0p4MapException(Exception):
    """Base exception"""
    pass

class ValidationError(L0p4MapException):
    """Input validation error"""
    pass

class ScanError(L0p4MapException):
    """Scan execution error"""
    pass

class EvasionError(L0p4MapException):
    """Evasion technique error"""
    pass

class DatabaseError(L0p4MapException):
    """Database operation error"""
    pass

class PluginError(L0p4MapException):
    """Plugin loading/execution error"""
    pass

class PermissionError(L0p4MapException):
    """Insufficient permissions"""
    pass


# Usage:
# from utils.exceptions import ValidationError
# raise ValidationError("Invalid IP address")
```

---

## 🚀 INSTRUCTIONS DE MISE EN PLACE

### JOUR 1: Créer structure base
```bash
# 1. Créer tous les répertoires
mkdir -p core/engine core/evasion core/database
mkdir -p ui/components ui/dialogs
mkdir -p workers utils config plugins reports

# 2. Créer les __init__.py
touch core/engine/__init__.py
touch core/evasion/__init__.py
touch workers/__init__.py
touch utils/__init__.py
touch config/__init__.py
touch plugins/__init__.py
touch reports/__init__.py

# 3. Créer les fichiers prioritaires
touch core/engine/scanner_engine.py
touch utils/validators.py
touch utils/sanitizers.py
touch utils/exceptions.py
```

### JOUR 2-3: Implémenter Priority 1
- `core/engine/scanner_engine.py` - complet
- `utils/validators.py` - complet
- `utils/sanitizers.py` - complet
- `utils/exceptions.py` - complet

### JOUR 4-5: Implémenter Priority 2
- `core/engine/analysis_engine.py`
- `core/engine/risk_calculator.py`
- `core/engine/correlation_engine.py`

### JOUR 6: Refactoriser ui/app.py
- Importer `ScannerEngine`
- Remplacer logique scan par `engine.run_scan()`
- Cleanup code

---

## ✅ TESTS UNITAIRES (Important)

Pour chaque module créé, faire des tests:

```python
# tests/test_validators.py
import pytest
from utils.validators import InputValidator

def test_validate_ip_valid():
    valid, result = InputValidator.validate_ip("192.168.1.1")
    assert valid == True

def test_validate_ip_invalid():
    valid, result = InputValidator.validate_ip("999.999.999.999")
    assert valid == False

def test_validate_port_valid():
    valid, result = InputValidator.validate_port(80)
    assert valid == True

def test_validate_port_invalid():
    valid, result = InputValidator.validate_port(99999)
    assert valid == False

# Run:
# pytest tests/test_validators.py -v
```

---

## 📊 CHECKLIST DE VALIDATION

Une fois ÉTAPE 1 complétée:

- [ ] Tous les répertoires créés
- [ ] Tous les `__init__.py` en place
- [ ] `core/engine/scanner_engine.py` fonctionnel
- [ ] `utils/validators.py` avec 5+ validations
- [ ] `utils/sanitizers.py` prêt pour subprocess
- [ ] `utils/exceptions.py` avec 6+ exceptions custom
- [ ] Tests unitaires passent 100%
- [ ] `ui/app.py` refactorisé (imports engines)
- [ ] Code monolithique supprimé de ui/app.py
- [ ] Git commit: "ÉTAPE 1: Refactorisation architecture base"

---

## 📝 NOTES IMPORTANTES

1. **Sécurité d'ABORD**: Ne pas utiliser `os.system()`, `eval()`, `exec()`
2. **Tests**: Ajouter tests pour chaque fonction
3. **Documentation**: Docstrings sur chaque classe/fonction
4. **Type hints**: Utiliser type hints (Python 3.9+)
5. **Logging**: Log tout pour debug futur

---

**Durée estimée:** 5-7 jours
**Risque:** ⚠️ MOYEN (refactorisation large)
**Bénéfice:** 🚀 TRÈS ÉLEVÉ (fondation solide)
