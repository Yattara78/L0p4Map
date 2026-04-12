# 🚀 GUIDE DE DÉMARRAGE - ÉTAPE 1 EN PRATIQUE

**Comment démarrer immédiatement la refactorisation architecture?**

---

## ⏱️ TEMPS ESTIMÉ: 30 minutes pour setup

---

## ÉTAPE 0: Préparer votre environnement

### 1. Vérifier que tout fonctionne actuellement

```bash
cd /Users/user/Downloads/L0p4Map
source .venv/bin/activate

# Vérifier que l'app se lance
python ui/app.py
# → Doit voir la fenêtre PyQt6
# Ctrl+C pour arrêter

# Vérifier les tests
pytest tests/ -v
# → Tous les tests doivent passer
```

### 2. Créer une branche Git pour cette étape

```bash
git status
# → Doit afficher "nothing to commit, working tree clean"

git checkout -b etape1-architecture-refactor
# → Vous êtes maintenant sur une nouvelle branche

git branch -v
# → Vérifier que vous voyez "* etape1-architecture-refactor"
```

---

## ÉTAPE 1: Créer la structure de répertoires

### Jour 1 - Matin

**Tâche:** Créer tous les répertoires

```bash
cd /Users/user/Downloads/L0p4Map

# Créer répertoires core/
mkdir -p core/engine
mkdir -p core/evasion
mkdir -p core/database

# Créer répertoires ui/
mkdir -p ui/components
mkdir -p ui/dialogs

# Créer répertoires workers/
mkdir -p workers

# Créer répertoires utils/
mkdir -p utils

# Créer répertoires config/
mkdir -p config

# Créer répertoires plugins/
mkdir -p plugins

# Créer répertoires reports/
mkdir -p reports

# Vérifier structure
ls -la
tree -L 2
```

**Résultat attendu:**
```
L0p4Map/
├── core/
│   ├── engine/
│   ├── evasion/
│   ├── database/
│   └── scanners/ (déjà existant)
├── ui/
│   ├── components/
│   ├── dialogs/
│   └── assets/ (déjà existant)
├── workers/
├── utils/
├── config/
├── plugins/
├── reports/
└── [autres fichiers]
```

### Jour 1 - Après-midi

**Tâche:** Créer tous les `__init__.py`

```bash
# Créer __init__.py dans chaque répertoire
touch core/engine/__init__.py
touch core/evasion/__init__.py
touch core/database/__init__.py

touch ui/components/__init__.py
touch ui/dialogs/__init__.py

touch workers/__init__.py
touch utils/__init__.py
touch config/__init__.py
touch plugins/__init__.py
touch reports/__init__.py

# Vérifier
find . -name "__init__.py" | wc -l
# → Doit afficher au minimum 11
```

**Commit:**
```bash
git add -A
git commit -m "ÉTAPE 1.0: Créer structure répertoires de base"
git log --oneline -3
# Vérifier le commit
```

---

## ÉTAPE 2: Implémenter les fichiers SECURITY (Priority 1)

### Jour 2 - Matin

**Tâche:** Créer `utils/validators.py`

Créer le fichier `/Users/user/Downloads/L0p4Map/utils/validators.py` avec ce contenu:

```python
"""
Input Validation Module
Validation des entrées utilisateur
CRITIQUE pour prévention injection
"""

import ipaddress
import re
from typing import Tuple, List

class InputValidator:
    """Validateur d'entrées pour sécurité"""
    
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
            
            return True, sorted(set(result))
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
```

**Test:**
```bash
cd /Users/user/Downloads/L0p4Map

# Tester dans Python shell
python3 << 'EOF'
from utils.validators import InputValidator

# Test IP
valid, result = InputValidator.validate_ip("192.168.1.1")
print(f"IP Test: {valid} - {result}")

# Test Port
valid, result = InputValidator.validate_port(80)
print(f"Port Test: {valid} - {result}")

# Test Ports Range
valid, result = InputValidator.validate_ports_range("80,443,8000-8010")
print(f"Ports Range Test: {valid} - {result}")

print("✅ Tous les tests passent!")
EOF
```

**Résultat:**
```
IP Test: True - 192.168.1.1
Port Test: True - 80
Ports Range Test: True - [80, 443, 8000, 8001, ..., 8010]
✅ Tous les tests passent!
```

### Jour 2 - Après-midi

**Tâche:** Créer `utils/sanitizers.py`

Créer le fichier `/Users/user/Downloads/L0p4Map/utils/sanitizers.py` avec ce contenu:

```python
"""
Subprocess Sanitizer
ABSOLUMENT CRITIQUE pour prévention injection command
"""

import subprocess
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)

class SubprocessSanitizer:
    """Exécuter commandes de façon SÛRE"""
    
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
        if isinstance(command, str):
            logger.error("Command must be a list, not string")
            return False
        
        if not all(isinstance(arg, str) for arg in command):
            logger.error("All command arguments must be strings")
            return False
        
        return True
```

**Commit:**
```bash
git add utils/validators.py utils/sanitizers.py
git commit -m "ÉTAPE 1.1: Ajouter validation & sanitization (SÉCURITÉ)"
```

### Jour 3 - Matin

**Tâche:** Créer `utils/exceptions.py`

```bash
cat > /Users/user/Downloads/L0p4Map/utils/exceptions.py << 'EOF'
"""
Custom Exceptions pour L0p4Map
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
EOF
```

**Commit:**
```bash
git add utils/exceptions.py
git commit -m "ÉTAPE 1.2: Ajouter exceptions custom"
```

---

## ÉTAPE 3: Tester tout fonctionne

### Jour 3 - Après-midi

**Tâche:** Créer tests unitaires

```bash
cat > /Users/user/Downloads/L0p4Map/tests/test_validators.py << 'EOF'
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

def test_validate_ports_range():
    valid, result = InputValidator.validate_ports_range("80,443,1000-1002")
    assert valid == True
    assert 80 in result
    assert 443 in result
    assert 1000 in result
    assert 1001 in result
    assert 1002 in result

def test_validate_hostname_valid():
    valid, result = InputValidator.validate_hostname("google.com")
    assert valid == True

def test_validate_hostname_invalid():
    valid, result = InputValidator.validate_hostname("invalid..domain.com")
    assert valid == False

def test_validate_cidr():
    valid, result = InputValidator.validate_cidr("192.168.1.0/24")
    assert valid == True
EOF

# Lancer les tests
cd /Users/user/Downloads/L0p4Map
pytest tests/test_validators.py -v
```

**Résultat attendu:**
```
tests/test_validators.py::test_validate_ip_valid PASSED
tests/test_validators.py::test_validate_ip_invalid PASSED
tests/test_validators.py::test_validate_port_valid PASSED
tests/test_validators.py::test_validate_port_invalid PASSED
tests/test_validators.py::test_validate_ports_range PASSED
tests/test_validators.py::test_validate_hostname_valid PASSED
tests/test_validators.py::test_validate_hostname_invalid PASSED
tests/test_validators.py::test_validate_cidr PASSED

====== 8 passed in 0.15s ======
```

**Commit:**
```bash
git add tests/test_validators.py
git commit -m "ÉTAPE 1.3: Ajouter tests unitaires pour validators"
```

---

## ÉTAPE 4: Vérifier que l'app fonctionne toujours

### Jour 4 - Matin

```bash
# Lancer l'app
python ui/app.py
# → Vérifier qu'elle démarre sans erreur
# Ctrl+C pour arrêter

# Lancer TOUS les tests
pytest tests/ -v
# → Tous doivent passer
```

---

## ÉTAPE 5: Préparer la Pull Request

### Jour 4 - Après-midi

```bash
# Vérifier status
git status
# → Working tree clean

# Vérifier logs
git log --oneline -5
# Voir les commits

# Push vers GitHub
git push origin etape1-architecture-refactor

# Sur GitHub: Créer une Pull Request
# - Title: "ÉTAPE 1: Architecture refactoring base"
# - Description: Décrire les changements
# - Wait for review
# - Merge quand OK
```

---

## ✅ CHECKLIST POUR CETTE SEMAINE

- [ ] Structure répertoires créée
- [ ] Tous les `__init__.py` en place
- [ ] `utils/validators.py` implémenté
- [ ] `utils/sanitizers.py` implémenté
- [ ] `utils/exceptions.py` implémenté
- [ ] Tests unitaires écrits (8+ tests)
- [ ] Tous les tests passent
- [ ] App fonctionne toujours
- [ ] Commits propres et détaillés
- [ ] Push sur GitHub
- [ ] Pull Request ouverte

---

## 🎯 PROCHAINES ÉTAPES

Une fois cette partie terminée:
1. Lire **ETAPE_1_ARCHITECTURE.md** section "core/engine/scanner_engine.py"
2. Implémenter `core/engine/scanner_engine.py`
3. Refactoriser `ui/app.py` pour utiliser ScannerEngine
4. Merger dans main

---

## 📞 BESOIN D'AIDE?

Si vous êtes bloqué:
1. Vérifier la structure: `tree -L 3`
2. Lancer les tests: `pytest tests/ -v`
3. Vérifier les imports: `python -c "from utils.validators import InputValidator"`
4. Consulter **ETAPE_1_ARCHITECTURE.md** pour plus de détails

---

**Bonne chance! 🚀**

Vous faites les premiers pas vers L0p4Map v2.0!
