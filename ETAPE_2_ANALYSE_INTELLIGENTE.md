# 🧠 ÉTAPE 2: MOTEUR D'ANALYSE INTELLIGENT

**Objectif:** Transformer les résultats bruts en insights actionnables

---

## 🎯 VISION

### AVANT (Bête scanner)
```
[INPUT] Target: 192.168.1.100
↓
[SCAN] 15 ports ouverts détectés
↓
[OUTPUT] Port 445: SMB (samba 4.10)
         Port 22: SSH (OpenSSH 7.4)
         Port 3389: RDP
```

### APRÈS (Assistant intelligent)
```
[INPUT] Target: 192.168.1.100
↓
[SCAN] 15 ports ouverts
↓
[ANALYSE] 
- Port 445: SMB samba 4.10
  ⚠️ CVE-2017-0144 (EternalBlue) applicable
  🔴 RISQUE: Ransomware (WannaCry)
  💡 Action: Patch Samba immédiatement

- Port 3389: RDP non patchée
  🟠 RISQUE: MOYEN → Possible brute-force
  💡 Action: Forcer VPN + 2FA

[SCORE GLOBAL] 78/100 🔴 CRITIQUE
[RECOMMENDATION] Patch immédiat requis!
```

---

## 📋 MODULES À CRÉER

### 1. `core/engine/risk_calculator.py` (Calcul du Score de Risque)

**Concept:**
```
SCORE = (CVSS_score × 0.4) + (Exposure × 0.3) + (Exploitability × 0.2) + (Criticality × 0.1)

Facteurs:
- CVSS: 0-10 (sévérité vulnérabilité)
- Exposure: 0-10 (combien d'attaquants peuvent y accéder)
- Exploitability: 0-10 (facile à exploiter?)
- Criticality: 0-10 (importance du service)

Résultat: 0-100 (0=aucun risque, 100=critique)
```

**Couleurs:**
- 🟢 0-25: LOW (vert)
- 🟡 26-50: MEDIUM (jaune)
- 🟠 51-75: HIGH (orange)
- 🔴 76-100: CRITICAL (rouge)

**Code:**
```python
# core/engine/risk_calculator.py

from enum import Enum
from typing import Dict, Tuple
import math

class RiskLevel(Enum):
    LOW = ("LOW", "#00ff00", 0)           # Vert
    MEDIUM = ("MEDIUM", "#ffff00", 1)     # Jaune
    HIGH = ("HIGH", "#ff8800", 2)         # Orange
    CRITICAL = ("CRITICAL", "#ff0000", 3) # Rouge

class RiskCalculator:
    
    # Poids des différents facteurs
    WEIGHTS = {
        'cvss': 0.40,
        'exposure': 0.30,
        'exploitability': 0.20,
        'criticality': 0.10
    }
    
    # Table de mapping: (port, service) → criticality
    CRITICALITY_MAP = {
        (445, 'smb'): 10,      # SMB = Très critique
        (3389, 'rdp'): 9,      # RDP = Très critique
        (22, 'ssh'): 7,        # SSH = Élevé
        (3306, 'mysql'): 9,    # MySQL = Très critique
        (5432, 'postgresql'): 9, # PostgreSQL = Très critique
        (80, 'http'): 6,       # HTTP = Moyen
        (443, 'https'): 5,     # HTTPS = Moyen-bas
    }
    
    @staticmethod
    def calculate_score(
        cvss: float,
        exposed_ports: int,
        open_services: int,
        critical_services: int,
        cve_count: int,
        has_rce: bool = False
    ) -> Tuple[int, RiskLevel]:
        """
        Calculer le score global de risque
        
        Args:
            cvss: CVSS score (0-10)
            exposed_ports: Nombre de ports ouverts
            open_services: Nombre de services actifs
            critical_services: Nombre de services critiques (SMB, RDP, MySQL, etc)
            cve_count: Nombre de CVE applicables
            has_rce: True si RCE (Remote Code Execution) possible
        
        Returns:
            (score: int 0-100, risk_level: RiskLevel)
        
        Example:
            score, level = RiskCalculator.calculate_score(
                cvss=8.5,
                exposed_ports=15,
                open_services=5,
                critical_services=2,
                cve_count=3,
                has_rce=True
            )
            print(f"Score: {score}/100 ({level.value[0]})")  # Score: 85/100 (CRITICAL)
        """
        
        # 1. Score CVSS (0-10 → 0-40)
        cvss_score = min(cvss, 10) * (40 / 10)
        
        # 2. Score Exposition (combien d'attaquants peuvent y accéder)
        # Ports ouverts = exposition
        exposure_score = min(exposed_ports / 20 * 10, 10) * (30 / 10)  # Max 10 ports = 30 points
        
        # 3. Score Exploitabilité (facile à exploiter?)
        exploitability_score = 0
        if cve_count > 0:
            exploitability_score += min(cve_count * 2, 10)  # Max 5 CVE = 10 points
        if has_rce:
            exploitability_score += 5  # RCE = bonus +5
        exploitability_score = min(exploitability_score, 10) * (20 / 10)
        
        # 4. Score Criticité (importance des services)
        # Services critiques = risque élevé
        criticality_score = min(critical_services * 5, 10) * (10 / 10)
        
        # 5. Calcul total
        total_score = (
            cvss_score * RiskCalculator.WEIGHTS['cvss'] +
            exposure_score * RiskCalculator.WEIGHTS['exposure'] +
            exploitability_score * RiskCalculator.WEIGHTS['exploitability'] +
            criticality_score * RiskCalculator.WEIGHTS['criticality']
        )
        
        # Arrondir et limiter à 100
        total_score = min(int(total_score), 100)
        
        # 6. Déterminer le niveau de risque
        if total_score >= 76:
            level = RiskLevel.CRITICAL
        elif total_score >= 51:
            level = RiskLevel.HIGH
        elif total_score >= 26:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW
        
        return total_score, level
    
    @staticmethod
    def get_risk_color(score: int) -> str:
        """Obtenir la couleur en fonction du score"""
        if score >= 76:
            return RiskLevel.CRITICAL.value[1]
        elif score >= 51:
            return RiskLevel.HIGH.value[1]
        elif score >= 26:
            return RiskLevel.MEDIUM.value[1]
        else:
            return RiskLevel.LOW.value[1]
    
    @staticmethod
    def get_risk_emoji(score: int) -> str:
        """Obtenir emoji en fonction du score"""
        if score >= 76:
            return "🔴"
        elif score >= 51:
            return "🟠"
        elif score >= 26:
            return "🟡"
        else:
            return "🟢"


# Usage:
# from core.engine.risk_calculator import RiskCalculator
# score, level = RiskCalculator.calculate_score(
#     cvss=8.5,
#     exposed_ports=15,
#     open_services=5,
#     critical_services=2,
#     cve_count=3,
#     has_rce=True
# )
# print(f"{RiskCalculator.get_risk_emoji(score)} Score: {score}/100 - {level.value[0]}")
```

---

### 2. `core/engine/correlation_engine.py` (Corrélation Intelligente)

**Concept:**
```
Port 445 + SMB 4.10 + (CVE-2017-0144) 
          ↓
    Corrélation avec base d'exploits
          ↓
    → EternalBlue exploit → RCE possible
    → Windows 7/8/Server 2008-2012 vulnérable
    → Ransomware WannaCry probable
    → ACTION: Patch immédiat
```

**Code:**
```python
# core/engine/correlation_engine.py

from typing import Dict, List, Optional
from enum import Enum

class AttackType(Enum):
    RCE = "Remote Code Execution"
    LPE = "Local Privilege Escalation"
    DOS = "Denial of Service"
    BRUTEFORCE = "Bruteforce Attack"
    RANSOMWARE = "Ransomware"
    DATATHEFT = "Data Theft"
    LATERAL_MOVE = "Lateral Movement"

class CorrelationEngine:
    
    # Base de corrélations: (port, service, version) → possible_attacks
    ATTACK_PATTERNS = {
        # SMB vulnerabilities
        ('445', 'smb', '4.0-4.10'): {
            'cves': ['CVE-2017-0144', 'CVE-2017-0145'],
            'attacks': [AttackType.RCE, AttackType.RANSOMWARE],
            'exploits': ['EternalBlue (WannaCry)', 'NotPetya'],
            'severity': 'CRITICAL',
            'recommendation': 'Appliquer patch MS17-010 immédiatement'
        },
        
        # RDP vulnerabilities
        ('3389', 'rdp', '*'): {
            'cves': ['CVE-2019-0708'],
            'attacks': [AttackType.RCE, AttackType.BRUTEFORCE],
            'exploits': ['BlueKeep', 'Brute force RDP'],
            'severity': 'HIGH',
            'recommendation': 'Forcer VPN + 2FA, patcher Windows'
        },
        
        # SSH vulnerabilities
        ('22', 'ssh', '7.0-7.4'): {
            'cves': ['CVE-2018-15473'],
            'attacks': [AttackType.BRUTEFORCE],
            'exploits': ['SSH username enumeration'],
            'severity': 'MEDIUM',
            'recommendation': 'Upgrade SSH, désactiver auth par password'
        },
        
        # MySQL vulnerabilities
        ('3306', 'mysql', '5.5-5.7'): {
            'cves': ['CVE-2016-6662'],
            'attacks': [AttackType.RCE, AttackType.DATATHEFT],
            'exploits': ['MySQL privilege escalation'],
            'severity': 'CRITICAL',
            'recommendation': 'Upgrade MySQL, utiliser authentification par socket uniquement'
        },
    }
    
    @staticmethod
    def correlate(
        port: int,
        service: str,
        version: str,
        cves: List[str] = None
    ) -> Optional[Dict]:
        """
        Trouver des corrélations pour un service
        
        Args:
            port: Numéro de port
            service: Nom du service (smb, rdp, ssh, etc)
            version: Version du service
            cves: Liste des CVE applicables
        
        Returns:
            Dict avec attacks, exploits, severity, recommendation
        
        Example:
            result = CorrelationEngine.correlate(
                port=445,
                service='smb',
                version='4.5',
                cves=['CVE-2017-0144']
            )
            # Résultat:
            # {
            #   'attacks': [AttackType.RCE, AttackType.RANSOMWARE],
            #   'exploits': ['EternalBlue (WannaCry)'],
            #   'severity': 'CRITICAL',
            #   'recommendation': 'Appliquer patch MS17-010...'
            # }
        """
        
        key = (str(port), service, version)
        
        # 1. Recherche exacte
        if key in CorrelationEngine.ATTACK_PATTERNS:
            return CorrelationEngine.ATTACK_PATTERNS[key]
        
        # 2. Recherche avec wildcard version
        for pattern_key, pattern_value in CorrelationEngine.ATTACK_PATTERNS.items():
            pattern_port, pattern_service, pattern_version = pattern_key
            if str(port) == pattern_port and service == pattern_service:
                # Vérifier si version match
                if pattern_version == '*' or CorrelationEngine._version_match(version, pattern_version):
                    return pattern_value
        
        return None
    
    @staticmethod
    def _version_match(actual: str, pattern: str) -> bool:
        """Vérifier si version match le pattern (ex: 4.5 match 4.0-4.10)"""
        if pattern == '*':
            return True
        
        if '-' in pattern:
            try:
                start, end = pattern.split('-')
                actual_ver = float(actual.split('-')[0])
                start_ver = float(start)
                end_ver = float(end)
                return start_ver <= actual_ver <= end_ver
            except:
                return False
        
        return actual.startswith(pattern)
    
    @staticmethod
    def generate_report(services: List[Dict]) -> Dict:
        """
        Générer un rapport d'analyse complet pour une liste de services
        
        Args:
            services: Liste de services {'port': int, 'service': str, 'version': str, 'cves': list}
        
        Returns:
            {
                'total_risks': int,
                'critical_count': int,
                'high_count': int,
                'recommendations': List[str],
                'attack_surface': List[Dict]
            }
        """
        
        report = {
            'total_risks': 0,
            'critical_count': 0,
            'high_count': 0,
            'recommendations': [],
            'attack_surface': []
        }
        
        for service in services:
            correlation = CorrelationEngine.correlate(
                port=service['port'],
                service=service['service'],
                version=service['version'],
                cves=service.get('cves', [])
            )
            
            if correlation:
                report['total_risks'] += 1
                
                if correlation['severity'] == 'CRITICAL':
                    report['critical_count'] += 1
                elif correlation['severity'] == 'HIGH':
                    report['high_count'] += 1
                
                # Ajouter recommandation
                if correlation['recommendation'] not in report['recommendations']:
                    report['recommendations'].append(correlation['recommendation'])
                
                # Ajouter attack surface
                report['attack_surface'].append({
                    'port': service['port'],
                    'service': service['service'],
                    'version': service['version'],
                    'attacks': [a.value for a in correlation['attacks']],
                    'severity': correlation['severity'],
                    'cves': correlation['cves']
                })
        
        return report


# Usage:
# from core.engine.correlation_engine import CorrelationEngine
# result = CorrelationEngine.correlate(445, 'smb', '4.5', ['CVE-2017-0144'])
# print(f"Attacks: {result['attacks']}")
# print(f"Exploits: {result['exploits']}")
# print(f"Recommendation: {result['recommendation']}")
```

---

### 3. `core/engine/analysis_engine.py` (Analyse Complète)

```python
# core/engine/analysis_engine.py

from typing import Dict, List, Optional
from .risk_calculator import RiskCalculator
from .correlation_engine import CorrelationEngine

class AnalysisEngine:
    
    def __init__(self):
        self.risk_calc = RiskCalculator()
        self.correlation = CorrelationEngine()
    
    def analyze_scan_results(self, scan_results: Dict) -> Dict:
        """
        Analyser les résultats complets d'un scan
        
        Args:
            scan_results: {
                'target': str,
                'hosts': [
                    {
                        'ip': str,
                        'mac': str,
                        'hostname': str,
                        'os': str,
                        'services': [
                            {'port': int, 'protocol': str, 'service': str, 'version': str},
                            ...
                        ],
                        'cves': [
                            {'cve_id': str, 'cvss': float, 'description': str},
                            ...
                        ]
                    },
                    ...
                ]
            }
        
        Returns:
            Rapport d'analyse complet
        """
        
        analysis = {
            'scan_target': scan_results['target'],
            'hosts_analyzed': len(scan_results['hosts']),
            'overall_risk_score': 0,
            'overall_risk_level': None,
            'critical_vulnerabilities': [],
            'recommendations': [],
            'hosts_summary': []
        }
        
        max_score = 0
        
        for host in scan_results['hosts']:
            # Analyser chaque host
            host_analysis = self._analyze_host(host)
            analysis['hosts_summary'].append(host_analysis)
            
            # Tracker le score max
            if host_analysis['risk_score'] > max_score:
                max_score = host_analysis['risk_score']
            
            # Collector les vulnérabilités critiques
            for vuln in host_analysis['critical_vulnerabilities']:
                analysis['critical_vulnerabilities'].append({
                    'ip': host['ip'],
                    'hostname': host.get('hostname', 'N/A'),
                    'vulnerability': vuln
                })
            
            # Collector les recommandations uniques
            for rec in host_analysis['recommendations']:
                if rec not in analysis['recommendations']:
                    analysis['recommendations'].append(rec)
        
        # Score global = max score des hosts
        analysis['overall_risk_score'] = max_score
        analysis['overall_risk_level'] = RiskCalculator.get_risk_emoji(max_score)
        
        return analysis
    
    def _analyze_host(self, host: Dict) -> Dict:
        """Analyser un seul host"""
        
        services = host.get('services', [])
        cves = host.get('cves', [])
        
        # Compter les services critiques
        critical_services = self._count_critical_services(services)
        
        # Vérifier RCE
        has_rce = any(cve.get('cvss', 0) >= 8.0 for cve in cves)
        
        # Calculer CVSS moyen
        avg_cvss = sum(cve.get('cvss', 0) for cve in cves) / len(cves) if cves else 0
        
        # Calculer risque
        risk_score, risk_level = RiskCalculator.calculate_score(
            cvss=avg_cvss,
            exposed_ports=len(services),
            open_services=len(services),
            critical_services=critical_services,
            cve_count=len(cves),
            has_rce=has_rce
        )
        
        # Corrélations
        attack_surface = []
        for service in services:
            correlation = CorrelationEngine.correlate(
                port=service['port'],
                service=service['service'],
                version=service['version']
            )
            if correlation:
                attack_surface.append(correlation)
        
        return {
            'ip': host['ip'],
            'hostname': host.get('hostname', 'N/A'),
            'os': host.get('os', 'Unknown'),
            'risk_score': risk_score,
            'risk_level': risk_level.value[0],
            'services_count': len(services),
            'cves_count': len(cves),
            'critical_vulnerabilities': [att['exploits'] for att in attack_surface if att['severity'] == 'CRITICAL'],
            'recommendations': [att['recommendation'] for att in attack_surface if att['severity'] == 'CRITICAL'],
            'attack_surface': attack_surface
        }
    
    def _count_critical_services(self, services: List[Dict]) -> int:
        """Compter les services critiques"""
        critical = ['smb', 'rdp', 'mysql', 'postgresql', 'mongodb']
        return sum(1 for s in services if s.get('service', '').lower() in critical)


# Usage:
# from core.engine.analysis_engine import AnalysisEngine
# engine = AnalysisEngine()
# analysis = engine.analyze_scan_results(scan_results)
# print(f"Risk Score: {analysis['overall_risk_score']}/100")
# print(f"Critical Vulnerabilities: {len(analysis['critical_vulnerabilities'])}")
```

---

## 🧪 TESTS UNITAIRES

```python
# tests/test_analysis_engine.py

import pytest
from core.engine.risk_calculator import RiskCalculator, RiskLevel
from core.engine.correlation_engine import CorrelationEngine, AttackType
from core.engine.analysis_engine import AnalysisEngine

class TestRiskCalculator:
    
    def test_low_risk(self):
        score, level = RiskCalculator.calculate_score(
            cvss=2.0,
            exposed_ports=1,
            open_services=1,
            critical_services=0,
            cve_count=0
        )
        assert score <= 25
        assert level == RiskLevel.LOW
    
    def test_critical_risk(self):
        score, level = RiskCalculator.calculate_score(
            cvss=9.0,
            exposed_ports=10,
            open_services=5,
            critical_services=2,
            cve_count=3,
            has_rce=True
        )
        assert score >= 76
        assert level == RiskLevel.CRITICAL

class TestCorrelationEngine:
    
    def test_smb_correlation(self):
        result = CorrelationEngine.correlate(
            port=445,
            service='smb',
            version='4.5'
        )
        assert result is not None
        assert AttackType.RCE in result['attacks']
        assert 'Patch' in result['recommendation']

class TestAnalysisEngine:
    
    def test_analyze_scan_results(self):
        engine = AnalysisEngine()
        
        scan_results = {
            'target': '192.168.1.100',
            'hosts': [
                {
                    'ip': '192.168.1.100',
                    'hostname': 'server1',
                    'os': 'Windows Server 2012',
                    'services': [
                        {'port': 445, 'protocol': 'tcp', 'service': 'smb', 'version': '4.5'},
                        {'port': 22, 'protocol': 'tcp', 'service': 'ssh', 'version': '7.2'}
                    ],
                    'cves': [
                        {'cve_id': 'CVE-2017-0144', 'cvss': 9.0, 'description': 'EternalBlue'}
                    ]
                }
            ]
        }
        
        analysis = engine.analyze_scan_results(scan_results)
        assert analysis['hosts_analyzed'] == 1
        assert analysis['overall_risk_score'] >= 76

# Run:
# pytest tests/test_analysis_engine.py -v
```

---

## ✅ CHECKLIST ÉTAPE 2

- [ ] `core/engine/risk_calculator.py` - Complet et testé
- [ ] `core/engine/correlation_engine.py` - Complet et testé
- [ ] `core/engine/analysis_engine.py` - Complet et testé
- [ ] Tests unitaires passent 100%
- [ ] Documentation complète (docstrings)
- [ ] Git commit: "ÉTAPE 2: Moteur d'analyse intelligent"

---

**Durée estimée:** 5-7 jours
**Risque:** ⚠️ MOYEN
**Bénéfice:** 🚀 TRÈS ÉLEVÉ (intelligence automatique)
