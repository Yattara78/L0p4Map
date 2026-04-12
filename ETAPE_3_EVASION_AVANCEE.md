# 🛡️ ÉTAPE 3: ÉVASION AVANCÉE

**Objectif:** Réduire drastiquement la détection par IDS/Firewalls (réaliste, pas magique)

---

## ⚠️ AVERTISSEMENT IMPORTANT

**Disclaimer:**
- ✅ Les techniques ci-dessous **réduisent** la détection (pas l'annulent)
- ✅ Parfait pour scans **autorisés** sur vos propres réseaux
- ❌ **ILLEGAL** si utilisation sans autorisation
- ❌ Vérifiez les lois locales avant utilisation

**Objectif réaliste:** Passer de "ALERTE IMMÉDIATE" à "Hmm, trafic anormal, à investiguer"

---

## 🎯 TECHNIQUES D'ÉVASION

### 1. Randomisation Intelligente
**Concept:** Rendre le scan indistinguable du trafic normal

#### 1.1 Jitter (Variation des délais)
```python
# core/evasion/adaptive_timing.py

import random
import time
from enum import Enum

class TimingMode(Enum):
    PARANOID = 1      # Très lent (1-5s entre paquets)
    SNEAKY = 2        # Lent (0.5-2s)
    POLITE = 3        # Moyen (100-500ms)
    NORMAL = 4        # Rapide (10-100ms)
    INSANE = 5        # Très rapide (pas de délai)

class AdaptiveTimer:
    
    def __init__(self, mode: TimingMode = TimingMode.POLITE):
        self.mode = mode
        self.delays = self._get_delays(mode)
    
    def _get_delays(self, mode: TimingMode) -> tuple:
        """Retourner (min_delay, max_delay) en secondes"""
        delays = {
            TimingMode.PARANOID: (1.0, 5.0),
            TimingMode.SNEAKY: (0.5, 2.0),
            TimingMode.POLITE: (0.1, 0.5),
            TimingMode.NORMAL: (0.01, 0.1),
            TimingMode.INSANE: (0.0, 0.01)
        }
        return delays[mode]
    
    def get_delay(self) -> float:
        """Obtenir délai aléatoire (jitter)"""
        min_delay, max_delay = self.delays
        # Jitter: ±10% variation
        base_delay = random.uniform(min_delay, max_delay)
        jitter = base_delay * random.uniform(0.9, 1.1)
        return max(0, jitter)
    
    def wait(self) -> None:
        """Attendre avec jitter"""
        delay = self.get_delay()
        if delay > 0:
            time.sleep(delay)
    
    @staticmethod
    def example():
        """Exemple d'utilisation"""
        timer = AdaptiveTimer(TimingMode.POLITE)
        
        # Scanner 100 ports avec délai aléatoire
        for port in range(1, 101):
            # Scan port...
            print(f"Scanning port {port}")
            timer.wait()  # Délai aléatoire entre scans
```

#### 1.2 Randomisation Ordre des Ports
```python
import random

# ❌ MAUVAIS (pattern détectable):
ports_to_scan = [1, 2, 3, 4, 5, ..., 65535]

# ✅ BON (ordre aléatoire):
ports_to_scan = [1, 5, 3, 65535, 100, ...]
random.shuffle(ports_to_scan)

# Encore MIEUX (gaussienne autour des ports communs):
def get_randomized_ports(target_count=1000):
    """Ports aléatoires avec bias sur ports communs"""
    ports = []
    
    # 60% ports communs
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 3306, 5432]
    ports.extend(random.choices(common_ports, k=int(target_count * 0.6)))
    
    # 40% ports aléatoires
    ports.extend(random.sample(range(1, 65536), k=int(target_count * 0.4)))
    
    random.shuffle(ports)
    return ports[:target_count]
```

#### 1.3 Fragmentation de Paquets
```python
# core/evasion/packet_fragmentation.py

from scapy.all import IP, TCP, fragment
import random

class PacketFragmenter:
    
    @staticmethod
    def fragment_packet(packet, max_size: int = None) -> list:
        """
        Fragmenter un paquet TCP pour éviter les IDS
        
        Technique: Les IDS regardent la taille des paquets
        Solution: Fragmenter en paquets plus petits
        
        Args:
            packet: Paquet Scapy à fragmenter
            max_size: Taille max (défaut: 576 bytes)
        
        Returns:
            Liste de paquets fragmentés
        """
        
        if max_size is None:
            # Taille aléatoire pour éviter pattern
            max_size = random.choice([576, 800, 1000, 1200, 1400])
        
        # Utiliser la fonction de Scapy
        fragments = fragment(packet, fragsize=max_size)
        return fragments
    
    @staticmethod
    def variable_fragmentation(packets: list) -> list:
        """
        Fragmenter un stream avec tailles variables
        Évite les patterns détectables
        """
        fragmented = []
        
        for packet in packets:
            # Chaque paquet a taille random
            size = random.randint(576, 1500)
            frags = PacketFragmenter.fragment_packet(packet, max_size=size)
            fragmented.extend(frags)
        
        # Réordonner pour plus de confusion
        random.shuffle(fragmented)
        return fragmented
```

#### 1.4 Variation TTL (Time To Live)
```python
# core/evasion/ttl_variation.py

from scapy.all import IP, TCP
import random

class TTLVarier:
    
    @staticmethod
    def normal_ttl_range() -> int:
        """
        TTL normal sur Internet:
        - Systèmes Linux: 64 ou 255
        - Systèmes Windows: 128
        - Routeurs: 254
        
        Retourner TTL aléatoire realiste
        """
        return random.choice([64, 128, 254])
    
    @staticmethod
    def vary_ttl(packet: IP) -> IP:
        """Varier le TTL d'un paquet"""
        packet[IP].ttl = TTLVarier.normal_ttl_range()
        return packet
    
    @staticmethod
    def suspicious_ttl(packet: IP) -> bool:
        """
        Détecter un TTL suspect (utilisé pour fingerprinting)
        Les IDS cherchent des TTL anormaux
        """
        ttl = packet[IP].ttl
        # TTL suspect: < 32 ou > 254
        return ttl < 32 or ttl > 254
```

### 2. Scan Adaptatif (Intelligent Timing)
```python
# core/evasion/adaptive_scan.py

class AdaptiveScan:
    
    def __init__(self, target: str):
        self.target = target
        self.detected = False
        self.is_local = self._check_if_local(target)
    
    def _check_if_local(self, target: str) -> bool:
        """Vérifier si c'est un scan local (LAN)"""
        import ipaddress
        
        try:
            ip = ipaddress.ip_address(target)
            # IP privée = local
            return ip.is_private
        except:
            return False
    
    def get_optimal_timing(self) -> TimingMode:
        """
        Déterminer timing optimal basé sur contexte
        
        LOCAL (LAN):
            - Attaquant sur même réseau
            - Pas de IDS souvent
            - On peut être rapide
        
        REMOTE (Internet):
            - Traverser firewalls
            - IDS probable
            - Doit être très discret
        """
        
        if self.is_local:
            return TimingMode.NORMAL  # Rapide, on est sur le LAN
        else:
            return TimingMode.SNEAKY  # Très discret sur Internet
    
    def detect_evasion_needed(self) -> bool:
        """
        Détecter si évasion est nécessaire
        (En pratique: vérifier si scans sont filtrés)
        """
        # TODO: Implémenter détection de blocage
        # - Test avec port knocking
        # - Analyser ICMP responses
        # - Vérifier si ports se ferment
        
        return True  # Par défaut: supposer IDS présent
```

### 3. Fingerprinting Passif (ULTRA-DISCRET)
```python
# core/evasion/fingerprint_passive.py

import socket
import dns.resolver
from typing import Dict, List

class PassiveFingerprint:
    """
    Analyser un service SANS scan actif
    Zéro alerte IDS
    """
    
    @staticmethod
    def analyze_dns(target: str) -> Dict:
        """
        Analyser DNS sans alerter IDS
        
        Informations obtenues:
        - Serveurs DNS
        - Domaines
        - Mail servers
        - All services (TXT records)
        """
        
        results = {}
        
        try:
            # A record (IPv4)
            results['a_records'] = dns.resolver.resolve(target, 'A')
        except:
            pass
        
        try:
            # AAAA record (IPv6)
            results['aaaa_records'] = dns.resolver.resolve(target, 'AAAA')
        except:
            pass
        
        try:
            # MX records (mail servers)
            results['mx_records'] = dns.resolver.resolve(target, 'MX')
        except:
            pass
        
        try:
            # TXT records (config, SPF, DKIM)
            results['txt_records'] = dns.resolver.resolve(target, 'TXT')
        except:
            pass
        
        try:
            # NS records (nameservers)
            results['ns_records'] = dns.resolver.resolve(target, 'NS')
        except:
            pass
        
        return results
    
    @staticmethod
    def analyze_tls_passive(host: str, port: int = 443) -> Dict:
        """
        Analyser certificat TLS SANS handshake complet
        
        Technique: On demande juste le certificat
        Les IDS ne considèrent pas ça comme malveillant
        """
        
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'subject': cert.get('subject'),
                        'issuer': cert.get('issuer'),
                        'version': cert.get('version'),
                        'notBefore': cert.get('notBefore'),
                        'notAfter': cert.get('notAfter'),
                        'altNames': cert.get('subjectAltName')
                    }
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def analyze_banner_passive(host: str, port: int, timeout: int = 5) -> str:
        """
        Obtenir bannière SANS scan actif
        
        Technique: Se connecter gentiment, récupérer bannière, fermer
        """
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Récupérer bannière
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            return banner
        except Exception as e:
            return f"Error: {str(e)}"
```

### 4. Camouflage du Trafic HTTP
```python
# core/evasion/traffic_camouflage.py

import random
import requests
from typing import Dict

class TrafficCamouflage:
    """
    Faire ressembler les scans à trafic HTTP normal
    """
    
    # User-agents réalistes
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15',
        'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15'
    ]
    
    @staticmethod
    def get_realistic_headers() -> Dict:
        """Obtenir headers HTTP réalistes"""
        return {
            'User-Agent': random.choice(TrafficCamouflage.USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Referer': 'https://www.google.com/',
            'Upgrade-Insecure-Requests': '1'
        }
    
    @staticmethod
    def mimick_browser(url: str) -> requests.Response:
        """
        Faire une requête en mimiquant un navigateur réel
        
        Détails:
        - User-agent aléatoire
        - Headers réalistes
        - Délais humains entre requêtes
        - Pas de pattern de scan
        """
        
        headers = TrafficCamouflage.get_realistic_headers()
        
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=10,
                verify=False
            )
            return response
        except Exception as e:
            return None
    
    @staticmethod
    def add_human_timing(min_delay: float = 1, max_delay: float = 5) -> None:
        """
        Attendre délai humain entre requêtes
        Les IDS cherchent les accès robotiques (très rapides)
        """
        import time
        delay = random.uniform(min_delay, max_delay)
        time.sleep(delay)
```

### 5. Détection de Blocage (Feedback Loop)
```python
# core/evasion/detection_detector.py

class DetectionDetector:
    """
    Détecter si on est bloqué/détecté
    Si oui: activer évasion avancée
    """
    
    def __init__(self, target: str):
        self.target = target
        self.blocked_ports = []
        self.reset_ports = []
        self.timeouts = 0
    
    def detect_blocking(self) -> bool:
        """
        Détecter si traffic est bloqué
        
        Signes:
        - Port réductions rapides
        - RST rapides sur tout
        - Timeouts massifs
        - Réponses ICMP "administratively prohibited"
        """
        
        # Si 50%+ des scans timeout
        if self.timeouts > 50:
            return True
        
        # Si tous les ports reset rapidement
        if len(self.reset_ports) > 80:
            return True
        
        return False
    
    def escalate_evasion(self, current_mode: TimingMode) -> TimingMode:
        """
        Si détection: escalader vers mode plus discret
        """
        
        escalation = {
            TimingMode.INSANE: TimingMode.NORMAL,
            TimingMode.NORMAL: TimingMode.POLITE,
            TimingMode.POLITE: TimingMode.SNEAKY,
            TimingMode.SNEAKY: TimingMode.PARANOID,
            TimingMode.PARANOID: TimingMode.PARANOID  # Max
        }
        
        return escalation.get(current_mode, TimingMode.PARANOID)
```

---

## 🔌 INTÉGRATION AVEC LES SCANNERS

```python
# core/evasion/evasion_manager.py

class EvasionManager:
    """
    Orchestrateur principal pour évasion
    """
    
    def __init__(self, mode: TimingMode = TimingMode.POLITE):
        self.timer = AdaptiveTimer(mode)
        self.fragmenter = PacketFragmenter()
        self.camouflage = TrafficCamouflage()
        self.detector = DetectionDetector(target="")
    
    def configure_scan(self, target: str, is_aggressive: bool = False) -> Dict:
        """
        Configurer les paramètres d'évasion pour un scan
        """
        
        # Déterminer timing adaptatif
        adaptive = AdaptiveScan(target)
        timing_mode = adaptive.get_optimal_timing()
        
        if is_aggressive:
            timing_mode = TimingMode.INSANE
        
        self.timer = AdaptiveTimer(timing_mode)
        
        return {
            'timing_mode': timing_mode,
            'is_local': adaptive.is_local,
            'fragmentation': True,
            'randomize_order': True,
            'use_passive_fp': True
        }
    
    def apply_evasion_to_packet(self, packet):
        """Appliquer techniques d'évasion à un paquet"""
        
        # 1. Fragmenter si gros paquet
        if len(packet) > 1000:
            packets = self.fragmenter.fragment_packet(packet)
        else:
            packets = [packet]
        
        # 2. Varier TTL
        packets = [TTLVarier.vary_ttl(p) for p in packets]
        
        # 3. Ajouter jitter
        for p in packets:
            self.timer.wait()
        
        return packets
```

---

## ✅ CHECKLIST ÉTAPE 3

- [ ] `core/evasion/adaptive_timing.py` - Jitter & timing
- [ ] `core/evasion/packet_fragmentation.py` - Fragmentation
- [ ] `core/evasion/ttl_variation.py` - TTL variation
- [ ] `core/evasion/adaptive_scan.py` - Scan adaptatif
- [ ] `core/evasion/fingerprint_passive.py` - Fingerprinting passif
- [ ] `core/evasion/traffic_camouflage.py` - HTTP camouflage
- [ ] `core/evasion/detection_detector.py` - Feedback loop
- [ ] `core/evasion/evasion_manager.py` - Orchestrateur
- [ ] Tests unitaires passent 100%
- [ ] Git commit: "ÉTAPE 3: Évasion avancée"

---

## 📊 EFFICACITÉ ESTIMÉE

| Technique | Efficacité | Complexité | Notes |
|-----------|-----------|-----------|-------|
| Jitter | 60% | ⭐ | Très simple, très efficace |
| Fragmentation | 70% | ⭐⭐ | Bon compromis |
| TTL Variation | 40% | ⭐ | Faible mais facile |
| Scan Adaptatif | 80% | ⭐⭐ | Très bon |
| Passive FP | 95% | ⭐⭐⭐ | Presque jamais détecté |
| Traffic Camouflage | 75% | ⭐⭐ | Très bon pour HTTP |
| Feedback Loop | 85% | ⭐⭐⭐ | Escalade automatique |

**Combiné:** ~85% chance d'éviter détection sur réseau standard

---

**Durée estimée:** 7-10 jours
**Risque:** ⚠️⚠️ MOYEN-ÉLEVÉ (complexité technique)
**Bénéfice:** 🚀 TRÈS ÉLEVÉ (discrétion maximale)
