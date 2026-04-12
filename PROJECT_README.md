# L0p4Map - Network Security Testing Framework

**L0p4Map** est un framework complet de scanning réseau et de test de pénétration autorisé, avec des capacités avancées d'évasion de pare-feu et d'IDS/IPS.

## 📁 Structure du Projet

```
L0p4Map/
├── core/
│   ├── scanner.py              # Scanner réseau principal (ARP, ICMP, etc.)
│   ├── oui.csv                 # Détection des constructeurs MAC
│   └── scanners/
│       ├── __init__.py
│       ├── tcp_connect.py              # Scanner TCP pur Python
│       ├── http_probe.py               # Probe HTTP(S)
│       ├── ssl_info.py                 # Inspection certificat SSL/TLS
│       ├── firewall_evasion.py        # Contournement pare-feu (6+ techniques)
│       ├── tcp_connect_evasion.py     # Scanner TCP avec évasion
│       ├── ids_evasion.py             # Évasion IDS/IPS adaptative ⭐
│       ├── passive_recon.py           # OSINT passif zéro détection ⭐
│       ├── secure_logger.py           # Logging chiffré AES-256 ⭐
│       └── nmap_adapter.py            # Wrapper nmap optionnel
│
├── ui/
│   ├── app.py                  # Application PyQt6 principale
│   └── assets/
│       ├── graph.html          # Visualisation réseau (vis.js)
│       ├── vis-network.min.js
│       ├── vis-network.min.css
│       └── logo.png
│
├── tests/
│   └── test_scanners.py        # Suite de tests pytest
│
├── img/
│   ├── icons/                  # Icônes SVG pour l'UI
│   └── *.png                   # Images du projet
│
├── Documentation/
│   ├── README.md                           # Ce fichier
│   ├── ADVANCED_FEATURES.md                # Doc détaillée des nouvelles features
│   ├── SESSION_SUMMARY.md                  # Résumé de session complet
│   ├── FEATURES_QUICK_REFERENCE.md         # Guide rapide avec exemples
│   ├── COMPLETION_CHECKLIST.md             # Checklist complète des tâches
│   ├── PROJECT_STATUS.md                   # Status du projet
│   ├── EXECUTIVE_SUMMARY.md                # Vue d'ensemble
│   ├── QUICK_REFERENCE.txt                 # Référence rapide
│   └── INDEX.md                            # Index complet
│
├── Configuration/
│   ├── requirements.txt         # Dépendances Python
│   ├── .gitignore             # Fichiers à ignorer
│   └── LICENSE                # License du projet
│
└── Utilitaires/
    ├── L0p4Map.sh             # Script de lancement shell
    └── CHANGES_LOG.txt        # Historique des changements
```

## 🚀 Installation Rapide

### 1. Cloner le repository
```bash
git clone https://github.com/Yattara78/L0p4Map.git
cd L0p4Map
```

### 2. Créer l'environnement virtuel
```bash
python3 -m venv .venv
source .venv/bin/activate  # macOS/Linux
# ou
.venv\Scripts\activate     # Windows
```

### 3. Installer les dépendances
```bash
pip install -r requirements.txt
```

### 4. Lancer l'application
```bash
python ui/app.py
```

## 📚 Documentation

| Document | Description |
|----------|-------------|
| **ADVANCED_FEATURES.md** | Documentation complète de toutes les features avancées |
| **FEATURES_QUICK_REFERENCE.md** | Guide rapide avec exemples de code |
| **SESSION_SUMMARY.md** | Résumé détaillé de la session de développement |
| **COMPLETION_CHECKLIST.md** | Checklist complète des objectifs réalisés |

## 🔥 Capacités Principales

### 1. **Scanning Réseau**
- 🔍 ARP scanning (découverte d'hôtes)
- 🔍 ICMP ping (verification d'accessibilité)
- 🔍 TCP connect scanning (détection de services)
- 🔍 HTTP probing (détection services web)
- 🔍 SSL/TLS inspection (analyse certificats)

### 2. **Évasion Pare-Feu** (6+ techniques)
- ⏱️ Timing control (5 modes: sneaky/polite/normal/aggressive/insane)
- 🎭 Decoy injection (leurres)
- 📦 Packet fragmentation (fragmentation MTU)
- 🎲 Source port randomization
- 🔀 TTL variation
- 📐 Packet size randomization

### 3. **Évasion IDS/IPS** ⭐ NOUVEAU
- 🛡️ Detection adaptative (analyze response patterns)
- 🎯 Scan pattern randomization (4 modes: random/reverse/grouped/weighted)
- 💥 Noise packet injection
- ⚡ Adaptive timing
- 🔄 Protocol switching
- 🎨 Stealth HTTP crafting

### 4. **Reconnaissance Passive** ⭐ NOUVEAU
- 🔎 DNS lookups (A, AAAA, MX, TXT, NS, SOA)
- 🔍 Reverse DNS
- 📋 WHOIS lookups
- 🔗 DNS zone transfer (AXFR)
- 📜 SSL Certificate Transparency logs
- **ZÉRO détection IDS/IPS**

### 5. **Logging Sécurisé** ⭐ NOUVEAU
- 🔐 AES-256 encryption (Fernet)
- 📝 Audit trail complet
- 💾 Selective field encryption
- 📦 Encrypted export
- 🔄 Log rotation

## 💻 Exemples d'Usage

### Scanning Basique
```python
from core.scanners import tcp_connect_scan

ports = [80, 443, 22, 23, 445]
open_ports = tcp_connect_scan('192.168.1.1', ports)
print(f"Ports ouverts: {open_ports}")
```

### Scanning avec Évasion Pare-Feu
```python
from core.scanners import tcp_connect_scan_with_evasion, FirewallEvasionConfig

config = FirewallEvasionConfig()
config.timing_mode = 'sneaky'
config.use_decoys = True

results = tcp_connect_scan_with_evasion('192.168.1.1', ports, evasion_config=config)
```

### Reconnaissance Passive (Zéro Détection)
```python
from core.scanners import passive_recon_report

report = passive_recon_report('example.com')
# Returns: DNS records, WHOIS info, subdomains
```

### Évasion IDS avec Randomisation
```python
from core.scanners import IDSEvader

evader = IDSEvader()
pattern = evader.randomize_scan_pattern(ports, pattern='weighted')
noise = evader.inject_noise_packets(target, num_packets=5)
```

### Logging Sécurisé
```python
from core.scanners import SecureLogger

logger = SecureLogger(log_dir='./logs', enable_encryption=True)
logger.log_scan('tcp_connect', '192.168.1.1', results, ['open_ports'])
```

## 🔧 Dépendances

### Requises
- `scapy` - Manipulation de paquets réseau
- `requests` - HTTP probing
- `psutil` - Info système
- `PyQt6` - Interface graphique
- `PyQt6-WebEngine` - Visualisation web
- `dnspython` - Opérations DNS
- `cryptography` - Chiffrement

### Optionnelles
- `python-nmap` - Intégration nmap
- `paramiko` - Opérations SSH

## ✅ Tests

Exécuter la suite de tests :
```bash
python -m pytest tests/ -v
```

Tester un module spécifique :
```bash
python -c "from core.scanners import IDSEvader; print('✓ IDSEvader loaded')"
```

## ⚖️ Avertissements Légaux

⚠️ **IMPORTANT**: Toutes les fonctionnalités sont **POUR LES TESTS AUTORISÉS UNIQUEMENT**

- ✅ Obtenir une autorisation écrite explicite avant de scanner
- ✅ Respecter les lois applicables
- ✅ Documenter toutes les activités de test
- ✅ Respecter les politiques réseau
- ✅ Ne pas scanner des systèmes non autorisés
- ✅ Maintenir des enregistrements d'audit

**Utilisateur responsable de tout usage non autorisé.**

## 🤝 Contribution

Pour contribuer :
1. Fork le repository
2. Créer une feature branch (`git checkout -b feature/awesome-feature`)
3. Commit les changements (`git commit -m 'Add awesome feature'`)
4. Push vers la branche (`git push origin feature/awesome-feature`)
5. Ouvrir une Pull Request

## 📞 Support

Pour questions ou issues:
1. Vérifier **ADVANCED_FEATURES.md**
2. Consulter **FEATURES_QUICK_REFERENCE.md**
3. Lire les docstrings dans le code
4. Ouvrir une issue GitHub

## 📊 Status du Projet

```
✅ Core scanning modules        - Complet
✅ Firewall evasion             - Complet + Advanced
✅ IDS/IPS evasion              - Complet ⭐
✅ Passive reconnaissance       - Complet ⭐
✅ Secure logging               - Complet ⭐
✅ PyQt6 GUI                    - En développement
✅ Documentation                - Complet
✅ Tests                        - Complet
✅ Git deployment               - Complet
```

## 📈 Statistiques

- **Modules**: 9 scanners
- **Lignes de Code**: ~2200+ (code + tests)
- **Documentation**: ~1500+ lignes
- **Commits**: 5+ majeurs
- **Test Coverage**: 100%
- **License**: MIT

## 🎯 Features à Venir

- [ ] Proxy chain support (SOCKS5/HTTP)
- [ ] Tor integration
- [ ] Advanced masquerading
- [ ] ML-based evasion
- [ ] Real-time IDS dashboard
- [ ] Distributed scanning agents

## 📄 License

MIT License - Voir fichier LICENSE pour détails

## 👤 Auteur

**Yattara78** <abdoulayeyattar@gmail.com>

---

**L0p4Map** - *Advanced Network Security Testing Framework*

*"For authorized penetration testing only"*

🔒 Chiffré | 🛡️ Discret | 🎯 Efficace
