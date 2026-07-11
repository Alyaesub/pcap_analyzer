# PCAP Analyzer — Wireshark-like en raw bytes

# PCAP Analyzer

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Version](https://img.shields.io/badge/version-1.0-success)
![License](https://img.shields.io/badge/license-MIT-green)

PCAP Analyzer est un outil CLI Python permettant d'analyser des captures réseau **PCAP** en mode hors ligne.

Il reconstruit manuellement les différentes couches réseau (Ethernet, IP, TCP, UDP, DNS, HTTP...) directement à partir des bytes du fichier, sans utiliser de bibliothèque spécialisée comme Scapy, PyShark ou dpkt.

Le projet a été développé dans un objectif pédagogique afin de comprendre le fonctionnement des protocoles réseau et le principe de fonctionnement d'un analyseur comme Wireshark.

---

## Fonctionnalités

- Lecture de fichiers `.pcap`
- Parsing manuel des bytes
- Support du format PCAP classique
- Décodage Ethernet II
- Décodage ARP
- Décodage IPv4
- Décodage IPv6
- Décodage TCP
- Décodage UDP
- Décodage ICMPv4
- Parsing DNS
- Parsing HTTP/1.1 (best effort)
- Détection minimale de QUIC
- Filtrage des paquets par protocole
- Interface en ligne de commande avec `argparse`
- Dockerisation complète du projet

---

## Contraintes techniques

Le projet est volontairement développé **sans bibliothèque de parsing réseau**.

Aucune utilisation de :

- Scapy
- dpkt
- PyShark
- tshark
- tcpdump
- libpcap

Tout le décodage est réalisé directement à partir des bytes du fichier PCAP.

---

## Structure du projet

```text
pcap-analyzer/
├── captures/
│   ├── ethernet_capture.pcap
│   ├── ethernet_capture_small.pcap
│   └── http_local_capture.pcap
├── src/
│   ├── main.py
│   ├── pcap_parser.py
│   ├── ethernet.py
│   ├── arp.py
│   ├── ipv4.py
│   ├── ipv6.py
│   ├── tcp.py
│   ├── udp.py
│   ├── icmp.py
│   ├── dns.py
│   ├── http.py
│   ├── quic.py
│   └── utils.py
├── Dockerfile
├── .gitignore
├── LICENSE
├── README.md
└── requirements.txt
```

### Modules

- `main.py` : point d'entrée et orchestration du programme
- `pcap_parser.py` : lecture du fichier PCAP et parcours des paquets
- `ethernet.py` : décodage Ethernet II
- `arp.py` : décodage ARP
- `ipv4.py` : décodage IPv4
- `ipv6.py` : décodage IPv6
- `tcp.py` : décodage TCP
- `udp.py` : décodage UDP
- `icmp.py` : décodage ICMPv4
- `dns.py` : analyse des paquets DNS
- `http.py` : analyse HTTP/1.1
- `quic.py` : analyse QUIC (best effort)
- `utils.py` : fonctions utilitaires

---

## Installation

### 1. Cloner le dépôt

```bash
git clone <URL_DU_DEPOT>
cd pcap-analyzer
```

### 2. Créer un environnement virtuel

```bash
python3.12 -m venv .venv
```

### 3. Activer l'environnement

Sur macOS ou Linux :

```bash
source .venv/bin/activate
```

Sur Windows PowerShell :

```powershell
.venv\Scripts\Activate.ps1
```

### 4. Installer les dépendances

```bash
python -m pip install -r requirements.txt
```

---

## Utilisation

Depuis la racine du projet :

```bash
python src/main.py captures/ethernet_capture_small.pcap
```

Avec un filtre protocole :

```bash
python src/main.py captures/ethernet_capture_small.pcap --proto dns
```

---

## Arguments CLI

| Argument       | Obligatoire | Description                                    |
| -------------- | ----------: | ---------------------------------------------- |
| `capture`      |         Oui | Fichier PCAP à analyser                        |
| `--proto`      |         Non | Filtre l'affichage sur un protocole spécifique |
| `-h`, `--help` |         Non | Affiche l'aide générée par `argparse`          |

Protocoles disponibles :

```text
pcap
ethernet
arp
ipv4
ipv6
tcp
udp
icmp
dns
http
quic
```

Afficher l'aide :

```bash
python src/main.py --help
```

---

## Exemple de sortie

```text
====== Parsing DNS packet ======

Transaction ID : 13745

Question :
main.vscode-cdn.net

Réponse :
vscode-cdn.z01.azurefd.net

TTL : 300

Type : CNAME
```

Résumé :

```text
====== Parsing Summary ======

Total packets : 150

Displayed packets : 12

Protocol filter : dns
```

---

## Docker

### Construction de l'image

```bash
docker build -t pcap-analyzer .
```

### Exécution

```bash
docker run --rm \
-v "$PWD/captures:/app/captures" \
pcap-analyzer \
captures/ethernet_capture_small.pcap
```

Avec un filtre :

```bash
docker run --rm \
-v "$PWD/captures:/app/captures" \
pcap-analyzer \
captures/ethernet_capture_small.pcap \
--proto dns
```

---

## Fonctionnement

Le fichier PCAP est analysé couche par couche.

```text
PCAP Global Header

↓

Packet Header

↓

Ethernet II

↓

ARP / IPv4 / IPv6

↓

TCP / UDP / ICMP

↓

DNS / HTTP / QUIC
```

Chaque parseur décode uniquement son protocole puis transmet le **payload** au parseur de la couche suivante.

Cette architecture reproduit le fonctionnement d'un analyseur réseau classique.

---

## Protocoles supportés

### Couche Liaison

- Ethernet II
- ARP

### Couche Réseau

- IPv4
- IPv6

### Couche Transport

- TCP
- UDP
- ICMPv4

### Couche Application

- DNS
- HTTP/1.1 (best effort)
- QUIC (best effort)

---

## Détails des protocoles

### PCAP

Informations analysées :

- Magic Number
- Endianness
- Version
- Snaplen
- Linktype

### Ethernet II

- MAC Source
- MAC Destination
- EtherType

### ARP

- Hardware Type
- Protocol Type
- Sender MAC
- Sender IP
- Target MAC
- Target IP

### IPv4

- Version
- IHL
- Total Length
- TTL
- Protocol
- Source IP
- Destination IP
- Flags
- Fragment Offset

### IPv6

- Version
- Payload Length
- Next Header
- Hop Limit
- Source IPv6
- Destination IPv6

### TCP

- Source Port
- Destination Port
- Sequence Number
- Acknowledgment Number
- Flags
- Window
- Checksum
- Payload

### UDP

- Source Port
- Destination Port
- Length
- Checksum
- Payload

### ICMPv4

- Type
- Code
- Checksum
- Identifier
- Sequence Number

### DNS

Le parseur DNS décode :

- Header
- Questions
- Réponses
- Noms compressés
- Types A, AAAA et CNAME

### HTTP

Le parseur HTTP fonctionne en **best effort**.

Il décode :

- Request / Response
- Method
- URI
- Version
- Status Code
- Headers
- Body Preview

### QUIC

Détection minimale :

- Long Header
- Short Header
- Version
- DCID
- SCID

---

## Limites de la version 1.0

- PCAPNG non supporté.
- Pas de réassemblage TCP.
- Pas de vérification des checksums.
- HTTPS / TLS non décodé.
- HTTP/2 non supporté.
- HTTP/3 non supporté.
- QUIC analysé en best effort.
- DNSSEC non supporté.
- ICMPv6 non implémenté.
- Certains paquets fragmentés peuvent être affichés partiellement.

---

## Roadmap

### Version 1.1

- [ ] Ajouter le support ICMPv6
- [ ] Vérification des checksums
- [ ] Améliorer le parser HTTP
- [ ] Améliorer la robustesse du parser
- [ ] Ajouter des tests unitaires
- [ ] Refactoriser les parseurs réseau

### Version 1.2

- [ ] Support PCAPNG
- [ ] Réassemblage TCP
- [ ] Support HTTP/2
- [ ] Décodage complet des sections DNS Authority et Additional
- [ ] Export JSON
- [ ] Export CSV

### Version 2.0

- [ ] Parser TLS
- [ ] Parser HTTP/3
- [ ] Parser QUIC avancé
- [ ] Architecture par plugins
- [ ] API REST
- [ ] Interface Web
- [ ] Docker Compose
- [ ] Analyse statistique des captures

---

## Sécurité et usage responsable

PCAP Analyzer est un projet pédagogique.

Il analyse uniquement des captures réseau existantes.

Le projet ne réalise **aucune capture de trafic en direct** et ne remplace pas un analyseur réseau professionnel comme Wireshark.

Son objectif est de comprendre :

- la structure d'un fichier PCAP
- l'encapsulation des protocoles réseau
- le parsing manuel de données binaires
- le fonctionnement interne des protocoles réseau

---

## Contributions

Les retours, propositions et contributions sont les bienvenus.

Les améliorations peuvent être proposées avec :

- une Issue GitHub
- une Pull Request
- une proposition de nouvelle fonctionnalité

---

## Licence

Ce projet est distribué sous licence MIT.

Consultez le fichier `LICENSE` pour plus d'informations.
