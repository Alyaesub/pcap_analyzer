# PCAP Analyzer — Wireshark-like en raw bytes

## Objectif

Ce projet consiste à développer un analyseur de fichiers PCAP capable de lire une capture réseau et d’afficher les informations importantes des protocoles rencontrés.

Le programme fonctionne en analyse offline : il ne capture pas le trafic en direct, il lit uniquement un fichier `.pcap`.

L’objectif est de reconstruire les couches réseau à partir des bytes bruts, sans utiliser de bibliothèque spécialisée dans le parsing PCAP ou réseau.

## Contraintes principales

- Lecture d’un fichier PCAP classique uniquement.
- PCAPNG non supporté.
- Parsing manuel des bytes.
- Pas d’utilisation de bibliothèques comme Scapy, dpkt, pyshark, tshark ou libpcap.
- Pas d’appel à un outil externe comme tcpdump ou tshark.
- Interface en ligne de commande.
- Projet dockerisé.

## Protocoles à supporter

Protocoles obligatoires prévus dans l’énoncé :

- PCAP
- Ethernet II
- ARP
- IPv4
- IPv6
- TCP
- UDP
- ICMP
- DNS
- HTTP/1.1
- QUIC minimal

## Utilisation prévue

Exécution sans filtre :

```bash
analyzer capture.pcap
```

Exécution avec filtre protocole :

```bash
analyzer capture.pcap --proto tcp
analyzer capture.pcap --proto dns
analyzer capture.pcap --proto http
analyzer capture.pcap --proto quic
```

## Structure prévue du projet

```txt
pcap-analyzer/
├── captures/
│   └── http_local_capture.pcap
├── src/
│   ├── main.py
│   ├── pcap_parser.py
│   ├── ethernet.py
│   ├── ipv4.py
│   ├── ipv6.py
│   ├── arp.py
│   ├── tcp.py
│   ├── udp.py
│   ├── icmp.py
│   ├── dns.py
│   ├── http.py
│   └── quic.py
├── tests/
├── Dockerfile
└── README.md
```

IPv6 extension headers:

- Hop-by-Hop, Routing, Destination Options: saut best effort
- Fragment Header: saut taille fixe 8 bytes
- ESP/AH: détectés mais non décodés complètement
- ICMPv6: identifié via next_header 58, parsing détaillé non implémenté

HTTP:

- parsing best effort sur trafic HTTP clair uniquement
- HTTPS/TLS non décodé
- pas de réassemblage TCP
- les fragments TCP incomplets sont ignorés
- body affiché en preview uniquement

QUIC :

- QUIC est détecté de manière best effort sur UDP/443.
- Le contenu HTTP/3 n’est pas décodé car QUIC est chiffré.
- Le parseur affiche seulement les champs accessibles sans déchiffrement.
