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

## Première capture de test

Pour commencer, une première capture locale est réalisée avec Wireshark sur macOS.

Contexte de capture :

- serveur HTTP Python lancé en local ;
- client HTTP Python lancé en local ;
- interface Wireshark utilisée : `lo0` ;
- trafic capturé : requête HTTP locale vers le serveur ;
- export demandé : format PCAP classique, pas PCAPNG.

Cette première capture sert surtout à comprendre :

- la structure globale d’une capture ;
- les paquets TCP ;
- une requête HTTP ;
- une réponse HTTP ;
- les données applicatives visibles en bytes.

Limite connue de cette première capture :

- comme elle est faite sur `lo0`, elle peut ne pas utiliser le linktype Ethernet attendu pour le rendu final.

Une capture complémentaire avec linktype Ethernet devra être réalisée plus tard pour valider le parsing Ethernet II, ARP, IPv4, IPv6 et les autres protocoles demandés.

## Limites actuelles

Le projet est en cours de développement.

À ce stade :

- le parseur PCAP n’est pas encore implémenté ;
- les protocoles ne sont pas encore décodés ;
- la capture locale HTTP sert uniquement de fichier de test initial.

## Notes de développement

Le développement se fera progressivement :

1. Lecture du Global Header PCAP.
2. Lecture des Packet Records.
3. Affichage des timestamps et tailles des paquets.
4. Parsing Ethernet II.
5. Parsing IPv4 / IPv6 / ARP.
6. Parsing TCP / UDP / ICMP.
7. Parsing HTTP / DNS / QUIC.
8. Ajout du filtre `--proto`.
9. Dockerisation.
10. Documentation finale avec exemples de sortie.
