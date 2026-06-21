# PCAP Analyzer — Wireshark-like en raw bytes

## Objectif

Ce projet est un analyseur de fichiers PCAP développé en Python.

Il lit une capture réseau `.pcap` en mode offline et affiche les informations importantes des protocoles rencontrés, couche par couche, à partir des bytes bruts.

L’objectif est de reconstruire manuellement une partie du fonctionnement d’un outil type Wireshark, sans utiliser de librairie spécialisée dans le parsing réseau.

Le programme ne capture pas de trafic en direct. Il analyse uniquement des fichiers PCAP existants.

---

## Contraintes techniques

Le projet respecte les contraintes suivantes :

- Lecture d’un fichier PCAP classique.
- PCAPNG non supporté.
- Parsing manuel des bytes.
- Pas de Scapy.
- Pas de dpkt.
- Pas de pyshark.
- Pas de tshark.
- Pas de tcpdump.
- Pas de libpcap.
- Pas d’outil externe pour décoder les paquets.
- Interface en ligne de commande avec `argparse`.
- Projet dockerisé.

---

## Protocoles supportés

Le parseur supporte les protocoles suivants :

- PCAP Global Header
- PCAP Packet Header
- Ethernet II
- ARP
- IPv4
- IPv6
- TCP
- UDP
- ICMPv4
- DNS
- HTTP/1.1 best effort
- QUIC minimal

---

## Structure du projet

```txt
pcap-analyzer/
├── captures/
│   ├── ethernet_capture.pcap
│   ├── ethernet_capture_small.pcap
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
│   ├── quic.py
│   └── utils.py
├── Dockerfile
├── README.md
└── output.txt
```

---

## Fonctionnement global

Le programme lit le fichier PCAP dans cet ordre :

```txt
PCAP Global Header
→ Packet Header
→ Packet Data
→ Ethernet II
→ ARP / IPv4 / IPv6
→ TCP / UDP / ICMP
→ DNS / HTTP / QUIC
```

Le parsing fonctionne en mode “poupée russe” : chaque couche contient un payload qui est ensuite donné au parseur de la couche suivante.

Exemple :

```txt
Ethernet II
└── IPv4
    └── UDP
        └── DNS
```

Ou :

```txt
Ethernet II
└── IPv4
    └── TCP
        └── HTTP
```

---

## Installation locale

Aucune dépendance externe n’est nécessaire.

Le projet utilise uniquement Python et la bibliothèque standard.

Version recommandée :

```bash
python3 --version
```

Exécution locale :

```bash
python3 src/main.py captures/ethernet_capture_small.pcap
```

---

## Utilisation CLI

### Exécution sans filtre

```bash
python3 src/main.py captures/ethernet_capture_small.pcap
```

Cette commande affiche tous les paquets parsés.

### Exécution avec filtre protocole

```bash
python3 src/main.py captures/ethernet_capture_small.pcap --proto tcp
```

Protocoles disponibles avec `--proto` :

```txt
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

Exemples :

```bash
python3 src/main.py captures/ethernet_capture_small.pcap --proto ethernet
python3 src/main.py captures/ethernet_capture_small.pcap --proto arp
python3 src/main.py captures/ethernet_capture_small.pcap --proto ipv4
python3 src/main.py captures/ethernet_capture_small.pcap --proto ipv6
python3 src/main.py captures/ethernet_capture_small.pcap --proto tcp
python3 src/main.py captures/ethernet_capture_small.pcap --proto udp
python3 src/main.py captures/ethernet_capture_small.pcap --proto icmp
python3 src/main.py captures/ethernet_capture_small.pcap --proto dns
python3 src/main.py captures/ethernet_capture_small.pcap --proto http
python3 src/main.py captures/ethernet_capture_small.pcap --proto quic
```

Le filtre est appliqué après le parsing du paquet.
Si aucun paquet ne correspond au filtre, le compteur affiché indique `0` paquet affiché.

---

## Docker

### Build de l’image

Depuis la racine du projet :

```bash
docker build -t pcap-analyzer .
```

### Exécution sans filtre

```bash
docker run --rm -v "$PWD/captures:/app/captures" pcap-analyzer captures/ethernet_capture_small.pcap
```

### Exécution avec filtre

Commande générique :

```bash
docker run --rm -v "$PWD/captures:/app/captures" pcap-analyzer captures/ethernet_capture_small.pcap --proto <protocole>
```

Exemples :

```bash
docker run --rm -v "$PWD/captures:/app/captures" pcap-analyzer captures/ethernet_capture_small.pcap --proto ipv4
docker run --rm -v "$PWD/captures:/app/captures" pcap-analyzer captures/ethernet_capture_small.pcap --proto ipv6
docker run --rm -v "$PWD/captures:/app/captures" pcap-analyzer captures/ethernet_capture_small.pcap --proto tcp
docker run --rm -v "$PWD/captures:/app/captures" pcap-analyzer captures/ethernet_capture_small.pcap --proto udp
docker run --rm -v "$PWD/captures:/app/captures" pcap-analyzer captures/ethernet_capture_small.pcap --proto dns
docker run --rm -v "$PWD/captures:/app/captures" pcap-analyzer captures/ethernet_capture_small.pcap --proto http
docker run --rm -v "$PWD/captures:/app/captures" pcap-analyzer captures/ethernet_capture_small.pcap --proto quic
```

Le volume Docker :

```bash
-v "$PWD/captures:/app/captures"
```

permet de monter le dossier local `captures/` dans le conteneur à l’emplacement `/app/captures`.

Cela permet au conteneur de lire les fichiers PCAP sans les copier directement dans l’image Docker.

---

## Exemple de sortie

Exemple avec un filtre DNS :

```txt
======Parsing DNS packet n°67======
Transaction ID: 13745
Flags DNS: 33152
Questions count: 1
Responses count: 6
Name Server Count: 0
Additional Record Count: 0
Question name: main.vscode-cdn.net
Question type: 1 - A
Question class: IN
Answer name: main.vscode-cdn.net
Answer type: 5 - CNAME
Answer class: IN
TTL: 300
Response length: 32
RDATA preview: 7673636f64652d63646e...
RDATA decoded: vscode-cdn.z01.azurefd.net
```

Exemple de résumé final :

```txt
======Nombre totale de packets======
Total packets: 150
Total display-packets: 12 / 150
Filter: dns
```

---

## Détails des protocoles

### PCAP

Le parseur lit :

- Magic number
- Endianness
- Version major
- Version minor
- ThisZone
- Sigfigs
- Snaplen
- Network / Linktype

Le programme supporte les fichiers PCAP classiques.

PCAPNG n’est pas supporté.

---

### Ethernet II

Le parseur lit :

- Adresse MAC destination
- Adresse MAC source
- EtherType
- Payload Ethernet

EtherTypes gérés :

```txt
0x0800 → IPv4
0x0806 → ARP
0x86DD → IPv6
```

---

### ARP

Le parseur lit :

- Hardware type
- Protocol type
- Hardware size
- Protocol size
- Operation
- Sender MAC
- Sender IP
- Target MAC
- Target IP

---

### IPv4

Le parseur lit :

- Version
- IHL
- Header length
- Total length
- TTL
- Protocol
- Source IP
- Destination IP
- Flags
- Fragment offset
- Payload

Protocoles IPv4 gérés :

```txt
1  → ICMP
6  → TCP
17 → UDP
```

---

### IPv6

Le parseur lit :

- Version
- Payload length
- Next Header
- Hop limit
- Source IPv6
- Destination IPv6
- Payload
- Final Next Header après extensions
- Extensions détectées

Gestion des extension headers IPv6 :

- Hop-by-Hop Options : saut best effort.
- Routing Header : saut best effort.
- Destination Options : saut best effort.
- Fragment Header : saut fixe de 8 bytes.
- ESP / AH : détectés mais non décodés complètement.
- ICMPv6 : identifié via `next_header = 58`, mais pas parsé en détail.

---

### TCP

Le parseur lit :

- Source port
- Destination port
- Sequence number
- Acknowledgment number
- Header length
- Flags
- Window
- Checksum
- Urgent pointer
- Options
- Payload

Flags TCP gérés :

```txt
FIN
SYN
RST
PSH
ACK
URG
```

---

### UDP

Le parseur lit :

- Source port
- Destination port
- Length
- Checksum
- Payload

UDP est utilisé ensuite pour détecter :

```txt
port 53  → DNS
port 443 → QUIC minimal
```

---

### ICMPv4

Le parseur lit :

- Type
- Code
- Checksum
- Identifier si applicable
- Sequence number si applicable
- Payload

---

### DNS

Le parseur DNS fonctionne sur UDP/53.

Il lit le header DNS :

- Transaction ID
- Flags
- QDCOUNT
- ANCOUNT
- NSCOUNT
- ARCOUNT

Il lit ensuite :

- Question name
- Question type
- Question class
- Answer name
- Answer type
- Answer class
- TTL
- RDLENGTH
- RDATA

Le parseur gère les noms DNS classiques et les noms compressés avec pointeurs.

Types DNS décodés :

```txt
A      → IPv4
AAAA   → IPv6
CNAME  → nom de domaine
```

Autres types détectés ou affichés :

```txt
NS
MX
SVCB
HTTPS
Unknown
```

---

### HTTP/1.1

Le parseur HTTP fonctionne en best effort sur TCP.

Il lit uniquement le HTTP clair, généralement sur le port 80 ou un port local de test.

Il lit :

- Type : request / response
- Method
- Path
- Version
- Status code
- Reason
- Headers
- Body length
- Body preview hex
- Body preview text

Limites HTTP :

- HTTPS/TLS non décodé.
- Pas de réassemblage TCP.
- Les fragments TCP incomplets sont ignorés.
- Le body est affiché en preview uniquement.
- Le body peut contenir du texte, du HTML, du JSON ou du binaire.

---

### QUIC minimal

QUIC est détecté en best effort sur UDP/443.

Le parseur lit :

- First byte
- Payload length
- Header type : long header ou short header
- Version si long header
- DCID length
- DCID hex
- SCID length
- SCID hex

Limites QUIC :

- HTTP/3 n’est pas décodé.
- Le contenu QUIC est chiffré.
- Le parseur affiche uniquement les champs accessibles sans déchiffrement.
- Les paquets short header sont seulement identifiés.

---

## Choix techniques

### Parsing manuel

Le projet utilise volontairement des opérations bas niveau :

```python
int.from_bytes(...)
bytes[start:end]
payload[offset:offset + length]
```

Ce choix permet de comprendre comment les protocoles sont réellement structurés dans les bytes.

### Gestion des offsets

Les protocoles comme DNS et QUIC utilisent des champs de taille variable.

Le programme utilise donc un curseur `offset` pour avancer progressivement dans les données :

```txt
lire un champ
avancer offset
lire le champ suivant
avancer offset
```

Cette logique est utilisée notamment pour :

- DNS QNAME
- DNS RDATA
- DNS compression
- QUIC DCID
- QUIC SCID

### Best effort

Certains protocoles sont volontairement parsés en best effort :

- IPv6 extension headers
- HTTP/1.1
- QUIC
- DNS types avancés

Le but est de produire une analyse lisible sans réimplémenter entièrement Wireshark.

---

## Limites connues

- PCAPNG non supporté.
- Pas de réassemblage TCP.
- Pas de vérification des checksums.
- Pas de décodage TLS/HTTPS.
- Pas de décodage HTTP/2.
- Pas de décodage HTTP/3.
- QUIC uniquement détecté et partiellement lu.
- DNS Authority et Additional non décodés en détail.
- DNSSEC non supporté.
- IPv6 ICMPv6 non parsé en détail.
- Certains paquets fragmentés ou incomplets peuvent être ignorés ou affichés partiellement.

---

## Exemples de tests utiles

Tester tous les paquets :

```bash
python3 src/main.py captures/ethernet_capture_small.pcap
```

Tester uniquement IPv4 :

```bash
python3 src/main.py captures/ethernet_capture_small.pcap --proto ipv4
```

Tester uniquement DNS :

```bash
python3 src/main.py captures/ethernet_capture_small.pcap --proto dns
```

Tester uniquement IPv6 :

```bash
python3 src/main.py captures/ethernet_capture_small.pcap --proto ipv6
```

Tester avec Docker :

```bash
docker run --rm -v "$PWD/captures:/app/captures" pcap-analyzer captures/ethernet_capture_small.pcap --proto dns
```

Tester une capture HTTP locale :

```bash
python3 src/main.py captures/http_local_capture.pcap --proto http
```

---

## Conclusion

Ce projet permet de comprendre la structure interne d’un fichier PCAP et des protocoles réseau courants en analysant directement les bytes.

Il met en pratique :

- la lecture de fichiers binaires ;
- la gestion des offsets ;
- l’encapsulation réseau ;
- le parsing manuel de protocoles ;
- la création d’une CLI ;
- la dockerisation d’un outil Python.

Le résultat est un analyseur PCAP simple, lisible et extensible, proche d’un mini Wireshark en ligne de commande.
