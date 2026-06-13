#function qui parse icmp (sert surtout aux messages de contrôle réseau)
def parse_icmp(icmp_bytes):
  if len(icmp_bytes) < 4:
    print("Erreur, packet ICMP non valide")
    exit(1)

  type_icmp =  icmp_bytes[0] # nature du message ICMP
  code_icmp =  icmp_bytes[1] #détail du message
  checksum_icmp =  int.from_bytes(icmp_bytes[2:4], byteorder="big") #comme tcop et udp contrôle d’intégrité
  identifiant_icmp = None
  sequence = None
  if type_icmp == 0 or type_icmp == 8:
    if len(icmp_bytes) < 8:
      print("Erreur, packet ICMP tronqué")
      exit(1)
    identifiant_icmp = int.from_bytes(icmp_bytes[4:6], byteorder="big")
    sequence = int.from_bytes(icmp_bytes[6:8], byteorder="big")
    payload_icmp =  icmp_bytes[8:]
  else:
    payload_icmp =  icmp_bytes[4:]
  
  return {
    "type_icmp": type_icmp,
    "code": code_icmp,
    "checksum": checksum_icmp,
    "identifiant_icmp": identifiant_icmp,
    "sequence": sequence,
    "payload": payload_icmp
    }