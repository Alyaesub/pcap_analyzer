#function qui parse UDP
def parse_udp(udp_bytes):
  if len(udp_bytes) < 8:
    print("Erreur, packet UDP non valide")
    exit(1)
  
  src_port = int.from_bytes(udp_bytes[0:2], byteorder="big")
  dst_port = int.from_bytes(udp_bytes[2:4], byteorder="big")
  length = int.from_bytes(udp_bytes[4:6], byteorder="big") # header UDP + payload UDP 
  if length < 8:
    print("Erreur, header UDP tronqué ou invalide")
    exit(1)
  checksum = int.from_bytes(udp_bytes[6:8], byteorder="big")
  if len(udp_bytes) < length:
    print("Erreur, packet tronqué ou invalide")
    exit(1)
  payload = udp_bytes[8:length]
  
  return {
    "src_port": src_port,
    "dst_port": dst_port,
    "length": length,
    "checksum": checksum,
    "payload": payload
  }