from utils import (format_ipv4)

# function qui parse le payload de ethernet et return les data de ipv4
def parse_ipv4(ipv4_bytes):
  if len(ipv4_bytes) < 20:
    print("Erreur, trame IPv4 non valide")
    exit(1)
  
  first_byte = ipv4_bytes[0]
  version = first_byte >> 4 #récupère les 4 bits de gauche
  if version != 4:
    return "Erreur IPv4"
  ihl = first_byte & 0X0F # récupère les 4 bits de droite
  if ihl < 5:
    return "Erreur ihl"
  header_length = ihl * 4 # recupére le length du header
  if len(ipv4_bytes) < header_length:
    return "Packet IPv4 tronqué"
  
  total_length_byte = ipv4_bytes[2:4]
  ttl_byte = ipv4_bytes[8] #Time To Live décremente a chaque routeur
  protocol_byte = ipv4_bytes[9]
  src_ip_byte = ipv4_bytes[12:16]
  dst_ip_byte = ipv4_bytes[16:20]
  payload_byte = ipv4_bytes[header_length:]
  
  total_length_number = int.from_bytes(total_length_byte, byteorder="big")
  src_ip_number = format_ipv4(src_ip_byte)
  dst_ip_number = format_ipv4(dst_ip_byte)
  flags_fragment = int.from_bytes(ipv4_bytes[6:8], byteorder="big") # fragment = morceau du packet si il est couper
  flags = flags_fragment >> 13 # dit si le paquet peut être fragmenté ou s’il y a d’autres fragments
  fragment_offset = flags_fragment & 0x1FFF #dit où ce fragment se place dans le paquet original
  
  return {
    "version": version,
    "ihl": ihl,
    "header_length": header_length,
    "total_length": total_length_number,
    "ttl": ttl_byte,
    "protocol": protocol_byte,
    "src_ip": src_ip_number,
    "dst_ip": dst_ip_number,
    "payload": payload_byte,
    "flags": flags,
    "fragment_offset": fragment_offset
  }

############### function qui verifie et traduit le numéoro du protocole ###########
def get_ipv4_protocol_name(protocol):
  if protocol == 1:
    return "1 - ICMP"
  elif protocol == 6:
    return "6 - TCP"
  elif protocol == 17:
    return "17 - UDP"
  else:
    return "Protocol non supporté"