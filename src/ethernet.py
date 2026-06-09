from utils import (
  format_mac,
)

# function qui parse le packet_data_byte pour recupéle le byte ethernet
def parse_ethernet(packet_data_byte ):
  if len(packet_data_byte ) < 14:
    return "Erreur trame Ethernet non valide" + exit(1)
  
  dst_mac_byte = packet_data_byte[0:6] # adress mac de destination
  src_mac_byte = packet_data_byte[6:12] # mac de la source
  ethertype_byte = packet_data_byte[12:14] #type de connexion
  payload = packet_data_byte[14:] # payload
  
  dst_mac_number = format_mac(dst_mac_byte)
  src_mac_number = format_mac(src_mac_byte)
  ethertype_number = int.from_bytes(ethertype_byte, byteorder="big")
  
  return {
    "dst_mac": dst_mac_number,
    "src_mac": src_mac_number,
    "ethertype": ethertype_number,
    "payload": payload
  }

############## function qui verifie et traduit le ethertype ###########
def get_ethertype_name(ethertype):
  if ethertype == 2048:
    return "0x0800 - IPv4"
  elif ethertype == 34525:
    return "0x86DD - IPv6"
  elif ethertype == 2054:
    return "0x0806 - ARP"
  else:
    return "Ethertype non supporté"