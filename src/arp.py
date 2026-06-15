from utils import (format_ipv4, format_mac)
#function pour parser ARP (arp sert a faire la liaison entre IP et MAC)
def parse_arp(arp_bytes):
  if len(arp_bytes) < 28:
    print("Erreur, packet ARP non valide")
    exit(1)
  
  hardware_type = int.from_bytes(arp_bytes[0:2], byteorder="big")
  protocol_type = int.from_bytes(arp_bytes[2:4], byteorder="big")
  hardware_size = arp_bytes[4]
  protocol_size = arp_bytes[5]
  operation = int.from_bytes(arp_bytes[6:8], byteorder="big")
  sender_mac = format_mac(arp_bytes[8:14])
  sender_ip = format_ipv4(arp_bytes[14:18])
  target_mac = format_mac(arp_bytes[18:24])
  target_ip = format_ipv4(arp_bytes[24:28])
  
  return {
    "hardware_type": hardware_type,
    "protocol_type": protocol_type,
    "hardware_size": hardware_size,
    "protocol_size": protocol_size,
    "operation": operation,
    "sender_mac": sender_mac,
    "sender_ip": sender_ip,
    "target_mac": target_mac,
    "target_ip": target_ip
  }