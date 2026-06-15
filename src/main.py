import os

#import des function pour les parser
import ipv6
from pcap_parser import (
  parse_global_header,
  parse_packet_header,
  read_exact,
  read_packet_header_or_none,
  get_linktype_name
)
from ethernet import (
  parse_ethernet,
  get_ethertype_name,
)
from ipv4 import (
  parse_ipv4,
  get_ipv4_protocol_name
)
from tcp import (
  parse_tcp,
  get_tcp_flags_names,
)
from udp import (
  parse_udp,
)
from icmp import (
  parse_icmp,
)
from arp import (
  parse_arp,
)
from ipv6 import (
  parse_ipv6,
  get_ipv6_protocol_name,
)

#pathe de la ressource a analiser
RESSOURCE_PATH = "captures/ethernet_capture_small.pcap"

############## Gestion et lecture des fichier source ##############

#verifie si le fichier existe 
if not os.path.isfile(RESSOURCE_PATH):
  print("fichier introuvable")
  exit(1)

#ouvre et lie le fichier en bytes
with open(RESSOURCE_PATH, 'rb') as f:
  # Global header
  global_header_byte = read_exact(f, 24) # lie les 24 byte du global header
  # Appele de la function qui parse le global header
  global_header = parse_global_header(global_header_byte)
  #variable qui stock le linktype (network 0 ou 1)
  linktype_name = get_linktype_name(global_header["network"])
  # print les byte du global header
  print("======Global-Header-Bytes======")
  print(global_header_byte)
  print()
  
  # variable qui stocke les packet pour boucler sur tous les packet
  packet_index = 1
  
  # boucle pour parcourire tous les packet du pcap
  while True:
    # Packet header
    packet_header_byte = read_packet_header_or_none(f) # lie les 16 byte du packet header et verifie si il est valide

    if packet_header_byte is None: # si fin des packet dans pcap on break
      break
    
    # Appele de la function qui parse le packet header
    packet_header = parse_packet_header(packet_header_byte, global_header["endianness"])
    # Packet data : contenu brut du paquet
    packet_data_byte = read_exact(f, packet_header["incl_len"])
    
    ######################### Gestion Ethernet, IPv4, tcp, etc, en mode poupée russe #####################
    ethernet = None # de base lecture sans ethernet si ethernet existe alors :
    ethertype_name = None #pareil pour ethertype
    ipv4 = None
    tcp = None
    flags_names = None
    udp = None
    icmp = None
    arp = None
    ipv6 = None
    
    if global_header["network"]  == 1: # verifie le network
      # appele la function qui parse le packet Ethernet
      ethernet = parse_ethernet(packet_data_byte)
      ethertype_name = get_ethertype_name(ethernet["ethertype"]) # function qui donne le nom du type prorpe
      if ethernet["ethertype"] == 0x0800: # if ethertype == ipv4
        ipv4 = parse_ipv4(ethernet["payload"])
        protocol_name_ipv4 = get_ipv4_protocol_name(ipv4["protocol"])
        if ipv4["protocol"] == 6:
          tcp = parse_tcp(ipv4["payload"])
          flags_names = get_tcp_flags_names(tcp["flags"])
        elif ipv4["protocol"] == 17:
          udp = parse_udp(ipv4["payload"])
        elif ipv4["protocol"] == 1:
          icmp = parse_icmp(ipv4["payload"])
      elif ethernet["ethertype"] == 0x0806: # if ethertype == ARP
        arp = parse_arp(ethernet["payload"])
      elif ethernet["ethertype"] == 0x86DD:  # if ethertype == IPV6
        ipv6 = parse_ipv6(ethernet["payload"])
        protocol_name_ipv6 = get_ipv6_protocol_name(ipv6["next_header"])

    ##################### Parsing des Packet #####################
    # print les infos du packet header
    print(f"===================Parsing Packet n°{packet_index}===================")
    print("Timestamp seconds: ", packet_header["ts_sec"])
    print("Timestamp microseconds: ", packet_header["ts_usec"])
    print("Included length: ", packet_header["incl_len"])
    print("Original length: ", packet_header["orig_len"])
    # print les data du packet
    print(f"======Packet Data packet n°{packet_index}======")
    print("Packet data length: ", len(packet_data_byte))
    print("Packet data preview (32 bytes): ", packet_data_byte[:32].hex())
    #print les data ethernet
    if ethernet is not None:
      print(f"======Parsing Ethernet packet n°{packet_index}======")
      print("Adresse MAC de destination:", ethernet["dst_mac"])
      print("Adresse MAC d'éxpédition:", ethernet["src_mac"])
      print("Ethernet Type:", ethertype_name)
      print()
      #print le header IPv4
    if ipv4 is not None:
      print(f"======Parsing IPv4 packet n°{packet_index}======")
      print("Version:", ipv4["version"])
      print("IHL:", ipv4["ihl"])
      print("Header length:", ipv4["header_length"])
      print("Total length:", ipv4["total_length"])
      print("TTL:", ipv4["ttl"])
      print("Protocol:", protocol_name_ipv4)
      print("Source IP:", ipv4["src_ip"])
      print("Destination IP:", ipv4["dst_ip"])
      print("Flags:", ipv4["flags"])
      print("Fragment offset:", ipv4["fragment_offset"])
      print()
    if tcp is not None:
      print(f"======Parsing TCP packet n°{packet_index}======")
      print("Source port:", tcp["src_port"])
      print("Destination port:", tcp["dst_port"])
      print("Sequence number:", tcp["sequence_number"])
      print("Acknowledgment number:", tcp["acknowledgment_number"])
      print("Header length:", tcp["header_length"])
      print("Window:", tcp["window"])
      print("Flags:", flags_names)
      print("Checksum:", tcp["checksum"])
      print("Urgent pointer:", tcp["urgent_pointer"])
      print("Options length:", len(tcp["options"]))
      print("Payload length:", len(tcp["payload"]))
      print("Payload preview:", tcp["payload"][:32].hex())
      print()
    if udp is not None:
      print(f"======Parsing UDP packet n°{packet_index}======")
      print("Source port:", udp["src_port"])
      print("Destination port:", udp["dst_port"])
      print("Length:", udp["length"])
      print("Checksum:", udp["checksum"])
      print("Payload preview:", udp["payload"][:32].hex())
      print()
    if icmp is not None:
      print(f"======Parsing ICMP packet n°{packet_index}======")
      print("Type ICMP:", icmp["type_icmp"])
      print("Code ICMP:", icmp["code"])
      print("Checksum ICMP:", icmp["checksum"])
      print("Identifiant ICMP:", icmp["identifiant_icmp"])
      print("Numéro de séquence ICMP:", icmp["sequence"])
      print("Payload preview:", icmp["payload"][:32].hex())
      print()
    if arp is not None:
      print(f"======Parsing ARP packet n°{packet_index}======")
      print("Hardware:", arp["hardware_type"])
      print("Protocol:", arp["protocol_type"])
      print("Hardware Size:", arp["hardware_size"])
      print("Protocol Size:", arp["protocol_size"])
      print("Operation:", arp["operation"])
      print("Sender MAC:", arp["sender_mac"])
      print("Sender IP:", arp["sender_ip"])
      print("Target MAC:", arp["target_mac"])
      print("Target IP:", arp["target_ip"])
      print()
    if ipv6 is not None:
      print(f"======Parsing IPV6 packet n°{packet_index}======")
      print("Version:", ipv6["version"])
      print("Payload length:", ipv6["payload_length"])
      print("Next Header:", protocol_name_ipv6)
      print("Hop limite:", ipv6["hop_limit"])
      print("Source IP:", ipv6["src_ipv6"])
      print("Destination IP:", ipv6["dst_ipv6"])
      print("Final Header:", ipv6["final_next_header"])
      print("Extensions:", ipv6["extensions_headers"])
      print("Payload preview:", ipv6["payload"][:32].hex())
      print()
    # incrémente l'index
    packet_index += 1


######## fin du with et lecture fermé ################
####### print du nombre de packet ####
print("======Nombre totale de packets======")
print("Total packets:", packet_index - 1)
print()

######################## parsing du global header #########################
# print les infos du global header
print("======Global Header Parsing======")
print("Magic Number hexa:", global_header["magic_number"])
print("Endianness:", global_header["endianness"])
print(f"Version: {global_header['version_major']}.{global_header['version_minor']}")
print("ThisZone:", global_header["thiszone"])
print("Sigfigs:", global_header["sigfigs"])
print("Snaplen:", global_header["snaplen"])
print("Network / Linktype:", global_header["network"], "-", linktype_name)
print()