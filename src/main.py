import os
##argparse et commande CLI
import argparse

parser = argparse.ArgumentParser(description="Analyseur PCAP en raw bytes")
parser.add_argument("file", help="argument obligatoire : fichier PCAP")
parser.add_argument(
  "--proto",
  choices=["pcap", "ethernet", "arp", "ipv4", "ipv6", "tcp", "udp", "icmp", "dns", "http", "quic"],
  help="Filtrer l'affichage par protocole"
)
args = parser.parse_args()

#import des function pour les parser
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
from dns import (
  parse_dns,
  get_dns_class_name,
  get_dns_type_name,
)
from http import (
  parse_http,
)
from quic import (
  parse_quic,
)

#pathe de la ressource a analiser
RESSOURCE_PATH = args.file # args du path de la ressource
PROTO_FILTER = args.proto #filtre pour commande cli et affiche les proto demandé

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
  displayed_packet = 0 #compteur total : combien de paquets affichés
  
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
    dns = None
    question_type_name = None
    question_class_name = None
    answer_type_name = None
    answer_class_name = None
    http = None
    quic = None
    
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
          if tcp["src_port"] == 80 or tcp["dst_port"] == 80:
            http = parse_http(tcp["payload"])
        elif ipv4["protocol"] == 17:
          udp = parse_udp(ipv4["payload"])
          if udp["src_port"] == 53 or udp["dst_port"] == 53:
            dns = parse_dns(udp["payload"])
            question_type_name = get_dns_type_name(dns["question_type"])
            if dns["answer_type"] is not None:
              answer_type_name = get_dns_type_name(dns["answer_type"])
            question_class_name = get_dns_class_name(dns["question_class"])
            if dns["answer_class"] is not None:
              answer_class_name = get_dns_class_name(dns["answer_class"])
          if udp["src_port"] == 443 or udp["dst_port"] == 443:
            quic = parse_quic(udp["payload"])
        elif ipv4["protocol"] == 1:
          icmp = parse_icmp(ipv4["payload"])
      elif ethernet["ethertype"] == 0x0806: # if ethertype == ARP
        arp = parse_arp(ethernet["payload"])
      elif ethernet["ethertype"] == 0x86DD:  # if ethertype == IPV6
        ipv6 = parse_ipv6(ethernet["payload"])
        protocol_name_ipv6 = get_ipv6_protocol_name(ipv6["final_next_header"])

    ########### filtrage des packet pour commande CLI ###############
  
    display_packet = False #booléen temporaire : afficher ce paquet  True/False
    
    if PROTO_FILTER is None:
      display_packet = True
    if PROTO_FILTER == "ethernet" and ethernet is not None:
      display_packet = True
    if PROTO_FILTER == "arp" and arp is not None:
      display_packet = True
    if PROTO_FILTER == "ipv4" and ipv4 is not None:
      display_packet = True
    if PROTO_FILTER == "ipv6" and ipv6 is not None:
      display_packet = True
    if PROTO_FILTER == "tcp" and tcp is not None:
      display_packet = True
    if PROTO_FILTER == "udp" and udp is not None:
      display_packet = True
    if PROTO_FILTER == "icmp" and icmp is not None:
      display_packet = True
    if PROTO_FILTER == "dns" and dns is not None:
      display_packet = True
    if PROTO_FILTER == "http" and http is not None:
      display_packet = True
    if PROTO_FILTER == "quic" and quic is not None:
      display_packet = True
    if PROTO_FILTER == "pcap":
      display_packet = True
    if display_packet is False:
      packet_index += 1
      continue
    
    ## ajoute au display packet
    displayed_packet += 1 #compteur total : combien de paquets affichés
  
    ##################### Print des parsing des Packet #####################
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
    print()
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
    if dns is not None:
      print(f"======Parsing DNS packet n°{packet_index}======")
      print("Transaction ID:", dns["transaction_id"])
      print("Flags DNS:", dns["flags_dns"])
      print("Questions count:", dns["qdcount"])
      print("Responses count:", dns["ancount"])
      print("Name Server Count:", dns["nscount"])
      print("Additional Record Count:", dns["arcount"])
      print("Question name:", dns["question_name"])
      print("Question type:", question_type_name)
      print("Question class:", question_class_name)
      print("Answer name:", dns["answer_name"])
      print("Answer type:", answer_type_name)
      print("Answer class:", answer_class_name)
      print("TTL:", dns["ttl"])
      print("Response length:", dns["rdlength"])
      print("RDATA preview:", dns["rdata"][:32].hex())
      print("RDATA decoded:", dns["rdata_decoded"])
      print()
    if http is not None:
      print(f"======Parsing HTTP packet n°{packet_index}======")
      print("HTTP type:", http["type"])
      print("HTTP methode:", http["method"])
      print("Path:", http["path"])
      print("HTTP version:", http["version"])
      print("Statut code:", http["status_code"])
      print("Reason:", http["reason"])
      print("HTTP headers:", http["headers"])
      print("Body length:", http["body_length"])
      print("Body preview hexa:", http["body_preview_hex"])
      print("Body preview texte:", http["body_preview_text"])
      print()
    if quic is not None:
      print(f"======Parsing QUIC packet n°{packet_index}======")
      print("Header type:", quic["header_type"])
      print("First byte:", quic["first_byte"])
      print("Payload length:", quic["payload_length"])
      print("Version:", quic["version"])
      print("DCID length:", quic["dcid_length"])
      print("DCID hexa:", quic["dcid_hex"])
      print("SCID length:", quic["scid_length"])
      print("SCID hexa:", quic["scid_hex"])
      print()
    # incrémente l'index
    packet_index += 1


######## fin du with et lecture fermé ################
####### print du nombre de packet ####
print("======Nombre totale de packets======")
print("Total packets:", packet_index - 1)
print("Total display-packets:", displayed_packet, "/", packet_index - 1)
print("Filter:", PROTO_FILTER)
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