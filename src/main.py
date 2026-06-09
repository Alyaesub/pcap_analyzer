import os
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

#pathe de la ressource a analiser
RESSOURCE_PATH = "captures/ethernet_capture_small.pcap"

############## Gestion et lecture des fichier source ##############

#verifie si le fichier existe et si oui lie les 24 premier bytes
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
    
    # Gestion Ethernet
    ethernet = None # de base lecture sans ethernet si ethernet existe alors :
    ethertype_name = None #pareil pour ethertype
    
    if global_header["network"]  == 1: # verifie le network
      # appele la function qui parse le packet Ethernet
      ethernet = parse_ethernet(packet_data_byte)
      ethertype_name = get_ethertype_name(ethernet["ethertype"])
    
    ##################### Parsing des Packet #####################
    # print les infos du packet header
    print(f"======Parsing Packet n°{packet_index}======")
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
    
    # incrémente l'index
    packet_index += 1

######## fin du with et lecture fermet ################
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