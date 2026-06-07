import os
from pcap_parser import (
  parse_global_header,
  parse_packet_header,
  read_exact
)

#pathe de la ressource a analiser
RESSOURCE_PATH = "captures/http_local_capture.pcap"

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
  
  # Packet header
  packet_header_byte = read_exact(f, 16) # lie les 16 byte du packet header
  # Appele de la function qui parse le packet header
  packet_header = parse_packet_header(packet_header_byte, global_header["endianness"])
  
  # Packet data : contenu brut du paquet
  packet_data_byte = read_exact(f, packet_header["incl_len"])

# print les byte du global header
print("====Global-Header-Bytes====")
print(global_header_byte)
print("====Packet-Header-Bytes====")
print(packet_header_byte)

######################## parsing du global header #########################
# print les infos du global header
print("======Global Header Parsing======")
print("Magic Number hexa:", global_header["magic_number"])
print("Endianness:", global_header["endianness"])
print(f"Version: {global_header['version_major']}.{global_header['version_minor']}")
print("ThisZone:", global_header["thiszone"])
print("Sigfigs:", global_header["sigfigs"])
print("Snaplen:", global_header["snaplen"])
print("Network:", global_header["network"])


##################### Parsing du Packet header #####################
# print les infos du packet header
print("======Packet Header Parsing======")
print("Timestamp seconds: ", packet_header["ts_sec"])
print("Timestamp microseconds: ", packet_header["ts_usec"])
print("Included length: ", packet_header["incl_len"])
print("Original length: ", packet_header["orig_len"])
# print les data du packet
print("=======Packet Data==========")
print("length byte data: ", len(packet_data_byte))
print("32 premier byte: ", packet_data_byte[:32].hex())