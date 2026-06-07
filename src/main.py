import os

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
  global_header_byte = f.read(24) # lie les 24 premier bytes (global header)
  if len(global_header_byte) != 24: # vérifie qu'il y a bien les 24 bytes
    print("Erreur : Global Header incomplet")
    exit(1)
  global_header_hex = global_header_byte.hex() #met en hexa les bytes
  
  # Packet header
  packet_header_byte = f.read(16) # lie les 16 byte du packet header
  if len(packet_header_byte) != 16:
    print("Erreur : Packet Header incomplet")
    exit(1)
  packet_header_hex = packet_header_byte.hex()

# print les byte et l'hexa du global header
print("====Global-Header-Bytes====")
print(global_header_byte)
print("====Global-Header-Hexa====")
print(global_header_hex)
print("====Packet-Header-Bytes====")
print(packet_header_byte)
print("====Packet-Header-Hexa====")
print(packet_header_hex)

######################## parsing du global header #########################

#récupere les byte pour le parsing
magic_number_byte = global_header_byte[0:4]
version_major_byte = global_header_byte[4:6]
version_minor_byte = global_header_byte[6:8]
thiszone_byte = global_header_byte[8:12]
sigfigs_byte = global_header_byte[12:16]
snaplen_byte = global_header_byte[16:20]
network_byte = global_header_byte[20:24]

# Parsing du global header en hexa
magic_number_hex = magic_number_byte.hex() # donne les endianness
version_major_hex = version_major_byte.hex() # version majeur == la version utiliser 2.
version_minor_hex = version_minor_byte.hex() # la sous version de la version == version.4
thiszone_hex = thiszone_byte.hex() # représente le décalage horaire entre les timestamps du fichier et UTC souvent 0
sigfigs_hex = sigfigs_byte.hex() # veut dire “significant figures”, précision théorique des timestamps.
snaplen_hex = snaplen_byte.hex() # taille maximale capturée par paquet
network_hex = network_byte.hex() # linktype type de lien, ce qui démarre chaque paquet

#verification de l'ordre endianness
endianness = ""
if magic_number_hex == "d4c3b2a1":
  endianness = "little"
elif magic_number_hex == "a1b2c3d4":
  endianness = "big"
else:
  print("Erreur : format PCAP invalide ou non supporté")
  exit(1)

# convertie en nombre les bytes du header global
version_major_number = int.from_bytes(version_major_byte, byteorder=endianness)
version_minor_number = int.from_bytes(version_minor_byte, byteorder=endianness)
thiszone_number = int.from_bytes(thiszone_byte, byteorder=endianness)
sigfigs_number = int.from_bytes(sigfigs_byte, byteorder=endianness)
snaplen_number = int.from_bytes(snaplen_byte, byteorder=endianness)
network_number = int.from_bytes(network_byte, byteorder=endianness)

# print les infos du global header
print("======Global Header Parsing======")
print("Magic Number hexa: ", magic_number_hex)
print("Endianness: ", endianness)
print(f"Version: {version_major_number}.{version_minor_number}")
print("ThisZone: ", thiszone_number)
print("Sigfigs: ", sigfigs_number)
print("Snaplen: ", snaplen_number)
print("Network: ", network_number)


##################### Parsing du Packet header #####################

#recupere les byte du packet header pour le parsing
ts_sec_byte = packet_header_byte[0:4]
ts_usec_byte = packet_header_byte[4:8]
incl_len_byte = packet_header_byte[8:12]
orig_len_byte = packet_header_byte[12:16]

#parsing du packet header en hexa
ts_sec_hex = ts_sec_byte.hex() #timestamp en secondes.
ts_usec_hex = ts_usec_byte.hex() # microsecondes du timestamp
incl_len_hex = incl_len_byte.hex() # taille réel capturée dans le fichier pour ce paquet
orig_len_hex = orig_len_byte.hex() # la taille originale du paquet sur le réseau

# convertie en nombre les bytes du packet header
ts_sec_number = int.from_bytes(ts_sec_byte, byteorder=endianness)
ts_usec_number = int.from_bytes(ts_usec_byte, byteorder=endianness)
incl_len_number = int.from_bytes(incl_len_byte, byteorder=endianness)
orig_len_number = int.from_bytes(orig_len_byte, byteorder=endianness)

# print les infos du packet header
print("======Packet Header Parsing======")
print("Timestamp seconds: ", ts_sec_number)
print("Timestamp microseconds: ", ts_usec_number)
print("Included length: ", incl_len_number)
print("Original length: ", orig_len_number)