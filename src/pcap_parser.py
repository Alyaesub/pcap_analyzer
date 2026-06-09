############ function qui parse le global header d'un pcap ###############
def parse_global_header(global_header_byte):
  #récupere les byte pour le parsing
  magic_number_byte = global_header_byte[0:4] # donne les endianness
  version_major_byte = global_header_byte[4:6] # version majeur == la version utiliser 2.
  version_minor_byte = global_header_byte[6:8] # la sous version de la version == version.4
  thiszone_byte = global_header_byte[8:12] # représente le décalage horaire entre les timestamps du fichier et UTC souvent 0
  sigfigs_byte = global_header_byte[12:16] # veut dire “significant figures”, précision théorique des timestamps.
  snaplen_byte = global_header_byte[16:20] # taille maximale capturée par paquet
  network_byte = global_header_byte[20:24] # linktype type de lien, ce qui démarre chaque paquet

  # Convertion du magic number en hexa
  magic_number = magic_number_byte.hex() 

  #verification de l'ordre endianness
  endianness = ""
  if magic_number == "d4c3b2a1":
    endianness = "little"
  elif magic_number == "a1b2c3d4":
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
  
  return {
    "magic_number": magic_number,
    "endianness": endianness,
    "version_major": version_major_number,
    "version_minor": version_minor_number,
    "thiszone": thiszone_number,
    "sigfigs": sigfigs_number,
    "snaplen": snaplen_number,
    "network": network_number
}

############### fonction qui parse le header des packet #####################

def parse_packet_header(packet_header_byte, endianness):
  #recupere les byte du packet header pour le parsing
  ts_sec_byte = packet_header_byte[0:4] #timestamp en secondes.
  ts_usec_byte = packet_header_byte[4:8] # microsecondes du timestamp
  incl_len_byte = packet_header_byte[8:12] # taille réel capturée dans le fichier pour ce paquet
  orig_len_byte = packet_header_byte[12:16] # la taille originale du paquet sur le réseau

  # convertie en nombre les bytes du packet header
  ts_sec_number = int.from_bytes(ts_sec_byte, byteorder=endianness)
  ts_usec_number = int.from_bytes(ts_usec_byte, byteorder=endianness)
  incl_len_number = int.from_bytes(incl_len_byte, byteorder=endianness)
  orig_len_number = int.from_bytes(orig_len_byte, byteorder=endianness)
  
  return {
    "ts_sec": ts_sec_number,
    "ts_usec": ts_usec_number,
    "incl_len": incl_len_number,
    "orig_len": orig_len_number
  }

###################### function qui lie le fichier et le nombre de byte demander ###########

def read_exact(f, size):
  data = f.read(size) #lie les X premier bytes
  
  if len(data) != size: ## vérifie qu'il y a bien les X bytes
    print("Erreur: Fichier tronqué ou invalide")
    exit(1)
  
  return data

############### function qui lie et verifie si le header packet est valide et si il en reste pour finir de bouclé sur les packet du pcap ###########
def read_packet_header_or_none(f):
  data_packet_header = f.read(16) # lie les 16 premier byte du packet header
  
  if len(data_packet_header) == 0:
    return None
  elif len(data_packet_header) != 16:
    print("Erreur: Fichier tronqué ou invalide")
    exit(1)
  else:
    return data_packet_header

############# function qui verifie et traduit le type de network ###########
def get_linktype_name(network):
  if network == 0:
    return "Loopback / non-Ethernet"
  elif network == 1:
    return "Ethernet II"
  else:
    return "Linktype non supporté"