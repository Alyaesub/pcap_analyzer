# IPv6 header = toujours 40 bytes

# payload_length = taille de tout ce qui vient après ces 40 bytes

# next_header = type du bloc juste après le header IPv6

# si next_header = 6/17/58 :
#     payload direct = TCP/UDP/ICMPv6

# si next_header = 0/43/44/50/51/60 :
#     payload direct = extension IPv6
#     il faut lire cette extension
#     puis regarder son next_header à elle

# final_next_header = vrai protocole final après extensions

from utils import (format_ipv6)

#function qui parse le packet IPV6
def parse_ipv6(ipv6_bytes):
  if len(ipv6_bytes) < 40:
    print("Erreur, trame IPv6 non valide")
    exit(1)
  
  first_byte = ipv6_bytes[0]
  version = first_byte >> 4 #récupère les 4 bits de gauche
  if version != 6:
    print("Erreur, trame IPv6 non valide")
    exit(1)
  
  payload_length = int.from_bytes(ipv6_bytes[4:6], byteorder="big")
  if len(ipv6_bytes) < 40 + payload_length:
    print("Erreur, header IPV6 tronqué ou invalide")
    exit(1)
  
  next_header = ipv6_bytes[6] # équivalent du protocol IPv4 mais avec option a gére
  hop_limit = ipv6_bytes[7] # équivalent du TTL IPv4
  src_ipv6 = format_ipv6(ipv6_bytes[8:24])
  dst_ipv6 = format_ipv6(ipv6_bytes[24:40])
  
  ###### logique qui parse les header et gére les extensions #############
  offset = 40 # initialize offset pour pouvoir le lire ensuite a partire de la fin du header principal byte 40
  end_offset = 40 + payload_length # donne la fin des packet des header minimum 40 bytes + payload avec le proto
  current_next_header = next_header # current pour le header qui est analizer a l'instant T
  final_next_header = next_header # header final (protocol)
  EXTENSION_HEADERS = 0, 43, 44, 50, 51, 60 # code valeur des dextension connue
  extensions_headers = [] #liste vide qui stockera les extensions si y en a
  
  while current_next_header in EXTENSION_HEADERS: # si current est une extension :
    
    extension_start = offset
    extension_type = current_next_header
    # gére les extensions en fonction de leur valeur (50 et 51 seront traiter basiquement)
    if extension_type in [0, 43, 60]:
      if offset + 2 > end_offset :
        print("Erreur, offset packet")
        exit(1)
      next_header_interne = ipv6_bytes[offset]
      extension_length = ipv6_bytes[offset + 1]
      extension_size = (extension_length + 1) * 8
      
      offset = offset + extension_size
      if offset > end_offset:
        print("Erreur, offset packet")
        exit(1)
      
      liste_details = [extension_type, extension_start, extension_size, next_header_interne]
      extensions_headers.append(liste_details)
      print(f"Extension présente:", extensions_headers)
      
      current_next_header = next_header_interne
      final_next_header = current_next_header
    
    elif extension_type == 44:
      extension_size = 8
      if offset + 8 > end_offset:
        print("Erreur, offset packet")
        exit(1)
      
      next_header_interne = ipv6_bytes[offset]
      offset = offset + 8
      
      liste_details = [extension_type, extension_start, extension_size, next_header_interne]
      extensions_headers.append(liste_details)
      print(f"Extension présente:", extensions_headers)
      
      current_next_header = next_header_interne
      final_next_header = current_next_header
    
    elif extension_type in [50, 51]:
      print("Extensions, non géré")
      print(extension_type)
      final_next_header = extension_type
      
      liste_details = [extension_type, extension_start, "unsupported"]
      extensions_headers.append(liste_details)
      print(f"Extension présente:", extensions_headers)
      break
  
  payload = ipv6_bytes[offset:end_offset]
  
  return {
    "version": version,
    "payload_length": payload_length,
    "next_header": next_header,
    "hop_limit": hop_limit,
    "src_ipv6": src_ipv6,
    "dst_ipv6": dst_ipv6,
    "final_next_header": final_next_header,
    "extensions_headers": extensions_headers,
    "payload": payload
  }




############### function qui verifie et traduit le numéoro du protocole ###########
def get_ipv6_protocol_name(protocol):
  if protocol == 6:
    return "6 - TCP"
  elif protocol == 17:
    return "17 - UDP"
  elif protocol == 58:
    return "58 - ICMPv6"
  else:
    return "Protocol non supporté"