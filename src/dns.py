#parser des packet DNS
""" Header DNS = bytes 0 à 11
Questions = commencent à offset 12
QNAME = taille variable
QTYPE/QCLASS = juste après le QNAME """

from utils import (
  format_ipv4,
  format_ipv6,
)

def parse_dns(dns_bytes):
  if len(dns_bytes) < 12:
    print("Erreur, packet DNS non valide")
    exit(1)
  
  #parsing du header du packet DNS
  transaction_id = int.from_bytes(dns_bytes[0:2], byteorder="big") #relier requête et réponse
  flags_dns = int.from_bytes(dns_bytes[2:4], byteorder="big") #type/état du message DNS
  qdcount = int.from_bytes(dns_bytes[4:6], byteorder="big") # nombre de question
  ancount = int.from_bytes(dns_bytes[6:8], byteorder="big") # nombre de reponses
  nscount = int.from_bytes(dns_bytes[8:10], byteorder="big") # nombre d'entré authority
  arcount = int.from_bytes(dns_bytes[10:12], byteorder="big") # nombre d'entré additional
  
  # parsing de QNAME / QTYPE / QCLASS
  #parsing de question dns
  offset = 12
  
  qname, offset = read_dns_name(dns_bytes, offset)
  ## l'offset pointe sur le debut des reponses grace a la function read_dns donc pour avancer on avance des byte de chaque valeurs
  qtype = int.from_bytes(dns_bytes[offset:offset + 2], byteorder="big") #type d’enregistrement DNS
  offset += 2
  qclass = int.from_bytes(dns_bytes[offset:offset + 2], byteorder="big") # dans quel espace/réseau on fait la requête DNS
  offset += 2
  ###### fin des byte des questions DNS
  
  ###### debut des byte des reponses DNS
  ## l'offset pointe sur le debut des reponses grace a la function read_dns
  answer_name = None
  answer_type = None
  answer_class = None
  ttl = None
  rdlength = None
  rdata = b""
  rdata_decoded = None

  if ancount > 0:
    answer_name, offset = read_dns_name(dns_bytes, offset)
    
    answer_type = int.from_bytes(dns_bytes[offset:offset + 2], byteorder="big")
    offset += 2

    answer_class = int.from_bytes(dns_bytes[offset:offset + 2], byteorder="big")
    offset += 2

    ttl = int.from_bytes(dns_bytes[offset:offset + 4], byteorder="big") #durée de cache
    offset += 4

    rdlength = int.from_bytes(dns_bytes[offset:offset + 2], byteorder="big") # taille de RDATA
    offset += 2

    rdata = dns_bytes[offset:offset + rdlength] # vrai data de la réponse
    offset += rdlength # offset arrive a la fin de rdata
    
    # gestion des type des réponse
  if answer_type == 1:
    rdata_decoded = format_ipv4(rdata)
  elif answer_type == 28:
    rdata_decoded = format_ipv6(rdata)
  elif answer_type == 5:
    rdata_decoded, _ = read_dns_name(dns_bytes, offset - rdlength)
  else:
    rdata_decoded = rdata.hex()
    
  
  return {
    "transaction_id": transaction_id,
    "flags_dns": flags_dns,
    'qdcount': qdcount,
    "ancount": ancount,
    "nscount": nscount,
    "arcount": arcount,
    "question_name": qname,
    "question_type": qtype,
    "question_class": qclass,
    "answer_name": answer_name,
    "answer_type": answer_type,
    "answer_class": answer_class,
    "ttl": ttl,
    "rdlength": rdlength,
    "rdata": rdata,
    "rdata_decoded": rdata_decoded
  }

#################### function qui lie le qname pour les question et reppnse dns et les name compréssé
# a la fin de la fonction Offset = apres name donc debut du reste
def read_dns_name(dns_bytes, offset):
  labels = []
  compressed = False # boolean qui verifie si c'est comprésser pour gére le saut des bytes

  while dns_bytes[offset] != 0:
    # Cas compression DNS, ex: c0 0c
    if dns_bytes[offset] & 0xC0 == 0xC0: # si commence au byte 11, pas longuer de label
      compressed = True
      
      pointer = int.from_bytes(dns_bytes[offset:offset + 2], byteorder="big") #les bits de compression + l’offset réel
      pointer_offset = pointer & 0x3FFF # retire les 2 bye de comprésion

      pointed_name, _ = read_dns_name(dns_bytes, pointer_offset) #lie le pointeur offset mais ne le met pas a jours
      labels.append(pointed_name)

      offset += 2 # vrai offset mis a jour car le pointer_offset fait que 2 byte
      break
    
    # cas normal
    label_length = dns_bytes[offset]
    offset += 1

    label_bytes = dns_bytes[offset : offset + label_length]
    label_string = label_bytes.decode()
    labels.append(label_string)
  
    offset += label_length
  
  if not compressed:
    offset += 1
  
  name = ".".join(labels)
  return name, offset

##################### function qui convertie les int en texte pour les Qtype et Qclass
def get_dns_type_name(qtype):
    if qtype == 1:
        return "1 - A"
    elif qtype == 28:
        return "28 - AAAA"
    elif qtype == 5:
        return "5 - CNAME"
    elif qtype == 15:
        return "15 - MX"
    elif qtype == 65:
      return "65 - HTTPS"
    elif qtype == 64:
      return "64 - SVCB"
    elif qtype == 2:
        return "2 - NS"
    else:
        return f"Unknown ({qtype})"

def get_dns_class_name(qclass):
    if qclass == 1:
        return "IN"
    else:
        return f"Unknown ({qclass})"