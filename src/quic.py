#parser des packet QUIC

def parse_quic(quic_bytes):
  if not quic_bytes:
    return None

  first_byte = quic_bytes[0]
  payload_length = len(quic_bytes)

  is_long_header = (first_byte & 0x80) == 0x80 # sert à tester le premier bit du premier byte si 1 long header si 0 short header
  
  quic_type = "long_header" if is_long_header else "short_header"
  
  offset = 1
  version = None
  dcid_length = None
  dcid_hex = None
  scid_length = None
  scid_hex = None
  
  if quic_type == "long_header":
    
    if len(quic_bytes) < 5:
      return "error:" "Erreur, packet Quic tronqué"
    else:
      version = int.from_bytes(quic_bytes[1:5], byteorder="big")
      offset += 4
    
    dcid_length = quic_bytes[offset]
    offset += 1
    
    if offset + dcid_length > len(quic_bytes):
      return "error:" "Erreur, packet Quic tronqué"
    else:
      dcid = quic_bytes[offset : offset + dcid_length]
      dcid_hex = dcid.hex() #identifiant de connexion côté destination
      offset += dcid_length
    
    if offset >= len(quic_bytes):
      return "error:" "Erreur, packet Quic tronqué"
      
    scid_length = quic_bytes[offset]
    offset += 1
    
    if offset + scid_length > len(quic_bytes):
      return "error:" "Erreur, packet Quic tronqué"
    else:
      scid = quic_bytes[offset : offset + scid_length]
      scid_hex = scid.hex() #identifiant de connexion côté source
      offset += scid_length
    

  return {
    "header_type": quic_type,
    "first_byte": first_byte,
    "payload_length": payload_length,
    "version": version,
    "dcid_length": dcid_length,
    "dcid_hex": dcid_hex,
    "scid_length": scid_length,
    "scid_hex": scid_hex
  }