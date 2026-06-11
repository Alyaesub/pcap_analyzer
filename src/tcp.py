#function qui parse les packet TCP
def parse_tcp(tcp_bytes):
  if len(tcp_bytes) < 20:
    print("Erreur, packet TCP non valide")
    exit(1)

  src_port_byte = tcp_bytes[0:2]
  dst_port_byte = tcp_bytes[2:4]
  sequence_number_byte = tcp_bytes[4:8]
  acknowledgment_number_byte = tcp_bytes[8:12]
  data_offset_byte = tcp_bytes[12] >> 4 # taille du header en blocs de 4 bytes
  header_length_byte = data_offset_byte * 4 #taille réelle du header TCP en bytes

  src_port_number = int.from_bytes(src_port_byte, byteorder="big")
  dst_port_number = int.from_bytes(dst_port_byte, byteorder="big")
  sequence_number_number = int.from_bytes(sequence_number_byte, byteorder="big") #position dans le flux envoyé
  acknowledgment_number_number= int.from_bytes(acknowledgment_number_byte, byteorder="big") #prochain byte attendu par le récepteur
  window = int.from_bytes(tcp_bytes[14:16], byteorder="big") # quantité de données que le récepteur accepte encore
  
  return {
    "src_port": src_port_number,
    "dst_port": dst_port_number,
    "sequence_number": sequence_number_number,
    "acknowledgment_number": acknowledgment_number_number,
    "header_length": header_length_byte,
    "window": window
  }