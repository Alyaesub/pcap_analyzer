import os

RESSOURCE_PATH = "captures/http_local_capture.pcap"

if not os.path.isfile(RESSOURCE_PATH):
  print("fichier introuvable")
else:
  f = open(RESSOURCE_PATH, 'rb')
  global_header_byte = f.read(24)
  global_header_hex = global_header_byte.hex()
  
  print("====Global-Header-Bytes====")
  print(global_header_byte)
  print("====Global-Header-Hexa====")
  print(global_header_hex)
  
  f.close()

