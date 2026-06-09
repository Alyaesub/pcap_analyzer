#function qui convertie les adress mac propre
def format_mac(mac_bytes):
  return ":".join(f"{byte:02x}" for byte in mac_bytes)