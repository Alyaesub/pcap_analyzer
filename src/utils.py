#function qui formate les adress mac
def format_mac(mac_bytes):
  return ":".join(f"{byte:02x}" for byte in mac_bytes)

#function qui formate les adress IPV4
def format_ipv4(ip_bytes):
  return ".".join(str(byte) for byte in ip_bytes)

#function qui formate les adress IPV6
def format_ipv6(ip_bytes):
  groups = []

  for i in range(0, 16, 2):
    group = int.from_bytes(ip_bytes[i:i+2], byteorder="big")
    groups.append(f"{group:04x}")

  return ":".join(groups)