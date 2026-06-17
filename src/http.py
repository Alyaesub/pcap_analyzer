#parser http
def parse_http(tcp_payload):
  if not tcp_payload:
    return None
  
  if b"\r\n\r\n" not in tcp_payload:
    return None
  
  header, body = tcp_payload.split(b"\r\n\r\n", 1) # le 1 veut dire coupe une seul fois au premier sépparateurs "\r\n\r\n" au cas ou il y en aurait d'autre dans le body
  
  decoded_header = header.decode("iso-8859-1") # avec iso-8859-1 chaque byte entre 0x00 et 0xFF peut être représenté sans crach le programme
  body_preview_text = body[:100].decode("iso-8859-1")
  
  header_lines = decoded_header.split("\r\n")#split le heade
  start_line = header_lines[0] #recupére le premiere line
  headers = header_lines[1:]
  
  parts_start_line = start_line.split(" ") # split cette premiere line
  
  if len(parts_start_line) < 3:
    return None
  
  http_type = "unknown"
  method = None
  path = None
  version = None
  status_code = None
  reason = None
  
  if parts_start_line[0].startswith("HTTP/"):
    http_type = "response"
    version = parts_start_line[0]
    status_code = parts_start_line[1]
    reason = " ".join(parts_start_line[2:])
  else:
    http_type = "request"
    method = parts_start_line [0]
    path = parts_start_line [1]
    version = parts_start_line [2]
  
  return {
  "type": http_type,              # request / response / unknown
  "method": method,
  "path": path,
  "version": version,
  "status_code": status_code,
  "reason": reason,
  "headers": headers,
  "body_length": len(body),
  "body_preview_hex": body[:32].hex(),
  "body_preview_text": body_preview_text
}