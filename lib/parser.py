import socket
import dpkt

def parse(frame):
  internet = {}
  transport = {}
  application = {}

  if frame.type == dpkt.ethernet.ETH_TYPE_IP:
    addr_family = socket.AF_INET
  elif frame.type == dpkt.ethernet.ETH_TYPE_IP6:
    addr_family = socket.AF_INET6
  else:
    # see https://dpkt.readthedocs.io/en/latest/_modules/dpkt/ethernet.html#Ethernet
    # for other ethernet payload types
    # for this project, will probably focus only on ipv6, ipv4(?)
    return {},{},{}

  packet = frame.data
  src_ip = socket.inet_ntop(addr_family, packet.src)
  dst_ip = socket.inet_ntop(addr_family, packet.dst)
  internet['src_ip'] = src_ip
  internet['dst_ip'] = dst_ip

  segment = packet.data

  if isinstance(segment, dpkt.tcp.TCP):
    transport['sport'] = segment.sport
    transport['dport'] = segment.dport

    app_data = segment.data

    try:
      request = dpkt.http.Request(app_data)
      
      for hder, val in request.headers.items():
        application[hder] = val
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
      application = {}

  return internet, transport, application




  
  