import socket
# import dpkt

class Packet:

  SRC = 1
  DST = 2

  # addr_family - socket.AF_INET vs socket.AF_INET6
  # target - SRC vs DST
  # ip_addr - unpacked ip address (i.e. in hex form), hence, line 15
  def __init__(self, addr_family, target, ip_addr):
    self.addr_family = addr_family
    self.target = target
    self.ip_addr = socket.inet_ntop(addr_family, ip_addr)

    try:
      hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(self.ip_addr)
      aliaslist.append(hostname)
      self.hostnames = aliaslist
      self.ipaddrlist = ipaddrlist 
    except socket.herror:
      self.hostnames = []
      self.ipaddrlist = []