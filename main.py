# https://superuser.com/questions/505130/are-segments-packets-and-frames-the-same-size-if-we-ignore-headers

# ETH_TYPE_IP = 0x0800  # IP protocol
# ETH_TYPE_IP6 = 0x86DD  # IPv6 protocol

from lib.packet import Packet
from lib.app import App
from lib.parser import parse
import socket
import dpkt
import sys
from pprint import pprint

# packets = []

for ts, data in dpkt.pcap.Reader(file(sys.argv[1], "rb")):
    ether = dpkt.ethernet.Ethernet(data)
    
    print('**********************')
    pprint(parse(ether))

    if ether.type == dpkt.ethernet.ETH_TYPE_IP:
      addr_family = socket.AF_INET
    elif ether.type == dpkt.ethernet.ETH_TYPE_IP6:
      addr_family = socket.AF_INET6
    else:
      # see https://dpkt.readthedocs.io/en/latest/_modules/dpkt/ethernet.html#Ethernet
      # for other ethernet payload types
      # for this project, will probably focus only on ipv6, ipv4(?)
      continue

    ip = ether.data

    
    #packets.append(Packet(addr_family, Packet.SRC, ip.src))
    #packets.append(Packet(addr_family, Packet.DST, ip.dst))

    if isinstance(ip.data, dpkt.tcp.TCP):
      tcp = ip.data
      app = tcp.data

      try:
        request = dpkt.http.Request(app)
        # pprint(request)
        # exit()
        
        
        # print request.headers
        # print request.headers['host']
        # print request.headers
      except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
        continue
          
      # request = dpkt.http.Request(tcp.data)
      # do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
      # more_fragments = bool(ip.off & dpkt.ip.IP_MF)
      # fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
      # print 'IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)' % (ip.src, ip.dst, ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset)
      # print 'HTTP request: %s\n' % repr(request)
      