import socket
import dpkt
import sys
import sqlite3
from multiprocessing.dummy import Pool as ThreadPool 



for ts, data in dpkt.pcap.Reader(file(sys.argv[1], "rb")):
    ether = dpkt.ethernet.Ethernet(data)
    print(len(data))

    if ether.type == dpkt.ethernet.ETH_TYPE_IP:
      addr_family = socket.AF_INET
    elif ether.type == dpkt.ethernet.ETH_TYPE_IP6:
      addr_family = socket.AF_INET6
    else:
      continue

    ip = ether.data
