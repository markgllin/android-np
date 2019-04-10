import dpkt
import sys
import socket
import sqlite3
import re
import os

def insert_dns_result(hostnames, ips):
  conn = sqlite3.connect('db_addresses.db')
  c = conn.cursor()

  for ip in ips:
    for hostname in hostnames:
        c.execute("select * from domains where hostname='" + hostname + "' and ip='" + ip + "'")

        results = c.fetchall()
        if len(results) == 0:
          query = "INSERT INTO domains VALUES ('" + ip + "','" + hostname + "')"
          print(query)
          c.execute(query)


        conn.commit()
  conn.close()


filepattern = re.compile('.*\.apk\.pcap$')

conn = sqlite3.connect('db_addresses.db')
c = conn.cursor()

#create table
c.execute("CREATE TABLE if not exists domains (ip text, hostname text)")
conn.close()
print("Creating table for domains...")

for pcap in os.listdir('../pcaps/Android9.0/nongames/'):
  filename = os.path.join('../pcaps/Android9.0/nongames/', pcap)

  if filepattern.match(filename):
    print('Parsing ' + filename + '...')

    for ts, data in dpkt.pcapng.Reader(file(filename, "rb")):
      ether = dpkt.ethernet.Ethernet(data)

      ip = ether.data
      udp = ip.data

      if not hasattr(udp, 'sport'): continue

      if udp.sport != 53 and udp.dport != 53:
        continue

      try:
        dns = dpkt.dns.DNS(udp.data)

        if dns.qr != dpkt.dns.DNS_R:
          continue

        hostname = set()
        ip = set()
        for answer in dns.an:
          hostname.add(answer.name)
          if hasattr(answer, 'ip'):
            ip.add(socket.inet_ntoa(answer.ip))
        
        insert_dns_result(hostname, ip)
      except dpkt.dpkt.NeedData:
        continue

