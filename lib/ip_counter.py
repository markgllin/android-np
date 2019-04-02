import socket
import dpkt
import csv
import sqlite3
import ipaddress
import os
import sys

from multiprocessing.dummy import Pool as ThreadPool 

def categorize_address(frame):
  extrnl_ip = ''

  if ipaddress.ip_address(frame[0]).is_private and ipaddress.ip_address(frame[1]).is_private:
    return [('benign',) + frame]
  elif ipaddress.ip_address(frame[0]).is_private:
    extrnl_ip = frame[1]
  else:
    extrnl_ip = frame[0]

  conn = sqlite3.connect('../database/ip_addresses.db')
  c = conn.cursor()

  c.execute("select * from ip_service where ip='" + extrnl_ip + "'")
  results = c.fetchall()

  service = ''
  for result in results:
    if service == '':
      service = result[1]
    else:
      service += ',' + result[1]

  if service == '':
    return [('benign',) + frame]
  
  return [(service,) + frame]

with open('ip_summary.csv', 'ab+') as csvfile:
  writer = csv.writer(csvfile, delimiter=',', quoting=csv.QUOTE_MINIMAL)
  writer.writerow(['App', 'IP', 'Service', 'Connections', 'Traffic Size'])

  for pcap in os.listdir('../pcaps/Android9.0/'):

    filename = os.path.join('../pcaps/Android9.0', pcap)
    print('Parsing ' + filename + '...')

    ips = {}

    try:
      
      for ts, data in dpkt.pcapng.Reader(file(filename, "rb")):

        ether = dpkt.ethernet.Ethernet(data)
              
        if ether.type == dpkt.ethernet.ETH_TYPE_IP:
          addr_family = socket.AF_INET
        elif ether.type == dpkt.ethernet.ETH_TYPE_IP6:
          addr_family = socket.AF_INET6
        else:
          continue

        ip = ether.data
        src_ip = socket.inet_ntop(addr_family, ip.src)
        dst_ip = socket.inet_ntop(addr_family, ip.dst)

        if not ipaddress.ip_address(src_ip).is_private:
          if src_ip not in ips.keys():
            ips[src_ip] = [1, len(data)]
          else:
            ips[src_ip][0] += 1
            ips[src_ip][1] += len(data)
        
        if not ipaddress.ip_address(dst_ip).is_private:
          if dst_ip not in ips.keys():
            ips[dst_ip] = [1, len(data)]
          else:
            ips[dst_ip][0] += 1
            ips[dst_ip][1] += len(data)
        
      for ip in ips:
        conn = sqlite3.connect('../database/ip_addresses.db')
        c = conn.cursor()

        c.execute("select * from ip_service where ip='" + ip + "'")
        results = c.fetchall()

        service = ''
        for result in results:
          if service == '':
            service = result[1]
          else:
            service += ',' + result[1]

        if service == '':
          service = 'benign'

        writer.writerow([filename, ip, service, ips[ip][0], ips[ip][1]])
    except (ValueError):
      print(pcap + ' is not a pcap file.')