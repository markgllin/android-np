import socket
import dpkt
import csv
import sqlite3
import ipaddress
import os

from multiprocessing.dummy import Pool as ThreadPool 

def categorize_address(frame):
  extrnl_ip = ''

  if ipaddress.ip_address(frame[0]).is_private:
    extrnl_ip = frame[1]
  else:
    extrnl_ip = frame[0]

  conn = sqlite3.connect('database/ip_addresses.db')
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
    return [(extrnl_ip, 'benign') + frame]
  
  return [(extrnl_ip, service) + frame]


with open('summary.csv', 'ab+') as csvfile:
  writer = csv.writer(csvfile, delimiter=',', quoting=csv.QUOTE_MINIMAL)
  writer.writerow(['Filename', 'Init. Timestamp', 'Fin. Timestamp', 'Δtime (s)', 'Δtime (min)', '# of Frames'])

for pcap in os.listdir('pcaps/'):
  filename = os.path.join('pcaps/', pcap)
  print('Parsing ' + filename + '...')

  frames = []
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

      framesize = len(data)
      frames.append( (src_ip, dst_ip, framesize, ts) )

  pool = ThreadPool(15)
  results = pool.map(categorize_address, frames)
  pool.close()
  pool.join()

  flat_results = [item for sublist in results for item in sublist]

  with open('summary.csv', 'ab+') as csvfile:
    writer = csv.writer(csvfile, delimiter=',', quoting=csv.QUOTE_MINIMAL)
    init_ts = flat_results[0][-1]
    end_ts = flat_results[-1][-1]
    delta_time_s = end_ts - init_ts
    delta_time_min = delta_time_s/60
    writer.writerow([pcap, flat_results[0][-1], flat_results[-1][-1], delta_time_s, delta_time_min, len(flat_results)])


  with open('results/' + pcap + '.csv', 'wb') as csvfile:
    writer = csv.writer(csvfile, delimiter=',', quoting=csv.QUOTE_MINIMAL)
    writer.writerow(['Destination', 'Service', 'Src IP', 'Dst IP', 'Frame Size', 'Timestamp'])
    
    for result in flat_results:
      writer.writerow(result)