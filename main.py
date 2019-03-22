# ad traffic vs tracking traffic vs both traffic vs benign
# # of unique ips
# amount of data per traffic category
# # of shared ips
# % encrypted over https vs http

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
  writer.writerow(
    [
      'Filename',
      'Init. Timestamp', 
      'Fin. Timestamp', 
      'time (s)', 
      'time (min)', 
      'Total # of Frames', 
      'Begnign Frames', 
      'Ad Frames', 
      'Tracking Frames', 
      'Ad/Tracking Frames', 
      'Benign Traffic Size', 
      'Ad Traffic Size', 
      'Tracking Traffic Size', 
      'Ad/Tracking Traffic Size',
      'Benign IPs',
      'Ad IPs',
      'Tracking IPs',
      'Ad/Tracking IPs'
      ]
  )

for pcap in os.listdir('pcaps/Android9.0/'):
  if pcap.startswith('.'): next

  filename = os.path.join('pcaps/Android9.0/', pcap)
  print('Parsing ' + filename + '...')

  frames = []

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

        framesize = len(data)
        frames.append( (src_ip, dst_ip, framesize, ts) )


    pool = ThreadPool(15)
    results = pool.map(categorize_address, frames)
    pool.close()
    pool.join()

    flat_results = [item for sublist in results for item in sublist]


    benign_ips = []
    ad_ips = []
    tracking_ips = []
    ad_tracking_ips = []
    benign_traffic_size = 0
    ad_traffic_size = 0
    tracking_traffic_size = 0
    ad_tracking_traffic_size = 0
    benign_frames = 0
    ad_frames = 0
    tracking_frames = 0
    ad_tracking_frames = 0

    with open('results/' + pcap + '.csv', 'wb') as csvfile:
      writer = csv.writer(csvfile, delimiter=',', quoting=csv.QUOTE_MINIMAL)
      writer.writerow(['Destination', 'Service', 'Src IP', 'Dst IP', 'Frame Size', 'Timestamp'])
      
      for result in flat_results:
        writer.writerow(result)

        service = result[1]
        ip = result[3]
        frame_size = result[4]

        ads = False
        tracking = False
        if 'ad' in service:
          ads = True
        
        if 'track' in service:
          tracking = True

        if ads and tracking:
          ad_tracking_ips.append(ip)
          ad_tracking_traffic_size += frame_size
          ad_tracking_frames += 1
        elif ads:
          ad_ips.append(ip)
          ad_traffic_size += frame_size
          ad_frames += 1
        elif tracking:
          tracking_ips.append(ip)
          tracking_traffic_size += frame_size
          tracking_frames += 1
        else:
          benign_ips.append(ip)
          benign_traffic_size += frame_size
          benign_frames += 1

        

    with open('summary.csv', 'ab+') as csvfile:
      writer = csv.writer(csvfile, delimiter=',', quoting=csv.QUOTE_MINIMAL)
      init_ts = flat_results[0][-1]
      end_ts = flat_results[-1][-1]
      delta_time_s = end_ts - init_ts
      delta_time_min = delta_time_s/60
      writer.writerow([
        pcap, 
        flat_results[0][-1], 
        flat_results[-1][-1], 
        delta_time_s, 
        delta_time_min, 
        len(flat_results), 
        benign_frames,
        ad_frames,
        tracking_frames,
        ad_tracking_frames,
        benign_traffic_size,
        ad_traffic_size,
        tracking_traffic_size,
        ad_tracking_traffic_size,
        len(set(benign_ips)),
        len(set(ad_ips)),
        len(set(tracking_ips)),
        len(set(ad_tracking_ips)),
        ])
  except (ValueError):
    print(pcap + ' is not a pcap file.')
