# Service
# Domain/hostname
# Ip
# Frame size at point in time
# timestamp
# Src ip
# Dst ip

import dpkt
import socket
import sqlite3
import ipaddress
import os
import sys
import csv

from multiprocessing.dummy import Pool as ThreadPool 

def get_ip_addr_type(ether):
  if ether.type == dpkt.ethernet.ETH_TYPE_IP:
    return socket.AF_INET
  elif ether.type == dpkt.ethernet.ETH_TYPE_IP6:
    return socket.AF_INET6
  else:
    return None

def get_pcapngs_from_dir(pcapng_or_dir):
  pcapngs = []
  if os.path.isfile(pcapng_or_dir):
    pcapngs.append(pcapng_or_dir)
  elif os.path.isdir(pcapng_or_dir):
    for pcapng in os.listdir(pcapng_or_dir):
      if 'pcap' not in pcapng: continue
      path = os.path.join(pcapng_or_dir, pcapng)
      pcapngs.append(path)

  return pcapngs

def get_domain_name(tcp):
  try:
    http = dpkt.http.Request(tcp.data)
    return http.headers['host']
  except(dpkt.dpkt.UnpackError, TypeError, KeyError):
    return ''

def get_ips(ether):
  external_ip = ''
  addr_family = get_ip_addr_type(ether)
  if addr_family == None: return '', '', ''

  ip = ether.data
  src_ip = socket.inet_ntop(addr_family, ip.src)
  dst_ip = socket.inet_ntop(addr_family, ip.dst)
  external_ip = get_external_ip(src_ip, dst_ip)

  return src_ip, dst_ip, external_ip

def get_external_ip(src, dst):
  if ipaddress.ip_address(src).is_private and ipaddress.ip_address(dst).is_private:
    external_ip = ''
  elif ipaddress.ip_address(src).is_private:
    external_ip = dst
  else:
    external_ip = src

  return external_ip

def parse_pcap(pcapng, base_ips):
  print("Parsing " + pcapng + '...')
  try:
    http_row = []
    https_row = []
    for ts, data in dpkt.pcapng.Reader(file(pcapng, "rb")):
      ether = dpkt.ethernet.Ethernet(data)

      src_ip, dst_ip, external_ip = get_ips(ether)
      if external_ip == '' or external_ip in base_ips: continue

      tcp = ether.data.data
      domain = get_domain_name(tcp)
      if domain == '': 
        https_row.append([ts, src_ip, dst_ip, external_ip, 'encrypted', len(data)])
      else:
        http_row.append([ts, src_ip, dst_ip, external_ip, domain, len(data)])

    return http_row, https_row
  except(ValueError):
    return ''

def get_service(packet_details):
  database = '/Users/marlin2/Documents/school/CPSC641/project/android-np/database/ip_addresses.db'
  domain = packet_details[4]

  conn = sqlite3.connect(database)
  c = conn.cursor()

  c.execute("select * from ip_address where hostname='" + domain + "' and used=1")
  results = c.fetchall()

  if len(results) == 0:
    c.execute("select * from ip_address where hostname='" + domain + "'")
    results = c.fetchall()

  service = ''
  for result in results:
    if service == '':
      service = result[2]
    else:
      service += ',' + result[2]

  if service == '':
    service = 'benign'
  
  packet_details.append(service)
  return packet_details

def get_associated_services(packet_details):
  database = '/Users/marlin2/Documents/school/CPSC641/project/android-np/database/ip_addresses.db'
  conn = sqlite3.connect(database)
  c = conn.cursor()

  ip = packet_details[3]
  c.execute("select * from ip_address where ip='" + ip + "' and used=1")
  results = c.fetchall()

  if len(results) == 0:
    c.execute("select * from ip_address where ip='" + ip + "'")
    results = c.fetchall()

  service = ''
  hostnames = ''
  for result in results:
    if service == '':
      service = result[2]
    else:
      if result[2] not in service:
        service += ',' + result[2]
    
    if hostnames == '':
      hostnames = result[1]
    else:
      if result[1] not in hostnames:
        hostnames += ',' + result[1]

  if service == '':
    service = 'benign'
  
  packet_details.append(service)
  packet_details.append(hostnames)
  return packet_details

def get_baseline_ips(basefile):
  base_ips = []

  print("Reading " + basefile + " for baseline ips...")
  for ts, data in dpkt.pcapng.Reader(file(basefile, "rb")):
    ether = dpkt.ethernet.Ethernet(data)

    src_ip, dst_ip, external_ip = get_ips(ether)
    if external_ip == '': continue
    base_ips.append(external_ip)
  
  base_ips = list(set(base_ips))
  print("\t found " + str(len(base_ips)) + " unique ips in baseline.")
  return base_ips

pcapng_or_dir = sys.argv[1]
baseline_file = sys.argv[2]

pcapngs = get_pcapngs_from_dir(pcapng_or_dir)
base_ips = get_baseline_ips(baseline_file)

with open('summary.csv', 'ab+') as summaryfile:
  summary_writer = csv.writer(summaryfile, delimiter=',', quoting=csv.QUOTE_MINIMAL)
  summary_writer.writerow(
    [
      'Package Name',
      'Benign Domains', 'Benign IPs', 'Benign Traffic', 
      'Ad Domains', 'Ad IPs', 'Ad Traffic',  
      'Tracking Domains', 'Tracking IPs', 'Tracking Traffic',
      'Suspected Benign IPs', 'Suspected Benign Traffic',
      'Suspected Ad Domains', 'Suspected Ad IPs', 'Suspected Ad Traffic',
      'Suspected Tracking Domains', 'Suspected Tracking IPs', 'Suspected Tracking Traffic'
      ]
  )

  for pcapng in pcapngs:
    http_rows, https_rows = parse_pcap(pcapng, base_ips)

    benign_domains = ''
    benign_ips = []
    benign_traffic = 0
    ad_domains = ''
    ad_ips = []
    ad_traffic = 0
    tracking_domains = ''
    tracking_ips = []
    tracking_traffic = 0
    sus_ad_domains = ''
    sus_ad_ips = []
    sus_ad_traffic = 0
    sus_tracking_domains = ''
    sus_tracking_ips = []
    sus_tracking_traffic = 0
    sus_benign_ips = []
    sus_benign_traffic = 0

    csv_file = os.path.splitext(os.path.basename(pcapng))[0]
    with open(csv_file + '.csv', 'ab+') as csvfile:
      writer = csv.writer(csvfile, delimiter=',', quoting=csv.QUOTE_MINIMAL)
      writer.writerow(
        [
          'timestamp',  'src ip', 
          'dst ip'   ,  'service',
          'domain'   ,  'frame size', 
          ]
      )

      pool = ThreadPool(20)
      results = pool.map(get_service, http_rows)
      pool.close()
      pool.join()

      print("\twriting http_rows...")

      for row in results:
        timestamp = row[0]
        src_ip = row[1]
        dst_ip = row[2]
        domain = row[4]
        external_ip = row[3]
        frame_size = row[5]
        service = row[6]

        if 'benign' in service:
          benign_ips.append(external_ip)
          benign_traffic += frame_size
          if benign_domains == '':
            benign_domains = domain
          elif domain not in benign_domains:
            benign_domains += ',' + domain      
        else:
          if 'ad' in service:
            ad_ips.append(external_ip)
            ad_traffic += frame_size
            if ad_domains == '':
              ad_domains = domain
            elif domain not in ad_domains:
              ad_domains += ',' + domain
          
          if 'tracking' in service:
            tracking_ips.append(external_ip)
            tracking_traffic += frame_size
            if tracking_domains == '':
              tracking_domains = domain
            elif domain not in tracking_domains:
              tracking_domains += ',' + domain

        writer.writerow([
          timestamp, src_ip,
          dst_ip, service,
          domain, frame_size
        ])
      


      writer.writerow(
        [
          'timestamp',  'src ip', 
          'dst ip'   ,  'Associated Services',  
          'Associated Domains', 'frame size', 
          ]
      )

      pool = ThreadPool(20)
      results = pool.map(get_associated_services, https_rows)
      pool.close()
      pool.join()

      print("\twriting https_rows...")

      for row in results:
        timestamp = row[0]
        src_ip = row[1]
        dst_ip = row[2]
        external_ip = row[3]
        frame_size = row[5]
        service = row[6]
        hostnames = row[7]

        if ('ads' not in service) and ('tracking' not in service):
          if 'ads' in service:
            sus_ad_ips.append(external_ip)
            sus_ad_traffic += frame_size
            if sus_ad_domains == '':
              sus_ad_domains = hostnames
            else:
              for d in hostnames.split(','):
                if d not in sus_ad_domains:
                  sus_ad_domains += ',' + d

          if 'tracking' in service:
            sus_tracking_ips.append(external_ip)
            sus_tracking_traffic += frame_size
            if sus_tracking_domains == '':
              sus_tracking_domains = hostnames
            else:
              for d in hostnames.split(','):
                if d not in sus_tracking_domains:
                  sus_tracking_domains += ',' + d
        else:
          sus_benign_ips.append(external_ip)
          sus_benign_traffic += frame_size

        writer.writerow([
          timestamp, src_ip,
          dst_ip, service,
          hostnames, frame_size
      ])

    benign_ips = list(set(benign_ips))
    ad_ips = list(set(ad_ips))
    tracking_ips = list(set(tracking_ips))
    sus_ad_ips = list(set(sus_ad_ips))
    sus_tracking_ips = list(set(sus_tracking_ips))
    sus_benign_ips = list(set(sus_benign_ips))

    summary_writer.writerow(
      [
        csv_file,
        benign_domains, len(benign_ips), benign_traffic,
        ad_domains, len(ad_ips), ad_traffic,
        tracking_domains, len(tracking_ips), tracking_traffic,
        len(sus_benign_ips), sus_benign_traffic,
        sus_ad_domains, len(sus_ad_ips), sus_ad_traffic,
        sus_tracking_domains, len(sus_tracking_ips), sus_tracking_traffic,
      ]
    )   