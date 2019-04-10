import dpkt
import socket
import sqlite3
import ipaddress
import os
import sys
import csv

from multiprocessing.dummy import Pool as ThreadPool 

global adtelemetry
global adlist
global telemetrylist

def readHostFromDir(dir):
  hosts = set()
  for file in os.listdir(dir):
    listname = os.path.join(dir, file)
    print "reading file" + listname

    hosts = hosts.union(readHostFile(listname))
  return hosts

def readHostFile(filename):
  hosts = set()
  file = open(filename, "r")
  lines = file.readlines()

  for line in lines:
    hosts.add(line.rstrip())
  
  return hosts

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

def get_ip_addr_type(ether):
  if ether.type == dpkt.ethernet.ETH_TYPE_IP:
    return socket.AF_INET
  elif ether.type == dpkt.ethernet.ETH_TYPE_IP6:
    return socket.AF_INET6
  else:
    return None

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

def get_domain_name(tcp):
  try:
    http = dpkt.http.Request(tcp.data)
    return http.headers['host']
  except(dpkt.dpkt.UnpackError, TypeError, KeyError):
    return ''

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
  service = ''
  domain = packet_details[4]
  if domain in adtelemetry:
    service = 'ad,tracking'
  elif domain in adlist:
    service = 'ad'
  elif domain in telemetrylist:
    service = 'tracking'
  else:
    service = 'benign'
  
  packet_details.append(service)
  return packet_details

def get_associated_services(packet_details):
  domain = ''
  db = '/Users/marlin2/Documents/school/CPSC641/project/android-np/database/db_addresses.db'
  conn = sqlite3.connect(db)
  c = conn.cursor()

  ip = packet_details[3]

  c.execute("select * from domains where ip='" + ip + "'")
  results = c.fetchall()

  service = set()
  if len(results) == 0:
    print "Could not find " + ip + " in db..."
    domain = ip
  else:
    for result in results:
      domain = result[1]

      if domain in adtelemetry:
        service.add('ad')
        service.add('telemetry')
        break
      elif domain in adlist:
        service.add('ad')
      elif domain in telemetrylist:
        service.add('telemetry')

  str_service = ''
  if len(service) == 2:
    str_service = 'ad,tracking'
  elif len(service) == 1:
    str_service = next(iter(service))
  else:
    str_service = 'benign'

  packet_details[4] = domain
  packet_details.append(str_service)
  return packet_details


adlist = readHostFromDir('lists/ad_hosts/')
telemetrylist = readHostFromDir('lists/tracking_hosts/')

adtelemetry = adlist.intersection(telemetrylist)
adlist -= adtelemetry
telemetrylist -= adtelemetry


pcapng_or_dir = sys.argv[1]
baseline_file = sys.argv[2]
pcapngs = get_pcapngs_from_dir(pcapng_or_dir)
base_ips = get_baseline_ips(baseline_file)


with open('summary_nongames.csv', 'w') as summaryfile:
  summary_writer = csv.writer(summaryfile, delimiter=',', quoting=csv.QUOTE_MINIMAL)
  summary_writer.writerow(
    [
      'Package Name',
      'Benign Domains', 'Benign IPs', 'Benign Traffic', 
      'Ad Domains', 'Ad IPs', 'Ad Traffic',  
      'Tracking Domains', 'Tracking IPs', 'Tracking Traffic',
      'HTTPS Benign Domains', 'HTTPS Benign IPs', 'HTTPS Benign Traffic', 
      'HTTPS Ad Domains', 'HTTPS Ad IPs', 'HTTPS Ad Traffic',  
      'HTTPS Tracking Domains', 'HTTPS Tracking IPs', 'HTTPS Tracking Traffic',
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

    sus_ad_ips = []
    sus_ad_traffic = 0
    sus_ad_domains = ''

    sus_benign_domains = ''
    sus_benign_ips = []
    sus_benign_traffic = 0
    
    sus_tracking_ips = []
    sus_tracking_traffic = 0
    sus_tracking_domains = ''
    
    csv_file = os.path.splitext(os.path.basename(pcapng))[0]
    with open('nongames/' + csv_file + '.csv', 'w') as csvfile:
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
      

      writer.writerow(['HTTPS'])
      writer.writerow(
        [
          'timestamp',  'src ip', 
          'dst ip'   ,  'Services',  
          'Domains', 'frame size', 
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
        domain = row[4]
        frame_size = row[5]
        service = row[6]

        if 'benign' in service:
          sus_benign_ips.append(external_ip)
          sus_benign_traffic += frame_size
          if sus_benign_domains == '':
            sus_benign_domains = domain
          elif domain not in sus_benign_domains:
            sus_benign_domains += ',' + domain      
        else:
          if 'ad' in service:
            sus_ad_ips.append(external_ip)
            sus_ad_traffic += frame_size
            if sus_ad_domains == '':
              sus_ad_domains = domain
            elif domain not in sus_ad_domains:
              sus_ad_domains += ',' + domain
          
          if 'tracking' in service:
            sus_tracking_ips.append(external_ip)
            sus_tracking_traffic += frame_size
            if sus_tracking_domains == '':
              sus_tracking_domains = domain
            elif domain not in sus_tracking_domains:
              sus_tracking_domains += ',' + domain

        writer.writerow([
          timestamp, src_ip,
          dst_ip, service,
          domain, frame_size
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
        sus_benign_domains, len(sus_benign_ips), sus_benign_traffic,
        sus_ad_domains, len(sus_ad_ips), sus_ad_traffic,
        sus_tracking_domains, len(sus_tracking_ips), sus_tracking_traffic,
      ]
    )   