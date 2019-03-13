import sqlite3
import socket
import os
from multiprocessing.dummy import Pool as ThreadPool 

global table_name

def insert_dns_result(hostname):
  conn = sqlite3.connect('db_addresses.db')
  c = conn.cursor()

  try:
    ip = socket.gethostbyname(hostname)

    c.execute("INSERT INTO " + table_name + " VALUES ('" + ip + "','" + hostname + "')")
    conn.commit()
    conn.close()
  except socket.gaierror:
    conn.close()
    return hostname


conn = sqlite3.connect('db_addresses.db')
c = conn.cursor()

for directory in os.listdir('../lists'):

  #read directory
  dir_category = os.path.join('../lists', directory)
  table_name = directory

  #create table
  c.execute("CREATE TABLE if not exists " + table_name + " (ip text, hostname text)")
  print("Creating table for " + table_name + "...")

  hosts = []
  for listing in os.listdir(dir_category):
    filename = os.path.join(dir_category, listing)
    
    print("\tReading " + filename)
    with open(filename, "r") as file:
      for hostname in file:
        hosts.append(hostname.strip())

  pool = ThreadPool(20)
  unhandled_hosts = pool.map(insert_dns_result, set(hosts))
  pool.close()
  pool.join()
  

conn.close()

f = open('unhandled_hosts.txt', 'a')
for hostname in unhandled_hosts:
  f.write(hostname)
f.close()

