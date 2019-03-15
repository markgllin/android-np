# #################################################################
# What this script does:
#   1. install app
#   2. start network capture interface
#   3. start monkey on app
#   4. run for 30 min
#   5. stop network capture
#   6. uninstall app
#
# Initial setup required:
#   1. apks to test should be in the dir 'apks/' and have the naming convention '*-1.apk'
#   2. have a dir calls 'pcaps/' created as that's where resulting network captures will be saved
#   3. Find the network interface that the phone is connected to
#       a. `tshark -D` (should look something like en0 or eth0)
#   4. Run script from the root dir
#       a. `python runner.py [network interface]`
#           e.g. `python runner.py en0`
#   
# #################################################################
# Useful info:
# 
# How to extract apk from phone:
#   1. `adb shell pm list packages` to find package name of app to pull
#       a. `| grep` if there's too much shit (which there likely will be)
#   2. `adb shell pm path <package name>` to find path where apk is located on phone
#   3.  `adb pull /path/to/apk </path/to/save/apk>`
#
# Monkey:
#     adb shell monkey -s 601 --pct-syskeys 0 --throttle 1000 -p <package_name> 1800
#       -s:                seed = 601
#       --pct-syskeys 0:   system key events never happen (volume, home, back, etc)
#       --throttle 1000:   1000ms between each event
#       -p <package_name>: specifies the package to run the events on (for example, com.reddit.frontpage)
#       1800:              number of events 


import subprocess
import time
import os

interface = sys.argv[1]

for apk in os.listdir('apks/'):
  print "Testing " + apk + "..."

  #install app
  print "\tInstalling apk..."
  os.system("adb install apks/" + apk)

  #start network capture interface
  print "\tStarting tshark..."
  tshark_process = subprocess.Popen("tshark -i " + interface + " -a duration:1800 -w pcaps/" + apk + ".pcap", shell=True)

  # sleep for 25 seconds before starting app
  time.sleep(25)

  # start monkey on app
  print "\tStarting Monkey..."
  os.system("adb shell monkey -s 601 --pct-syskeys 0 --throttle 1000 -p apks/" + apk + " 1750")
  print "\tDone Monkey-ing around :)"

  # sleep for 25 seconds after monkey is done
  time.sleep(25)

  # wait for tshark process to finish
  print "\tChecking if tshark process exited..."
  wait = True
  while wait:
    poll = tshark_process.poll()
    if poll != None: wait = False

  # uninstall package
  print "\tUninstalling apk..."
  os.system("adb uninstall " + apk.replace("-1.apk", ""))