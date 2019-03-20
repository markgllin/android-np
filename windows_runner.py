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

############  D:\"Program Files"\Python27\python .\test_runner.py 4

import subprocess
import time
import os
import sys

interface = sys.argv[1]

# for apk in os.listdir('apks/'):
#   print(apk)
#   print("adb shell monkey -s 601 --pct-syskeys 0 --throttle 1000 -p " + apk[:-4] + " 10")

sys.stdout = open('.\monkey_tests_results.txt', 'w')

for apk in os.listdir('apks/'):
	print("Testing " + apk + "...")

	# install app
	print("\tInstalling apk...")
	os.system("adb install apks/" + apk)

	# launch the app
	monkey_output = subprocess.getoutput("adb shell monkey -s 1234 -p " + apk[:-4] + " 1")
	print(monkey_output)
	time.sleep(10)  # wait 10 seconds after launch to fully launch

	# lock the screen
	activity_names = subprocess.getoutput("adb shell am stack list")
	activity_names = activity_names.split('\n')
	activity_names = [line for line in activity_names if "taskId" in line]
	
	my_activity = [line for line in activity_names if apk[:-4] in line]
	my_activity_id = my_activity[0].split("=")[1].split(":")[0]
	
	os.system("adb shell am task lock " + str(my_activity_id))

	#start network capture interface
	print("\tStarting tshark...")
	tshark_process = subprocess.Popen("tshark -i " + interface + " -a duration:900 -w pcaps/" + apk + ".pcap", shell=True)

	# sleep for 10 seconds before starting monkey
	time.sleep(10)

	# start monkey on app
	print("\tStarting Monkey...")
	monkey_output = subprocess.getoutput("adb shell monkey -s 1234 --throttle 100 -p " + apk[:-4] + " 25000")
	print(monkey_output)
	print("\tDone Monkey-ing around :)")

	# sleep for 10 seconds after monkey is done
	time.sleep(10)

	# wait for tshark process to finish
	print("\tChecking if tshark process exited...")
	wait = True
	while wait:
		poll = tshark_process.poll()
		if poll != None: wait = False

	# unlock the screen
	os.system("adb shell am task lock stop")  

	# uninstall package
	print("\tUninstalling apk...")
	os.system("adb uninstall " + apk[:-4])