
import subprocess
import time
import os
import sys

package_names = subprocess.getoutput("adb shell pm list packages -3")
package_names = list(filter(None, package_names.split('\n')))
package_names = [i.split(':', 1)[1] for i in package_names]
# print(package_names)

apk_path = "\"D:\School\CPSC 601\APKs"

# # pull all the packages
# for package in package_names:
#     print("------ " + package + " ------")
#     package_path = subprocess.getoutput("adb shell pm path " + package)
#     package_path = package_path.rstrip()
#     package_path = package_path[8:]

    os.system("adb pull " + package_path + " " + apk_path + "\\" + package + ".apk\"")

dont_uninstall = ["org.fdroid.fdroid", "org.thisisafactory.simiasque", 
                  "de.robv.android.xposed.installer"]
to_uninstall = [x for x in package_names if x not in dont_uninstall]

# uninstall
for package in to_uninstall:
    os.system("adb uninstall " + package)
