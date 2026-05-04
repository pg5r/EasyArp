import os
import subprocess
import platform

os_name = platform.system()

def CopySelf():
    os.chdir("..")
    if os_name.lower() == "windows":
        subprocess.run(["start", "launcher.bat"], shell=True)
    else:
        subprocess.run(["bash", "launcher.sh"])
