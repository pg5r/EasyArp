import os
import subprocess
import platform

os_name = platform.system()

def CopySelf():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if os_name.lower() == "windows":
        script_path = os.path.join(base_dir, "launcher.bat")
        subprocess.run(["start", script_path], shell=True)
    else:
        script_path = os.path.join(base_dir, "launcher.sh")
        subprocess.run(["bash", script_path])
