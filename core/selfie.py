import os
import sys
import subprocess
import signal

def CopySelf():
    subprocess.run("cd ..", shell=True)
    subprocess.run(["start", "launcher.bat"], shell=True)