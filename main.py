import signal
import subprocess
import sys
import time

gosniffer_path = "gosniffer.exe"
inerface = "Ethernet"
directory = "pcap"

parameters = ["--i", inerface, "--d", directory]
process = subprocess.Popen([gosniffer_path] + parameters)


time.sleep(5)

if sys.platform == "win32":
    process.send_signal(signal.CTRL_BREAK_EVENT)
else:
    process.send_signal(signal.SIGINT)
