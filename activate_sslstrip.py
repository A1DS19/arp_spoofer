import subprocess

subprocess.run(["sudo", "bettercap", "-iface", "wlan0", "-caplet", "hstshijack/hstshijack"])
