import time
import threading

from pypacker.layer3 import ip
from pypacker import tuntap

ip_src = "12.34.56.1"
ip_dst = "12.34.56.2"

lt = tuntap.LocalTunnel(ip_src=ip_src, ip_dst=ip_dst)
lt.set_state(True)

try:
	time.sleep(9999)
except:
	pass
lt.set_state(False)
