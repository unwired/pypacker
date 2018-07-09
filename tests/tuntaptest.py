import time
import threading

from pypacker.layer3 import ip
from pypacker.tuntap import TunInterface
tundev1 = TunInterface(tun_iface_name="tun0", create_ondemand=True)
tundev2 = TunInterface(tun_iface_name="tun1", create_ondemand=True)

"""
if ipaddress is not None:
	output = subprocess.getoutput("ip addr add %s dev %s" % (ipaddress, iface_name))
	logger.debug("Output was: %s", output)
"""


def read_cycler(tun_1, tun2, name, states):
	print("starting cycler %s" % name)

	while states[0]:
		try:
			bts = tun_1.read()
			tun2.write(bts)
			print("Sending %s" % name)
		except ValueError:
			break
		"""
		try:
			pkt_ip = ip.IP(bts)
			print("%s: %s" % name)
		except:
			print(bts)
		"""


states = [True]
cycler1 = threading.Thread(target=read_cycler, args=[tundev1, tundev2, "1to2", states])
cycler2 = threading.Thread(target=read_cycler, args=[tundev2, tundev1, "2to1", states])
cycler1.start()
cycler2.start()

try:
	print("joining")
	cycler1.join()
	cycler2.join()
	states[0] = False
	print("finished joining")
except:
	pass
print("Closing interfaces!")
tundev1.close(destroy_interface=True)
tundev2.close(destroy_interface=True)
