import time
import threading

from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp
from pypacker import tuntap, utils

ip_src = "192.168.12.34"
ip_src2 = "192.168.12.35"
ip_dst = "192.168.12.35"

iface_internet = "enp0s31f6"
iface_tap = "tapA"
#lt.set_state(True)

print("Creating interface")
lt = tuntap.TuntapInterface(iface_tap, ifacetype=tuntap.TYPE_TAP, ip_src=ip_src, ip_dst=ip_dst)

time.sleep(1)
print("Getting config")
ip_gw = utils.get_gwip_for_iface(iface_internet)
mac_gw = utils.get_arp_cache_entry(ip_gw)
mac_tap = utils.get_mac_for_iface(iface_tap)
mac_inet = utils.get_mac_for_iface(iface_internet)
print("%s %s %s" % (ip_gw, mac_gw, mac_tap))

#pkt0 = ethernet.Ethernet(dst_s=mac_tap, src_s=mac_tap) + ip.IP(src_s=ip_src2, dst_s="172.217.16.195") + tcp.TCP(dport=1234)
pkt0 = ethernet.Ethernet(dst_s=mac_tap, src_s="b6:bd:6c:40:6f:01") + ip.IP(src_s=ip_src2, dst_s="172.217.16.195") + tcp.TCP(dport=443)


time.sleep(2)

print("Sending")
lt.write(pkt0.bin())

try:
	time.sleep(9999)
except:
	pass

lt.close()