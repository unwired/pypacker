import time
import threading
import sys

from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer3.icmp import ICMP
from pypacker import tuntap, utils
from pypacker import psocket

"""
Packets from TUN/TAP are not forwarded? (fd -> tun0 -> local [the end])
sysctl -w net.ipv4.conf.all.route_localnet=1
sysctl -ar 'rp_filter'
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o tunA0 -j MASQUERADE
ip -s -s neigh flush all

> For tap interface (eg icmp request/response): [dev] -> tap0 -> wlp3s0 (masq) -> [internet]
> This setup works just fine!
MAC of source (dev writing dev unit) has to be manually added
	arp -s 192.168.2.123 12:23:34:45:56:67

Masquerade traffic to internet
	iptables -t nat -A POSTROUTING -o wlp3s0 -j MASQUERADE

write to dev:
	Eth: dst_s=mac_tap0, src_s="12:23:34:45:56:67"
	IP: src_s="192.168.2.123", dst_s=internet_ip


"""


ip_tuntapiface = "192.168.2.9"
#tunnel_dst = "192.168.1.165"
#tunnel_dst = "192.168.2.1"
#ip_src = ip_tun
#ip_dst = "78.46.70.188"

"""
tti = tuntap.TuntapInterface(
	"tunA0",
	devnode="/dev/net/tunA",
	ifacetype=tuntap.TYPE_TUN,
	ip_src=tunnel_src,
	ip_dst=tunnel_dst)
# For tun
icmp_req1 = ip.IP(src_s=ip_src, dst_s=ip_dst, p=1) +\
	ICMP(type=8) +\
	ICMP.Echo(id=123, seq=1, body_bytes=b"foobar")

"""
tti = tuntap.TuntapInterface(
	"tapA0",
	devnode="/dev/net/tapA",
	ifacetype=tuntap.TYPE_TAP,
	ip_src=ip_tuntapiface)

# For tap
mac_tap0 = utils.get_mac_for_iface("tapA0")
print(mac_tap0)

icmp_req2 = ethernet.Ethernet(dst_s=mac_tap0, src_s="12:23:34:45:56:67") +\
	ip.IP(src_s="192.168.2.123", dst_s="172.217.18.3", p=1) +\
	ICMP(type=8) +\
	ICMP.Echo(id=123, seq=1, body_bytes=b"foobar")
print("Starting main loop")


def read_cycler(tti_obj):
	while True:
		bts = tti_obj.read()
		try:
			print(ethernet.Ethernet(bts))
		except:
			pass
		#print("Got a packet...")
th_read = threading.Thread(target=read_cycler, args=[tti])
th_read.start()

while True:
	#print("Sending request")
	tti.write(icmp_req2.bin())
	time.sleep(4)


tti.close()
