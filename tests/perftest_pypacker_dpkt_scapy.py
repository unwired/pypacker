import time


"""
pkt_eth_ip_tcp = Ethernet() + ip.IP() + tcp.TCP(dport=80)
http_l = http.HTTP(startline=b"GET / HTTP/1.1", hdr=[(b"header1", b"value1")], body_bytes=b"Content123")
pkt_eth_ip_tcp += http_l
pkt_eth_ip_tcp_bts = pkt_eth_ip_tcp.bin()
"""
pkt_eth_ip_tcp_bts = b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x08\x00E\x00\x00S\x00\x00\x00\x00@\x06z\xa6' \
	b'\x00\x00\x00\x00\x00\x00\x00\x00\xde\xad\x00P\xde\xad\xbe\xef\x00\x00\x00\x00P\x02\xff\xff\x1a' \
	b'\xfa\x00\x00GET / HTTP/1.1header1: value1\r\n\r\nContent123'

LOOP_CNT = 10000

print("Comparing pypacker, dpkt and scapy performance (parsing Ethernet + IP + TCP + HTTP)")
print("")
print("nr = new results on this machine")
print("rounds per test: %d" % LOOP_CNT)

try:
	from pypacker.layer12.ethernet import Ethernet
	from pypacker.layer3 import ip
	from pypacker.layer4 import tcp
	from pypacker.layer567 import http

	print(">>> testing pypacker parsing speed")

	t_start = time.time()

	for cnt in range(LOOP_CNT):
		pkt1 = Ethernet(pkt_eth_ip_tcp_bts)
		# dpkt does not parse TCP content but pypacker does
		# -> access layer ip to get comparable result
		pkt2 = pkt1.higher_layer
		bts = pkt2.body_bytes
	t_end = time.time()

	print("nr = %d p/s" % (LOOP_CNT / (t_end - t_start)))
except Exception as ex:
	print("Could not execute pypacker tests: %r" % ex)

try:
	import dpkt
	print(">>> testing dpkt parsing speed")
	EthernetDpkt = dpkt.ethernet.Ethernet

	t_start = time.time()

	for cnt in range(LOOP_CNT):
		pkt1 = EthernetDpkt(pkt_eth_ip_tcp_bts)
		pkt2 = pkt1.ip
		bts = pkt2.data
	t_end = time.time()

	print("nr = %d p/s" % (LOOP_CNT / (t_end - t_start)))
except Exception as ex:
	print("Could not execute dpkt tests: %r" % ex)

try:
	from scapy.all import *

	print(">>> testing scapy parsing speed")

	t_start = time.time()

	for _ in range(LOOP_CNT):
		pkt1 = Ether(pkt_eth_ip_tcp_bts)
		pkt2 = pkt1[IP]
		bts = "%s" % pkt1

	t_end = time.time()

	print("nr = %d p/s" % (LOOP_CNT / (t_end - t_start)))
except Exception as ex:
	print("Could not execute scapy tests: %r" % ex)
