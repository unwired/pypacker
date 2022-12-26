# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
import time

from pypacker import psocket
from pypacker.layer12 import arp, ethernet, ieee80211, prism
from pypacker.layer3 import ip, icmp
from pypacker.layer4 import udp, tcp

eth0 = ethernet.Ethernet() + ip.IP() + tcp.TCP(sport=12345, dport=65535) + b"Test123AAAAAAAAAAAAAa"
psock = psocket.SocketHndl(iface_name="wlp3s0", timeout=10)

while True:
	print("Sending")
	psock.send(eth0.bin())
	time.sleep(1)
psock.close()
