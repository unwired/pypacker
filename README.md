<p align="center">
	<img width="105" height="176" src="./pypacker_logo_large.png">
</p>

[![Build Status](https://travis-ci.org/mike01/pypacker.svg?branch=master)](https://travis-ci.org/mike01/pypacker)
[![version](http://img.shields.io/pypi/v/pypacker.svg)](https://pypi.python.org/pypi/pypacker)
[![supported-versions](https://img.shields.io/pypi/pyversions/pypacker.svg)](https://pypi.python.org/pypi/pypacker)
[![supported-implementations](https://img.shields.io/pypi/implementation/pypacker.svg)](https://pypi.python.org/pypi/pypacker)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](LICENSE)

# General information
This is Pypacker: The fastest and simplest low-level packet manipulation library for Python.
See below examples for what you can do with it.

If you like this project you can [![Donate with PayPal](https://www.paypalobjects.com/en_US/i/btn/btn_donate_SM.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=M6GGAXJQCUHVC&source=url) via PayPal.

## What you can do with Pypacker
Create custom Packets (via keywords) or from raw bytes and change their data:

```python
from pypacker.layer3.ip import IP
from pypacker.layer3.icmp import ICMP

# Packet via keywords
ip0 = IP(src_s="127.0.0.1", dst_s="192.168.0.1", p=1) +\
	ICMP(type=8) +\
	ICMP.Echo(id=123, seq=1, body_bytes=b"foobar")

# Packet from raw bytes. ip1_bts can also be retrieved via ip0.bin()
ip1_bts = b"E\x00\x00*\x00\x00\x00\x00@\x01;)\x7f\x00\x00\x01\xc0\xa8\x00\x01\x08\x00\xc0?\x00{\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00foobar"
ip1 = IP(ip1_bts) 
# Change source IPv4 address
ip0.src_s = "1.2.3.4"
# Change ICMP payload
ip0[IP,ICMP,ICMP.Echo].body_bytes = b"foobar2"

# Output packet (similar result for ip1)
print("%s" % ip0)
layer3.ip.IP
        v_hl        : 0x45 = 69 = 0b1000101
        tos         : 0x0 = 0 = 0b0
        len         : 0x2B = 43 = 0b101011
        id          : 0x0 = 0 = 0b0
        off         : 0x0 = 0 = 0b0
        ttl         : 0x40 = 64 = 0b1000000
        p           : 0x1 = 1 = 0b1
        sum         : 0xB623 = 46627 = 0b1011011000100011
        src         : b'\x01\x02\x03\x04' = 1.2.3.4
        dst         : b'\xc0\xa8\x00\x01' = 192.168.0.1
        opts        : []
layer3.icmp.ICMP
        type        : 0x8 = 8 = 0b1000
        code        : 0x0 = 0 = 0b0
        sum         : 0x8E3F = 36415 = 0b1000111000111111
layer3.icmp.Echo
        id          : 0x7B = 123 = 0b1111011
        seq         : 0x1 = 1 = 0b1
        ts          : 0x0 = 0 = 0b0
        bodybytes   : b'foobar2'
```

Read/write packets from/to file (Support only for Wireshark/tcpdump pcap format):

```python
from pypacker import ppcap
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp

preader = ppcap.Reader(filename="packets_ether.pcap")
pwriter = ppcap.Writer(filename="packets_ether_new.pcap", linktype=ppcap.DLT_EN10MB)

for ts, buf in preader:
	eth = ethernet.Ethernet(buf)

	if eth[ethernet.Ethernet, ip.IP, tcp.TCP] is not None:
		print("%d: %s:%s -> %s:%s" % (ts, eth[ip.IP].src_s, eth[tcp.TCP].sport,
			eth[ip.IP].dst_s, eth[tcp.TCP].dport))
		pwriter.write(eth.bin())

pwriter.close()
```

Merge multiple pcap files to one file. Tries to read corrupted pcap files and allows filtering by pypacker callback.
```
from pypacker import ppcap
from pypacker.layer4 import tcp

def filter_accept(bts):
    # Get all TCP packets
    pkt = ethernet.Ethernet(bts)
    return pkt[tcp.TCP] is not None

ppcap.merge_pcaps(["file_in1.pcap", "file_in2.pcap"], "file_out.pcap", filter_accept=filter_accept)
```

Send/receive layer 2 packets:

```python
from pypacker import psocket
from pypacker.layer12 import ethernet

psock = psocket.SocketHndl(timeout=10)

def filter_pkt(pkt):
	return pkt.ip.tcp.sport == 80

# Receive raw bytes
for raw_bytes in psock:
	eth = ethernet.Ethernet(raw_bytes)
	print("Got packet: %r" % eth)
	eth.reverse_address()
	eth.higher_layer.reverse_address()
	# Send bytes
	psock.send(eth.bin())
	# Receive raw bytes
	bts = psock.recv()
	# Send/receive based on source/destination data in packet
	pkts = psock.sr(eth)
	# Use filter to get specific packets
	pkts = psock.recvp(filter_match_recv=filter_pkt)
	# stop on first packet
	break

psock.close()
```

Intercept (and modificate) Packets eg for MITM:

```python
# Add iptables rule:
# iptables -I INPUT 1 -p icmp -j NFQUEUE --queue-balance 0:2
import time

from pypacker import interceptor
from pypacker.layer3 import ip, icmp

# ICMP Echo request intercepting
def verdict_cb(ll_data, ll_proto_id, data, ctx, *args):
	ip1 = ip.IP(data)
	icmp1 = ip1[icmp.ICMP]

	if icmp1 is None or icmp1.type != icmp.ICMP_ECHO:
		return data, interceptor.NF_ACCEPT

	echo1 = icmp1[icmp.ICMP.Echo]

	if echo1 is None:
		return data, interceptor.NF_ACCEPT

	pp_bts = b"PYPACKER"
	print("changing ICMP echo request packet")
	echo1.body_bytes = echo1.body_bytes[:-len(pp_bts)] + pp_bts
	return ip1.bin(), interceptor.NF_ACCEPT

ictor = interceptor.Interceptor()
ictor.start(verdict_cb, queue_ids=[0, 1, 2])
print("now sind a ICMP echo request to localhost: ping 127.0.0.1")
time.sleep(999)
ictor.stop()
```


## Prerequisites
- Python 3.x (CPython, Pypy, Jython or whatever Interpreter)
- Optional: netifaces >=0.10.6 (for utils)
- Optional (for interceptor):
  - CPython
  - Linux based system with kernel support for NFQUEUE target. The config option is at:
	- Networking Options -> Network packet filtering -> Core Netfilter -> NFQUEUE target
  - iptables (alternatively nftables)
    - NFQUEUE related rulez can be added eg "iptables -I INPUT 1 -j NFQUEUE --queue-num 0"
  - libnetfilter_queue library (see http://www.netfilter.org/projects/libnetfilter_queue)

## Installation
Some examples:
- Clone newest version
  - git clone https://gitlab.com/mike01/pypacker.git
  - cd pypacker
  - python setup.py install
- Use pip (synched to master on major version changes)
  - pip install pypacker

## Usage examples
See examples/ and tests/test_pypacker.py.

## Testing
Tests are executed as follows:

1) Add Pypacker directory to the PYTHONPATH.

- cd pypacker
- export PYTHONPATH=$(pwd):$PYTHONPATH

2) execute tests

- python tests/test_pypacker.py

**Performance test results: pypacker**
```
orC = Intel CPU, 4 Cores @ 3GHz, CPython v3.6
orP = Intel CPU, 4 Cores @ 3GHz, PyPy v7.3.0
rounds per test: 10000
=====================================
>>> full packet parsing (Ethernet + IP + TCP + HTTP)
orC = 28300 p/s
orP = 78232 p/s
>>> parsing (IP + ICMP)
orC =  405921 p/s
orP =  1018554 p/s
>>> creating/direct assigning (IP only header)
orC =  166124 p/s
orP =  263307 p/s
>>> bin() without change (IP)
orC =  722147 p/s
orP =  1255403 p/s
>>> output with change/checksum recalculation (IP)
orC =  37826 p/s
orP =  77582 p/s
>>> basic/first layer parsing (Ethernet + IP + TCP + HTTP)
orC =  380642 p/s
orP =  907858 p/s
>>> changing Triggerlist element value (Ethernet + IP + TCP + HTTP)
orC =  303882 p/s
orP =  596451 p/s
>>> changing dynamic field (Ethernet + IP + TCP + HTTP)
orC = 511238 p/s
orP =  1041597 p/s
>>> direct assigning and concatination (Ethernet + IP + TCP + HTTP)
time diff: 0.2921011447906494s
orC = 34229 p/s
orP = 59600 p/s
```

**Performance test results: pypacker vs. dpkt vs. scapy**
```
Comparing pypacker, dpkt and scapy performance (parsing Ethernet + IP + TCP + HTTP)
orC = Intel CPU, 4 Cores @ 3GHz, CPython v3.6
rounds per test: 10000
=====================================
>>> testing pypacker parsing speed
orC = 131770 p/s
>>> testing dpkt parsing speed
(Not working anymore)
>>> testing scapy parsing speed
orC = 2213 p/s
```

# FAQ

If you have any questions: please first read the following point "Is there any documentation?".
For any questions left please file a bug (will be tagged as "questions").

**Q**:	Where should I start learn to use Pypacker?

**A**:	If you allready know Scapy starting by reading the examples should be OK. Otherwise there
	is a general introduction to pypacker included at the doc's which shows the usage and concepts
	of pypacker.

**Q**:	How fast is pypacker?

**A**:	See results above. For detailed results on your machine execute tests.

**Q**:	Is there any documentation?

**A**:	Pypacker is based on code of dpkt, which in turn didn't have any official and very little
	internal code documentation. This made understanding of the internal behaviour tricky.
	After all the code documentation was pretty much extended for Pypacker. Documentation can
	be found in these directories and files:
- examples/ (many examples showing the usage of Pypacker)
- wiki (general intro into pypacker)
- pypacker.py (general Packet structure)

Protocols itself (see layerXYZ) generally don't have much documentation because those are documented
by their respective RFCs/official standards.

**Q**:	Which protocols are supported?

**A**:	Currently minimum supported protocols are:
	Ethernet, Radiotap, IEEE80211, ARP, DNS, STP, PPP, OSPF, VRRP, DTP, IP, ICMP, PIM, IGMP, IPX,
	TCP, UDP, SCTP, HTTP, NTP, RTP, DHCP, RIP, SIP, Telnet, HSRP, Diameter, SSL, TPKT, Pmap, Radius, BGP

**Q**:	How are protocols added?

**A**:  Short answer: Extend Packet class and add the class variable `__hdr__` to define header fields.
        Long answer: See examples/examples_new_protocol.py for a very complete example.

**Q**: How can I contribute to this project?

**A**: Please use the Gitlab bug-tracker for bugs/feature request. Please read the bugtracker for
     already known bugs before filing a new one. Patches can be send via pull request.

**Q**:	Under which license Pypacker is issued?

**A**:	It's the GPLv2 License (see LICENSE file for more information).

**Q**:	Are there any plans to support [protocol xyz]?

**A**:	Support for particular protocols is added to Pypacker as a result of me needing this feature or people contributing
	that support - no formal plans for adding support for particular protocols in particular
	future releases exist. 

**Q**:	There is problem xyz with Pypacker using Windows 3.11/XP/7/8/mobile etc. Can you fix that?

**A**:	The basic features should work with any OS. Optional ones may make trouble (eg interceptor).

**Q**:	Calling copy.deepcopy(some_packet) raises an exception "TypeError: can't pickle Struct objects".

**A**:	Try the following workaround to be able to pickle Struct objects:
```python
import copy, copyreg
def pickle_struct(s):
	return struct.Struct, (s.format,)

copyreg.pickle(struct.Struct, pickle_struct)
```


# Usage hints
## Performance related
- For maxmimum performance start accessing attributes at lowest level via the following index notation.
  This will lazy parse only needed layers behind the scenes:
```
pkt_eth, pkt_ip, pkt_tcp, pkt_http = pkt[
  (ethernet.Ethernet, lambda a: a.dst_s=="00:11:22:33:44:55"),
  (None, lambda b: b.__class__ in [ip.IP, ip6.IP6]),
  (tcp.TCP, lambda c: c.dport==80),
  http.HTTP
]
...
```

- Avoid to convert packets using the "%s" or "%r" format as it triggers parsing behind the scene:
```
pkt = Ethernet() + IP() + TCP()
# This parses ALL layers
packet_print = "%s" % pkt
```

- Avoid searching for a layer using single-value index-notation via pkt[L] as it parses all layers until L is found or highest layer is reached:
```
packet_found = pkt[Telnet]
# Alternative: Use multi-value index-notation. This will stop parsing at any non-matching layer:
packet_found = pkt[Ethernet,IP,TCP,Telnet]
```

- Use pypy instead of cpython (~3x faster related to full packet parsing)

- For even more performance disable auto fields (affects calling bin(...)):
```
pkt = ip.IP(src_s="1.2.3.4", dst_s="1.2.3.5") + tcp.TCP()
# Disable checksum calculation (and any other update) for IP and TCP (only THIS packet instance)
pkt.sum_au_active = False
pkt.tcp.sum_au_active = False
bts = pkt.bin(update_auto_fields=False)
```

- Enlarge receive/send buffers to get max performance. This can be done using the following commands
	(taken from: http://www.cyberciti.biz/faq/linux-tcp-tuning/):
```
sysctl -w net.core.rmem_max=12582912
sysctl -w net.core.rmem_default=12582912
sysctl -w net.core.wmem_max=12582912
sysctl -w net.core.wmem_default=12582912
sysctl -w net.core.optmem_max=2048000
sysctl -w net.core.netdev_max_backlog=5000
sysctl -w net.unix.max_dgram_qlen=1000
sysctl -w net.ipv4.tcp_rmem="10240 87380 12582912"
sysctl -w net.ipv4.tcp_wmem="10240 87380 12582912"
sysctl -w net.ipv4.tcp_mem="21228 87380 12582912"
sysctl -w net.ipv4.udp_mem="21228 87380 12582912"
sysctl -w net.ipv4.tcp_window_scaling=1
sysctl -w net.ipv4.tcp_timestamps=1
sysctl -w net.ipv4.tcp_sack=1
```

## Misc related
- Assemblation of TCP/UDP streams can be done by tshark using pipes
	with "-i -" and "-z follow,prot,mode,filter[,range]"
- Chosing the right "lowest layer" when reading capture files: Open the file eg w/ wireshark
  and look at the packet details for the data link layer. Most times this will probably
  be Ethernet II which can be parsed w/ layer12.ethernet.Ethernet.
  When capturing eg via wiresharks/tsharks "-i any" option, this will lead to Linux cooked capture
  represented by layer12.linuxcc.LinuxCC.
