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

If you want to support this project you can [![Donate with PayPal](https://www.paypalobjects.com/en_US/i/btn/btn_donate_SM.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=M6GGAXJQCUHVC&source=url) via PayPal.

## What you can do with Pypacker
Create custom Packets (via keywords) or from raw bytes and access/change their data:

```python
from pypacker.layer3 import ip
from pypacker.layer3 import icmp

# Packet via keywords
ip0 = ip.IP(src_s="127.0.0.1", dst_s="192.168.0.1", p=1) +\
	icmp.ICMP(type=8) +\
	icmp.ICMP.Echo(id=123, seq=1, body_bytes=b"foobar")

# Packet from raw bytes. ip1_bts can also be retrieved via ip0.bin()
ip1_bts = b"E\x00\x00*\x00\x00\x00\x00@\x01;)\x7f\x00\x00\x01\xc0\xa8\x00\x01\x08\x00\xc0?\x00{\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00foobar"
ip1 = ip.IP(ip1_bts) 

# Output packet (similar result for ip1)
print("%s" % ip0)
layer3.ip.IP
        v_hl         (B): 0x45 = 69 = 0b1000101
        tos          (B): 0x0 = 0 = 0b0
        len          (H): 0x22 = 34 = 0b100010
        id           (H): 0x0 = 0 = 0b0
        frag_off     (H): 0x0 = 0 = 0b0
        ttl          (B): 0x40 = 64 = 0b1000000
        p            (B): 0x1 = 1 = 0b1 = IP_PROTO_ICMP
        sum          (H): 0x3B31 = 15153 = 0b11101100110001
        src          (4): b'\x7f\x00\x00\x01' = 127.0.0.1
        dst          (4): b'\xc0\xa8\x00\x01' = 192.168.0.1
        opts            : []
layer3.icmp.ICMP
        type         (B): 0x8 = 8 = 0b1000 = ICMP_ECHO
        code         (B): 0x0 = 0 = 0b0
        sum          (H): 0xC03F = 49215 = 0b1100000000111111
layer3.icmp.Echo
        id           (H): 0x7B = 123 = 0b1111011
        seq          (H): 0x1 = 1 = 0b1
        bodybytes    (6): b'foobar'

# Access any header fields on any layer
ip_dst = ip1.dst_s
icmp_type = ip1.higher_layer.type

# Access layers via advanced filter (e.g. on unknown packet structure)
ip0_found, icmp0_found, echo0_found = pkt[
	(None, lambda b: b.__class__ == ip.IP),
	icmp.ICMP,
	(icmp.ICMP.Echo, lambda b: b.id == 123)
]

if echo0_found is not None:
	print(echo0_found)

# Change source IPv4 address
ip1.src_s = "1.2.3.4"

# Change ICMP payload
ip1.highest_layer.body_bytes = b"foobar2"
```


Read/write packets from/to file (Support only for Wireshark/tcpdump pcap format):

```python
from pypacker import ppcap
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip, ip6
from pypacker.layer4 import tcp
from pypacker.layer567 import http

preader = ppcap.Reader(filename="ether.pcap")
pwriter = ppcap.Writer(filename="ether_new.pcap", linktype=ppcap.DLT_EN10MB)

for ts, buf in preader:
	pkt = ethernet.Ethernet(buf)

	# Filter specific packets
	eth0, ip0, tcp0, http0 = pkt[
		None,
		(None, lambda b: b.__class__ in [ip.IP, ip6.IP6]),
		(tcp.TCP, lambda c: c.dport==80),
		http.HTTP
	]

	if eth0 is not None:
		print(f"{ts}: {ip0.src_s}:{tcp0.sport} -> {ip0.dst_s}:{tcp0.dport}")
		pwriter.write(eth0.bin())

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

Send/receive layer 2 (and higher)  packets:

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
# Alternatively add nftables rule:
# nft add table inet pptable
# nft add chain inet pptable filter { type filter hook input priority 0 \; policy accept\; }
# nft add rule inet pptable filter counter queue num 0-2
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
  - Linux based system with kernel support for NFQUEUE target. The kernel config option is at:
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

```
python tests/test_pypacker.py
python examples/python [example]
```
## Testing
Tests are executed as follows:

1) Add Pypacker directory to the PYTHONPATH.

- `cd pypacker`
- `export PYTHONPATH=$(pwd):$PYTHONPATH`

2) Execute tests

- `python tests/test_pypacker.py`

**Performance test results: pypacker**
```
nr = Intel CPU, 4 Cores @ 2.5 GHz, CPython v3.6

rounds per test: 10000
=====================================
>>> Packet parsing (Ethernet + IP + UDP + DNS): Search UDP port
Time diff: 0.41541337966918945s
nr = 24072 p/s
>>> Packet parsing (Ethernet + IP + TCP + HTTP): Search TCP port
Time diff: 0.788198709487915s
nr = 12687 p/s
>>> Packet parsing (Ethernet + IP + TCP + HTTP): Reading all header
Time diff: 1.32124924659729s
nr = 7568 p/s
>>> Parsing first layer (IP + ICMP)
Time diff: 0.05343985557556152s
nr = 187126 p/s
>>> Creating/direct assigning (IP only header)
Time diff: 0.11874556541442871s
nr = 84213 p/s
>>> bin() without change (IP)
Time diff: 0.028677940368652344s
nr = 348700 p/s
>>> Output with change/checksum recalculation (IP)
Time diff: 0.2695651054382324s
nr = 37096 p/s
>>> Basic/first layer parsing (Ethernet + IP + TCP + HTTP)
Time diff: 0.062027692794799805s
nr = 161218 p/s
>>> Changing Triggerlist element value (Ethernet + IP + TCP + HTTP)
Time diff: 0.061231374740600586s
nr = 163314 p/s
>>> Changing dynamic field (Ethernet + IP + TCP + HTTP)
Time diff: 0.02509450912475586s
nr = 398493 p/s
>>> Direct assigning and concatination (Ethernet + IP + TCP + HTTP)
Time diff: 0.5904519557952881s
nr = 16936 p/s

```

**Performance test results: pypacker vs. dpkt vs. scapy**
```
Comparing pypacker, dpkt and scapy performance (parsing Ethernet + IP + TCP + HTTP)
orC = Intel CPU, 4 Cores @ 3GHz, CPython v3.6
rounds per test: 10000
=====================================
>>> testing pypacker parsing speed
nr = 55374 p/s
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
	is a general introduction to pypacker included at the doc's/wiki which shows the usage and concepts
	of pypacker.

**Q**:	How fast is pypacker?

**A**:	See results above. For detailed results on your machine execute tests:
	`python tests/test_pypacker.py PerfTestCase`

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
        Long answer: See examples/new_protocol.py for a very complete example.

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
import struct, copyreg
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
  None,
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

- Use pypy (~3x faster than CPython related to full packet parsing)

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
