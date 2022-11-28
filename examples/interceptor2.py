"""
Interceptor example via nftables

# Add table
nft add table inet queuetable
# Add chain to table
nft add chain inet queuetable input { type filter hook input priority 0\; }
nft add chain inet queuetable output { type filter hook output priority 0\; }
# Add rule to chain
nft insert rule inet queuetable input counter queue num 0-1 bypass
nft insert rule inet queuetable output counter queue num 2-3 bypass

# Delete table
nft delete table inet queuetable

# List handles
nft --handle --numeric list chain inet queuetable input
# List rules
nft list ruleset
https://wiki.nftables.org/wiki-nftables/index.php/Queueing_to_userspace
# Show ARP cache for IPv6
ip -6 neigh
"""
import time
import socket

from pypacker import interceptor
from pypacker.pypacker import mac_bytes_to_str
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip, ip6

id_class = {
	ethernet.ETH_TYPE_IP: ip.IP,
	ethernet.ETH_TYPE_IP6: ip6.IP6
}



def verdict_cb(hwaddr, ll_proto_id, data, ctx, if_idx_in, if_idx_out, *args):
	clz = id_class.get(ll_proto_id, None)
	if_in, if_out = "", ""

	try:
		if if_idx_in != 0:
			if_in = socket.if_indextoname(if_idx_in)
		if if_idx_out != 0:
			if_out = socket.if_indextoname(if_idx_out)
	except:
		pass

	if clz is not None:
		pkt = clz(data)
		if hwaddr is not None:
			hwaddr = mac_bytes_to_str(hwaddr)
		print("Got a packet: %s (hwaddr: %s, in: %s, out: %s)" % (
			pkt.__class__.__name__, hwaddr, if_in, if_out))
	else:
		print("Unknown NW layer proto: %X" % ll_proto_id)

	return data, interceptor.NF_ACCEPT


ictor = interceptor.Interceptor()
ictor.start(verdict_cb, queue_ids=[0, 1, 2, 3])

try:
	time.sleep(999)
except KeyboardInterrupt:
	pass
ictor.stop()
