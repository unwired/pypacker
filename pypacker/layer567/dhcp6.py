# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
"""Dynamic Host Configuration Protocolv6."""
import logging

from pypacker import pypacker, triggerlist
from pypacker.structcbs import unpack_H

logger = logging.getLogger("pypacker")


DHCP_TYPE_SOLICIT		= 1

DHCP_OPT_CLIENT_ID		= 1
DHCP_OPT_ID_ASSOC_NTA		= 3
DHCP_OPT_REQUEST		= 6
DHCP_OPT_ELAPSED_TIME		= 8


class DHCP6(pypacker.Packet):
	__hdr__ = (
		("msgid", "B", DHCP_TYPE_SOLICIT),
		("tid", "3s", b"\x00" * 3),
		("opts", None, triggerlist.TriggerList)
	)

	def _dissect(self, buf):
		self.opts(buf[4:], DHCP6._get_opts)
		return len(buf)

	class DHCPOpt(pypacker.Packet):
		__hdr__ = (
			("type", "H", 0),
			("len", "H", 14)
		)

	class ClientOpt(pypacker.Packet):
		__hdr__ = (
			("type", "H", DHCP_OPT_CLIENT_ID),
			("len", "H", 14)
		)

	class IDAssocNTAOpt(pypacker.Packet):
		__hdr__ = (
			("type", "H", DHCP_OPT_ID_ASSOC_NTA),
			("len", "H", 12),
			("iaid", "I", 0),
			("t1", "I", 0),
			("t2", "I", 0)
		)

	class RequestOpt(pypacker.Packet):
		__hdr__ = (
			("type", "H", DHCP_OPT_REQUEST),
			("len", "H", 0),
			# Content example: 001700180027001f
		)

	class ElapsedTimeOpt(pypacker.Packet):
		__hdr__ = (
			("type", "H", DHCP_OPT_ELAPSED_TIME),
			("len", "H", 2),
			("timeelaps", "H", 0)
		)

	@staticmethod
	def _get_opts(buf):
		opts = []
		off = 0

		# TODO: Use dedicated Option classes
		while off < len(buf):
			off_start = off
			#otype = unpack_H(buf[i: i+1])[0]
			off += 2
			olen = unpack_H(buf[off: off + 1])[0]
			off += olen

			opt = DHCP6.DHCPOpt(buf[off_start: off])
			opts.append(opt)

		return opts
