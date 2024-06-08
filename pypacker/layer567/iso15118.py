# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
"""
ISO15118
"""
import logging

from pypacker.pypacker import Packet

logger = logging.getLogger("pypacker")

MSGTYPE_EXI	= 0x8001
MSGTYPE_SDP_REQ	= 0x9000
MSGTYPE_SDP_RSP	= 0x9001


class SDP(Packet):
	__hdr__ = (
		("id", "B", 0),
		("idrev", "B", 0),
		("msgtype", "H", 0),
		("msglen", "I", 0)
	)
