# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
"""Trivial File Transfer Protocol (TFTP)"""
import re
import logging

from pypacker.pypacker import Packet
from pypacker.structcbs import unpack_H

logger = logging.getLogger("pypacker")

PATTERN_00 = re.compile(b"\x00")
split_nullbyte = PATTERN_00.split

# Opcodes
OP_RRQ = 1  # read request
OP_WRQ = 2  # write request
OP_DATA = 3  # data packet
OP_ACK = 4  # acknowledgment
OP_ERR = 5  # error code

OPCODES_READ_WRITE = {OP_RRQ, OP_WRQ}
OPCODES_DATA_ACK = {OP_DATA, OP_ACK}

# Error codes
EUNDEF = 0  # not defined
ENOTFOUND = 1  # file not found
EACCESS = 2  # access violation
ENOSPACE = 3  # disk full or allocation exceeded
EBADOP = 4  # illegal TFTP operation
EBADID = 5  # unknown transfer ID
EEXISTS = 6  # file already exists
ENOUSER = 7  # no such user


class TFTP(Packet):
	__hdr__ = (
		("opcode", "H", OP_RRQ),
		("file", None, None),
		("block", "H", 0),
		("ttype", None, None)
	)

	def _dissect(self, buf):
		hlen = 4
		opcode = unpack_H(buf[: 2])
		# logger.debug("opcode: %d" % opcode)

		if opcode in OPCODES_DATA_ACK:
			pass
		elif opcode in OPCODES_READ_WRITE:
			self.block = None
			file, ttype = split_nullbyte(buf[2:], maxsplit=2)
			# logger.debug("file/ttype = %r / %r" % (file, ttype))
			self.file = file + b"\x00"
			self.ttype = ttype + b"\x00"
			hlen = 2 + len(file) + len(ttype)
		elif opcode == OP_ERR:
			pass
		return hlen
