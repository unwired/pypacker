# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
"""
Hypertext Transfer Protocol.
"""
import re
import logging

from pypacker import pypacker, triggerlist

logger = logging.getLogger("pypacker")


class HTTPHeader(triggerlist.TriggerList):
	def _pack(self, tuple_entry):
		# logger.debug("packing HTTP-header")
		# no header = no CRNL
		if len(self) == 0:
			# logger.debug("empty buf 2")
			return b""
		#return b"\r\n".join([b": ".join(keyval) for keyval in self]) + b"\r\n\r\n"
		#logger.debug("adding: %r" % (tuple_entry[0] +b": "+ tuple_entry[1] + b"\r\n"))
		# Note: does not preserve deviating separators, eg "x  :   yz"
		return tuple_entry[0] + b": " + tuple_entry[1] + b"\r\n"

# [Method] [Path] HTTP...\r\n
# key: value\r\n
# \r\n
# [body]
PROG_STARTLINE			= re.compile(rb"[\w\./]{3,10} +[\w\./]{1,400} +[\w\./]{1,20}.+")
PROG_STARTLINE_MATCH		= PROG_STARTLINE.match
PROG_SPLIT_HEADBODY		= re.compile(b"\r\n\r\n")
PROG_SPLIT_HEADBODY_SPLIT	= PROG_SPLIT_HEADBODY.split
PROG_SPLIT_HEADER		= re.compile(b"\r\n")
PROG_SPLIT_HEADER_SPLIT		= PROG_SPLIT_HEADER.split
PROG_SPLIT_KEYVAL		= re.compile(b": ")
PROG_SPLIT_KEYVAL_SPLIT		= PROG_SPLIT_KEYVAL.split


class HTTP(pypacker.Packet):
	__hdr__ = (
		# content: b"startline"
		("startline", None, None),  # Including trailing \r\n
		# content: [("name", "value"), ...]
		("hdr", None, HTTPHeader),  # Including trailing \r\n
		("sep", "2s", b"\r\n")
	)

	def _dissect(self, buf):
		# Requestline: [method] [uri] [version] eg GET / HTTP/1.1
		# Responseline: [version] [status] [reason] eg HTTP/1.1 200 OK
		#logger.debug("Full HTTP: %s", buf)
		# Request/responseline is mendatory to parse header
		if len(buf) == 0 or not PROG_STARTLINE_MATCH(buf):
			self.sep = None
			return 0

		try:
			bts_header, bts_body = PROG_SPLIT_HEADBODY_SPLIT(buf, maxsplit=1)
			#logger.debug("Header: %s\nBody: %s", bts_header, bts_body)
		except ValueError:
			#logger.debug("no startline/header present")
			# Deactivate separator
			self.sep = None
			# Assume this is part of a bigger (splittet) HTTP-message: no header/only body
			return 0

		try:
			startline, bts_header = PROG_SPLIT_HEADER_SPLIT(bts_header, maxsplit=1)
		except ValueError:
			# logger.debug("just startline: %r, hdr length=%d" % (bts_header, len(bts_header) + 4))
			# bts_header was something like "HTTP/1.1 123 status" (\r\n\r\n previously removed)
			self.startline = bts_header + b"\r\n"
			return len(bts_header) + 4  # startline + 2 (CR NL) + 0 (header) + 2 (sep: CR NL) + 0 (body)

		self.startline = startline + b"\r\n"
		# bts_header = hdr1\r\nhdr2 -> hdr1\r\nhdr2\r\n
		self.hdr(memoryview(bts_header + b"\r\n"), self._parse_header)
		# HEADER + "\r\n" + BODY -> newline is part of the header
		return len(buf) - len(bts_body)

	@staticmethod
	def _parse_header(buf):
		#logger.debug("Parsing header: %s", buf)
		header = []
		lines = PROG_SPLIT_HEADER_SPLIT(buf)

		for line in lines:
			#logger.debug("Checking line: %s", line)
			if len(line) == 0:
				break
			try:
				key, val = PROG_SPLIT_KEYVAL_SPLIT(line, 1)
				header.append((key, val))
			except:
				# Not a "key: value" line
				logger.warning("Invalid HTTP line: %s", line)
				header.append(line)

		return header
