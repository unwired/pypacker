"""
Scalable service-Oriented MiddlewarE over IP (SOME/IP)
"""
import logging

from pypacker.pypacker import Packet
from pypacker.pypacker import FIELD_FLAG_AUTOUPDATE

logger = logging.getLogger("pypacker")


# TODO needs testing
class SomeIP(Packet):
	__hdr__ = (
		("serviceid", "H", 1),
		("methodid", "H", 0),
		("length", "I", 8, FIELD_FLAG_AUTOUPDATE),  # in bytes, inclusive 8 bytes of header
		("clientid", "I", 0),
		("sessionid", "I", 0),
		("protoversion", "B", 0),
		("ifaceversion", "B", 0),
		("msgtype", "B", 0),
		("retcode", "B", 0)
	)

	def _update_fields(self):
		if not self._changed():
			return

		if self.length_au_active:
			self.length = 8 + len(self.body_bytes)
