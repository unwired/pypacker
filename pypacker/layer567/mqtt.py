"""
Message Queuing Telemetry Transport (MQTT)
https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html
TODO:
	TCP port 1883 and 8883
"""
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
		return tuple_entry[0] + b": " + tuple_entry[1] + b"\r\n"

# Message Types:
MSGTYPE_RESERVED	= 0
MSGTYPE_CONNECT		= 1
MSGTYPE_CONNACK		= 2
MSGTYPE_PUBLISH		= 3
MSGTYPE_PUBACK		= 4
MSGTYPE_PUBREC		= 5
MSGTYPE_PUBREL		= 6
MSGTYPE_PUBCOMP		= 7
MSGTYPE_SUBSCRIBE	= 8
MSGTYPE_SUBACK		= 9
MSGTYPE_UNSUBSCRIBE	= 10
MSGTYPE_UNSUBACK	= 11
MSGTYPE_PINGREQ		= 12
MSGTYPE_PINGRESP	= 13
MSGTYPE_DISCONNECT	= 14


class Connect(pypacker.Packe):
	__hdr__ = (
		("pnamelen", "H", 0),
		("pname", None, b""),
		("version", "B", 0),
		("conflags", "B", 0),
		("keepalive", "H", 0),
		("clientidlen", "B", 0),
		("clientid", None, b"")
	)


class ConnAck(pypacker.Packe):
	__hdr__ = (
		("reserved", "B", 0),
		("retcode", B, 0)
	)


class Publish(pypacker.Packe):
	__hdr__ = (
		("topiclen", "H", 0),
		("topic", None, b""),
		("msg", None, b""),
	)


class PubAck(pypacker.Packe):
	__hdr__ = (
	)


class PubRecv(pypacker.Packe):
	__hdr__ = (
		("msgid", "H", 0)
	)


class PubRel(pypacker.Packe):
	__hdr__ = (
		("msgid", "H", 0)
	)


class PubComplete(pypacker.Packe):
	__hdr__ = (
		("msgid", "H", 0)
	)


class Subscribe(pypacker.Packe):
	__hdr__ = (
		("msgid", "H", 0),
		("topiclen", "H", 0),
		("topic", None, b""),
		("qos", "B", 0)
	)


class SubAck(pypacker.Packe):
	__hdr__ = (
		("msgid", "H", 0),
		("qos", "B", 0)
	)


class Unsubscribe(pypacker.Packe):
	__hdr__ = (
	)


class UnsubAck(pypacker.Packe):
	__hdr__ = (
	)


"""
class PingReq(pypacker.Packe):
	__hdr__ = (
	)
class PingResp(pypacker.Packe):
	__hdr__ = (
	)
class Discconnect(pypacker.Packe):
	__hdr__ = (
	)
"""


class MQTTBase(pypacker.Packet):
	__hdr__ = (
		("ctl", "B", 1),
		("plen", None, b"\x00"),  # 0xF000 = 11110000 00000000 = [one more byte] 1110000 [no more byte] 0000000
	)

	def _dissect(self, buf):
		# Cascaded MQTT-Messages
		return 0

	@staticmethod
	def __decode_length(buf):
		return 0
