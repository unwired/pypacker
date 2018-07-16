"""
Signal Level Attenuation Characterization (SLAC)
HomePlug Green PHY Specification
"""
import logging

from pypacker.pypacker import Packet
from pypacker.structcbs import pack_H_le, unpack_H

logger = logging.getLogger("pypacker")

MASK_MSGTYPE_LE = 0xFCF9
MASK_MMTYPELSB_LE = 0x0300
MASK_MMTYPEMSB_LE = 0x0006

# TODO: extend
# who defined all that useless messages???
TYPEINFO_DESCRIPTION = {
	0x0080: "CC_POWERSAVE_LIST.CNF",
	0x0084: "CC_STOP_POWERSAVE.IND",
	0x2000: "CP_PROXY_APPOINTR",
	0x2004: "PH_PROXY_APPOINT",
	0x2008: "CP_PROXY_WAKE",
	0x4000: "NN_INL",
	0x4004: "NN_NEW_NET",
	0x4008: "NN_ADD_ALLOC",
	0x400C: "NN_REL_ALLOC",
	0x4010: "NN_REL_NET",
	0x6000: "CM_UNASSOCIATED_STA",
}

# Management message type LSB
MMTYPE_LSB_DESCRIPTION = {
	0x00: "Request",
	0x01: "Confirm",
	0x02: "Indication",
	0x03: "Response"
}

# Management message type MSB
MMTYPE_MSB_DESCRIPTION = {
	0x00: "STA <-> Central Coordinator",
	0x01: "Proxy Coordinator",
	0x02: "Central Coordinator <-> Central Coordinator",
	0x03: "STA <-> STA",
	0x04: "Manufacturer Specific"
}


class Slac(Packet):
	__hdr__ = (
		("version", "B", 1),
		("typeinfo", "H", 0),
		("frag", "H", 0)
	)

	def _get_msgtype(self):
		typetmp = self.typeinfo & MASK_MSGTYPE_LE
		return unpack_H(pack_H_le(typetmp))[0]

	def _set_msgtype(self, msgtype):
		typetmp = unpack_H(pack_H_le(msgtype))[0]
		self.typeinfo = typetmp & MASK_MSGTYPE_LE

	msgtype = property(_get_msgtype, _set_msgtype)

	def _get_mmtypelsb(self):
		return (self.typeinfo & MASK_MMTYPELSB_LE) >> 8

	def _set_mmtypelsb(self, msgtype):
		typetmp = (self.typeinfo & ~MASK_MMTYPELSB_LE)
		self.typeinfo = typetmp | (msgtype << 8)

	# REQ->CNF, IND->RSP
	mmtypelsb = property(_get_mmtypelsb, _set_mmtypelsb)

	def _get_mmtypemsb(self):
		return (self.typeinfo & MASK_MMTYPEMSB_LE) >> 1

	def _set_mmtypemsb(self, msgtype):
		typetmp = (self.typeinfo & ~MASK_MMTYPEMSB_LE)
		self.typeinfo = typetmp | (msgtype << 1)

	mmtypemsb = property(_get_mmtypemsb, _set_mmtypemsb)
