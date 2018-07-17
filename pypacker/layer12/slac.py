"""
Signal Level Attenuation Characterization (SLAC)
HomePlug Green PHY Specification
"""
import logging
import sys

from pypacker.pypacker import Packet
from pypacker.structcbs import pack_H_le, unpack_H

logger = logging.getLogger("pypacker")

MASK_MSGTYPE_LE = 0xFCF9
MASK_MMTYPELSB_LE = 0x0300
MASK_MMTYPEMSB_LE = 0x0006

module_this = sys.modules[__name__]

# TODO: extend
# who defined all that useless messages???
TYPEINFO_DESCRIPTION = {
	# Central <-> Station
	0x0000: "CC_CCO_APPOINT",
	0x0004: "CC_BACKUP_APP",
	0x0008: "CC_LINK_INFO",
	0x000C: "CC_HANDOVER",
	0x0010: "CC_HANDOVER_INFO",
	0x0014: "CC_DISCOVER_LIST",
	0x0018: "CC_LINK_NEW",
	0x001C: "CC_LINK_MOD",
	0x0020: "CC_LINK_SQZ",
	0x0024: "CC_LINK_REL",
	0x0028: "CC_DETECT_REPORT",
	0x002C: "CC_WHO_RU",
	0x0030: "CC_ASSOC",
	0x0034: "CC_LEAVE",
	0x0038: "CC_SET_TEI_MAP",
	0x003C: "CC_RELAY",
	0x0040: "CC_BEACON_RELIABILITY.REQ",
	0x0044: "CC_ALLOC_MOVE",
	0x0048: "CC_ACCESS_NEW",
	0x004C: "CC_ACCESS_REL",
	0x0050: "CC_DCPPC",
	0x0054: "CC_HP1_DET",
	0x0058: "CC_BLE_UPDATE",
	0x005C: "CC_BCAST_REPEAT",
	0x0060: "CC_MH_LINK_NEW",
	0x0064: "CC_ISP_DetectionReport.IND",
	0x0068: "CC_ISP_StartReSync",
	0x006C: "CC_ISP_FinishReSync",
	0x0070: "CC_ISP_ReSyncDetected.IND",
	0x0074: "CC_ISP_ReSyncTransmit.REQ",
	0x0078: "CC_POWERSAVE.",
	0x007C: "CC_POWERSAVE_EXIT.REQ",
	0x0080: "CC_POWERSAVE_LIST.REQ",
	0x0084: "CC_STOP_POW",
	# Proxy Coordinator
	0x2000: "CP_PROXY_APPOINT",
	0x2004: "PH_PROXY_APPOINT",
	0x2008: "CP_PROXY_WAKE.",
	# CCo - CCo
	0x4000: "NN_INL.REQ",
	0x4004: "NN_NEW_NET.RE",
	0x4008: "NN_ADD_ALLOC.R",
	0x400C: "NN_REL_ALLOC.R",
	0x4010: "NN_REL_NET.IND",
	# Station - Station
	0x6000: "CM_UNASSOCIATED",
	0x6004: "CM_ENCRYPTED_PAYLOAD",
	0x6008: "CM_SET_KEY",
	0x600C: "CM_GET_KEY",
	0x6010: "CM_SC_JOIN",
	0x6014: "CM_CHAN_EST",
	0x6018: "CM_TM_UPDATE",
	0x601C: "CM_AMP_MAP",
	0x6020: "CM_BRG_INFO",
	0x6024: "CM_CONN_NEW",
	0x6028: "CM_CONN_REL",
	0x602C: "CM_CONN_MOD",
	0x6030: "CM_CONN_INFO",
	0x6034: "CM_STA_CAP",
	0x6038: "CM_NW_INFO",
	0x603C: "CM_GET_BEACON",
	0x6040: "CM_HFID",
	0x6044: "CM_MME_ERROR",
	0x6048: "CM_NW_STATS",
	0x604C: "CM_LINK_STATS",
	0x6050: "CM_ROUTE_INFO",
	0x6054: "CM_UNREACHABLE",
	0x6058: "CM_MH_CONN_NEW",
	0x605C: "CM_EXTENDED_TONEMASK",
	0x6060: "CM_STA_IDENTIFY",
	0x6064: "CM_SLAC_PARM",
	0x6068: "CM_START_ATTEN_CHAR",
	0x606C: "CM_ATTEN_CHAR",
	0x6070: "CM_PKCS_CERT",
	0x6074: "CM_MNBC_SOUND",
	0x6078: "CM_VALIDATE",
	0x607C: "CM_SLAC_MATCH",
	0x6080: "CM_SLAC_USER_DATA",
	0x6084: "CM_ATTEN_PROFILE"
}

# reverse access of message IDs
for msgid, name in TYPEINFO_DESCRIPTION.items():
	setattr(module_this, name, msgid)

# Management message type LSB
MMTYPE_LSB_DESCRIPTION = {
	0x00: "MMTYPELSB_REQUEST",
	0x01: "MMTYPELSB_CONFIRM",
	0x02: "MMTYPELSB_INDICATION",
	0x03: "MMTYPELSB_RESPONSE"
}

for msgid, name in MMTYPE_LSB_DESCRIPTION.items():
	setattr(module_this, name, msgid)

# Management message type MSB
MMTYPE_MSB_DESCRIPTION = {
	0x00: "MMTYPEMSB_STA__CentralCoordinator",
	0x01: "MMTYPEMSB_ProxyCoordinator",
	0x02: "MMTYPEMSB_CentralCoordinator__CentralCoordinator",
	0x03: "MMTYPEMSB_STA__STA",
	0x04: "MMTYPEMSB_Manufacturer_Specific"
}

for msgid, name in MMTYPE_MSB_DESCRIPTION.items():
	setattr(module_this, name, msgid)


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

	def _get_msgtype_s(self):
		return TYPEINFO_DESCRIPTION.get(self.msgtype, None)

	msgtype_s = property(_get_msgtype_s)

	def _get_mmtypelsb(self):
		return (self.typeinfo & MASK_MMTYPELSB_LE) >> 8

	def _set_mmtypelsb(self, msgtype):
		typetmp = (self.typeinfo & ~MASK_MMTYPELSB_LE)
		self.typeinfo = typetmp | (msgtype << 8)

	# REQ->CNF, IND->RSP
	mmtypelsb = property(_get_mmtypelsb, _set_mmtypelsb)

	def _get_mmtypelsb_s(self):
		return MMTYPE_LSB_DESCRIPTION.get(self.mmtypelsb, None)

	mmtypelsb_s = property(_get_mmtypelsb_s, None)

	def _get_mmtypemsb(self):
		return (self.typeinfo & MASK_MMTYPEMSB_LE) >> 1

	def _set_mmtypemsb(self, msgtype):
		typetmp = (self.typeinfo & ~MASK_MMTYPEMSB_LE)
		self.typeinfo = typetmp | (msgtype << 1)

	mmtypemsb = property(_get_mmtypemsb, _set_mmtypemsb)

	def _get_mmtypemsb_s(self):
		return MMTYPE_MSB_DESCRIPTION.get(self.mmtypemsb, None)

	mmtypemsb_s = property(_get_mmtypemsb_s, None)
