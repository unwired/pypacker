"""
Wraper for TUN/TAP interfaces.

packets written to /dev/net/tun look like "outer network -> tunX" (coming for another network)
and get handled by the kernel state machine.

> Examples
ip tuntap add dev tun0 mode tun user mike group users
ip addr add 192.168.3.1/24 dev tun0
"""

from fcntl import ioctl
from os import read as os_read
from os import write as os_write
import struct
import time
import subprocess
import netifaces
import logging

logger = logging.getLogger("pypacker")

# Some constants used to ioctl the device file
TUNSETIFF	= 0x400454ca
TUNSETOWNER	= TUNSETIFF + 2
IFF_TUN		= 0x0001
IFF_TAP		= 0x0002
#  The kernel adds a 4-byte preamble to the frame, avoid this
IFF_NO_PI	= 0x1000

TYPE_TUN	= 0
TYPE_TAP	= 1

TYPE_STR_DCT = {
	TYPE_TUN : "tun",
	TYPE_TAP : "tap"
}

class TunInterface(object):
	def __init__(self, tun_iface_name, ifacetype=TYPE_TUN, create_ondemand=False):
		self._tun_iface_name = tun_iface_name
		self._is_newly_created = False
		self._ifacetype = ifacetype
		self._ifacetype_str = "tun"

		is_iface_present = TunInterface.is_interface_present(tun_iface_name)
		logger.debug("Found interface %s", tun_iface_name)

		if not is_iface_present:
			if not create_ondemand:
				raise Exception("Did not find %s and won't create ondemand" % tun_iface_name)
			else:
				TunInterface.create_interface_os(
				iface_name=tun_iface_name,
				iface_type_str=TYPE_STR_DCT[ifacetype]
				)
				self._is_newly_created = True

		# Open TUN device file
		logger.debug("Configuring interface %s", tun_iface_name)

		if ifacetype == TYPE_TUN:
			self._tun = open("/dev/net/tun", "r+b", buffering=0)
			self._ifr = struct.pack("16sH", tun_iface_name.encode("UTF-8"), IFF_TUN | IFF_NO_PI)
		else:
			self._tun = open("/dev/net/tap", "r+b", buffering=0)
			self._ifr = struct.pack("16sH", tun_iface_name.encode("UTF-8"), IFF_TAP | IFF_NO_PI)
		ioctl(self._tun, TUNSETIFF, self._ifr)

		# Optionally, we want it be accessed by the normal user.
		# ioctl(tun, TUNSETOWNER, 1000)
		output = subprocess.getoutput("ifconfig %s up" % tun_iface_name)
		logger.debug("Output was: %s", output)

	is_newly_created = property(lambda self: self._is_newly_created)

	@staticmethod
	def is_interface_present(iface_name):
		try:
			addr = netifaces.ifaddresses(iface_name)
			return True
		except ValueError:
			# raised if interface is not present
			return False

	@staticmethod
	def create_interface_os(iface_name, iface_type_str="tun"):
		output = subprocess.getoutput("ip tuntap add dev %s mode %s" % (iface_name, iface_type_str))
		logger.debug("Output was: %s", output)

	@staticmethod
	def destroy_interface_os(iface_name, iface_type_str="tun"):
		logger.debug("Trying to destroy interface %s", iface_name)
		subprocess.getoutput("ifconfig %s down" % iface_name)
		output = subprocess.getoutput("ip tuntap del dev %s mode %s" % (iface_name, iface_type_str))
		logger.debug("Output was: %s", output)

	def read(self):
		"""Read an IP packet been sent to this TUN device."""
		return os_read(self._tun.fileno(), 2048)

	def write(self, bts):
		"""Write an IP packet to this TUN device."""
		os_write(self._tun.fileno(), bts)

	def close(self, destroy_interface=False):
		try:
			logger.debug("Closing %s", self._tun_iface_name)
			self._tun.close()
		except Exception as ex:
			logger.warning("Could not close %s", self._tun_iface_name)
			print(ex)

		if destroy_interface:
			time.sleep(2)
			logger.debug("Destroying %s", self._tun_iface_name)
			TunInterface.destroy_interface_os(
				self._tun_iface_name,
				iface_type_str=TYPE_STR_DCT[self._ifacetype])