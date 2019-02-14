"""
Wraper for TUN/TAP interfaces.

packets written to /dev/net/tun look like "outer network -> tunX" (coming for another network)
and get handled by the kernel state machine.

Requirements:
netifaces

> Examples
ip tuntap add dev tun0 mode tun user mike group users
ip addr add 192.168.3.1/24 dev tun0
ip rule list; ip link show
ip tuntap del dev tun0 mode tun; ip tuntap del dev tun1 mode tun;
"""

from fcntl import ioctl
import os
from os import read as os_read
from os import write as os_write
import struct
import time
import threading
import subprocess
# no try/except: we need this in any case
import netifaces
import logging

from pypacker import utils

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
	TYPE_TUN: "tun",
	TYPE_TAP: "tap"
}


class TunInterface(object):
	def __init__(self,
		tun_iface_name,
		ifacetype=TYPE_TUN,
		ip_src="12.34.56.1",
		ip_dst="12.34.56.2",
		create_ondemand=False,
		is_local_tunnel=False):
		self._closed = False
		self._tun_iface_name = tun_iface_name
		self._is_newly_created = False
		self._ifacetype = ifacetype

		if not utils.is_interface_present(tun_iface_name):
			if not create_ondemand:
				raise Exception("Did not find %s and won't create ondemand" % tun_iface_name)
			else:
				TunInterface.create_tun_interface(
					tun_iface_name,
					iface_type_str=TYPE_STR_DCT[ifacetype]
				)
				self._is_newly_created = True
		else:
			logger.debug("Found interface %s", tun_iface_name)

		if ip_src is not None and ip_dst is not None:
			TunInterface.configure_tun_interface(tun_iface_name,
				ip_src, ip_dst,
				is_local_tunnel=is_local_tunnel)
		utils.set_interface_state(tun_iface_name, state_active=True)

		# Open TUN device file
		# TODO: multiqueue?
		if ifacetype == TYPE_TUN:
			self._tun = open("/dev/net/tun", "r+b", buffering=0)
			self._ifr = struct.pack("16sH", tun_iface_name.encode("UTF-8"), IFF_TUN | IFF_NO_PI)
		else:
			self._tun = open("/dev/net/tap", "r+b", buffering=0)
			self._ifr = struct.pack("16sH", tun_iface_name.encode("UTF-8"), IFF_TAP | IFF_NO_PI)
		ioctl(self._tun, TUNSETIFF, self._ifr)
		self._fileno_tun = self._tun.fileno()
		# Optionally, we want it be accessed by the normal user.
		# ioctl(self._tun, TUNSETOWNER, 1000)

	is_newly_created = property(lambda self: self._is_newly_created)

	@staticmethod
	def create_tun_interface(iface_name, iface_type_str="tun"):
		output = subprocess.getoutput("ip tuntap add dev %s mode %s" % (iface_name, iface_type_str))
		logger.debug(output)

	@staticmethod
	def configure_tun_interface(iface_name, ip_src, ip_dst, is_local_tunnel=False):
		output = subprocess.getoutput("ifconfig %s %s pointopoint %s" % (iface_name, ip_src, ip_dst))
		logger.debug(output)

		if is_local_tunnel:
			# Packet with target ip_dst goes through "lo" if ip_dst is on the same host.
			# Avoid this by removing local rules
			# TODO: bind() doesn't work with this
			# TODO: avoid this if tun1 is not local (only tun0 or vose versa)
			output = subprocess.getoutput("ip route del %s table local" % ip_src)
			logger.debug(output)
			# pointopoint creates implicit rule in "main"
			# Problem if src/dst tun are on the same host: packets pop out of tun1 (target), but the kernel
			# does not recognize them as being addressed to the local host. (we removed the rule above)
			# Solution: distinct routing decisions and configure routing in such a way that the local
			# type routes are only "seen" by the input routing decision
			output = subprocess.getoutput("ip route add local %s dev %s table 13" % (ip_src, iface_name))
			logger.debug(output)
			# make sure previous rules have been removed
			output = subprocess.getoutput("ip rule del iif %s lookup 13" % iface_name)
			logger.debug(output)
			output = subprocess.getoutput("ip rule add iif %s lookup 13" % iface_name)
			logger.debug(output)

	@staticmethod
	def destroy_tun_interface(iface_name, iface_type_str="tun", obj=None):
		logger.debug("Trying to destroy interface %s", iface_name)
		#output = subprocess.getoutput("ip link set dev %s down" % iface_name)
		#logger.debug(output)
		output = subprocess.getoutput("ip tuntap del dev %s mode %s" % (iface_name, iface_type_str))
		logger.debug(output)

	def read(self):
		"""Read an IP packet been sent to this TUN device."""
		try:
			return os_read(self._fileno_tun, 1024 * 4)
		except TypeError:
			# read after closing
			return None

	def write(self, bts):
		"""Write an IP packet to this TUN device."""
		try:
			os_write(self._fileno_tun, bts)
		except TypeError:
			# write after closing
			pass

	def close(self, destroy_iface=False):
		if self._closed:
			return
		self._closed = True

		try:
			logger.debug("Closing %s", self._tun_iface_name)
			#self._tun.close()
			# TODO: read is blocking although socket is closed -> removing interface is not possible
			os.close(self._fileno_tun)
			self._fileno_tun = None
		except Exception as ex:
			logger.warning("Could not close %s", self._tun_iface_name)
			print(ex)
		#time.sleep(2)
		if self._is_newly_created or destroy_iface:
			# destroy interface only if it was auto-created
			logger.debug("Destroying %s", self._tun_iface_name)
			TunInterface.destroy_tun_interface(
				self._tun_iface_name,
				iface_type_str=TYPE_STR_DCT[self._ifacetype],
				obj=self)


class LocalTunnel(object):
	"""
	Local Back-to-back tunnel based on tun interfaces: local <-> tun1 <-> tun2 <-> local
	"""
	def __init__(self, ip_src="12.34.56.1", ip_dst="12.34.56.2"):
		# TODO: enable for use with external tooling (eg netcat)
		islocaltunnel = False
		self._state_active = False
		self._tundev0 = TunInterface(tun_iface_name="tun0",
			create_ondemand=True,
			ip_src=ip_src, ip_dst=ip_dst,
			is_local_tunnel=islocaltunnel)
		self._tundev1 = TunInterface(tun_iface_name="tun1",
			create_ondemand=True,
			ip_src=ip_dst, ip_dst=ip_src,
			is_local_tunnel=islocaltunnel)
		self._rs_thread_tun0 = None
		self._rs_thread_tun1 = None

	def _start_cycler_threads(self):
		self._rs_thread_tun0 = threading.Thread(target=LocalTunnel.read_cycler,
			args=[self, self._tundev0, self._tundev1, "1to2"])
		self._rs_thread_tun1 = threading.Thread(target=LocalTunnel.read_cycler,
			args=[self, self._tundev1, self._tundev0, "2to1"])
		self._rs_thread_tun0.start()
		self._rs_thread_tun1.start()

	@staticmethod
	def read_cycler(obj, tun_1, tun2, name):
		logger.debug("starting cycler %s" % name)

		while obj._state_active:
			try:
				bts = tun_1.read()
				logger.debug("Sending %s" % name)
				logger.debug(bts)
				tun2.write(bts)
			except ValueError as ex:
				logger.warning(ex)
				break
			except OSError as ex:
				logger.warning(ex)
				break
			except Exception as ex:
				logger.debug(ex)
				break
		logger.debug("Cycler finished")

	def set_state(self, state_active):
		if self._state_active is None:
			logger.warning("Tunnel was already closed!")
			return

		if state_active == self._state_active:
			return

		self._state_active = state_active

		if state_active:
			self._start_cycler_threads()
		else:
			logger.debug("Closing interfaces!")
			self._tundev0.close()
			self._tundev1.close()

			logger.debug("Waiting for cycler threads to finish")
			for th in [self._rs_thread_tun0, self._rs_thread_tun1]:
				th.join()
			self._state_active = None
