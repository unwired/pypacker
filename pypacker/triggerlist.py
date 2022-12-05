"""TriggerList for handling dynamic headers."""
import logging
import types

logger = logging.getLogger("pypacker")

TRIGGERLIST_CONTENT_SIMPLE = {bytes, tuple}


class TriggerList(list):
	"""
	List with trigger-capabilities representing a Packet header.
	This list can contain any type of raw bytes, tuples like (key, value)
	or packets. Calling bin() will reassemble a content like
	[b"somebytes", mypacket, ("tuplekey", "tuplevalue")]
	to this: b"somebytes" + mypacket.bin() + ("tuplekey", "tuplevalue")[1].
	Custom reassemblation for tuples can be done by overwriting "_pack()".
	"""

	def __init__(self, packet, dissect_callback=None, buffer=b"", headerfield_name=""):
		"""
		packet -- packet where this TriggerList gets integrated
		dissect_callback -- callback which dessects byte string b"buffer", returns [a, b, c, ...]
		buffer -- byte string to be dissected
		headerfield_name -- name of this triggerlist when placed in a packet
		"""
		super().__init__()
		# Set by external Packet
		self._packet = packet
		self._dissect_callback = dissect_callback
		self._cached_result = buffer
		self._headerfield_name = headerfield_name

	def _lazy_dissect(self):
		if self._packet._unpacked == False:
			# Before changing TriggerList we need to unpack or
			# cached header won't fit on _unpack(...).
			# Ignored if still in dissect (_unpacked == None).
			# This is called before any changes to TriggerList so place it here.
			self._packet._unpack()

		if self._dissect_callback is None:
			# Already dissected, ignore
			return

		try:
			# TODO: use memoryview?
			initial_list_content = self._dissect_callback(self.bin())
		except:
			# If anything goes wrong: raw bytes will be accessible in any case
			#logger.debug("Failed to dissect in TL")
			initial_list_content = [self.bin()]

		self._dissect_callback = None
		# This is re-calling _lazy_dissect(), avoid by calling parent version
		super(TriggerList, self).extend(initial_list_content)

	# Python predefined overwritten methods

	def __getitem__(self, needle):
		self._lazy_dissect()
		if type(needle) != types.FunctionType:
			return super().__getitem__(needle)
		else:
			idx_value = []
			idx = 0

			for idx, value in enumerate(self):
				try:
					if needle(value):
						idx_value.append((idx, value))
				except:
					# Don't care. Note: gets inperformant if too many exceptions
					pass
			return idx_value

	def __iadd__(self, v):
		"""Item can be added using '+=', use 'append()' instead."""
		self._lazy_dissect()
		super().__iadd__(v)
		self.__refresh_listener([v])
		return self

	def __setitem__(self, needle, value):
		self._lazy_dissect()
		idxs_to_set = []

		if type(needle) != types.FunctionType:
			idxs_to_set.append(needle)
		else:
			idx = 0

			for idx, value_it in enumerate(self):
				try:
					if needle(value_it):
						idxs_to_set.append(idx)
						break
				except:
					# Don't care. Note: gets inperformant if too many exceptions
					pass

		for idx_to_set in idxs_to_set:
			try:
				# Remove listener from old packet which gets overwritten
				self[idx_to_set].remove_change_listener(None, remove_all=True)
			except:
				pass
			super().__setitem__(idx_to_set, value)

		if len(idxs_to_set) > 0:
			self.__refresh_listener([value])

	def __delitem__(self, k):
		self._lazy_dissect()
		if type(k) is int:
			itemlist = [self[k]]
		else:
			# Assume slice: [x:y]
			itemlist = self[k]
		super().__delitem__(k)
		self.__refresh_listener(itemlist, connect_packet=False)

	def __len__(self):
		self._lazy_dissect()
		return super().__len__()

	def __iter__(self):
		self._lazy_dissect()
		return super().__iter__()

	def append(self, v):
		self._lazy_dissect()
		super().append(v)
		self.__refresh_listener([v])

	def extend(self, v):
		self._lazy_dissect()
		super().extend(v)
		self.__refresh_listener(v)

	def insert(self, pos, v):
		self._lazy_dissect()
		super().insert(pos, v)
		self.__refresh_listener([v])

	def clear(self):
		self._lazy_dissect()
		items = [item for item in self]
		super().clear()
		self.__refresh_listener(items, connect_packet=False)

	def __refresh_listener(self, val, connect_packet=True):
		"""
		Handle modifications of this TriggerList (adding, removing, ...).
		WARNING: packets can only be put in one tl once at a time

		val -- list of bytes, tuples or packets
		connect_packet -- connect packet to this tl and parent packet
		"""
		for v in val:
			# Ignore non-packets
			if type(v) in TRIGGERLIST_CONTENT_SIMPLE:
				continue

			if connect_packet:
				# Allow packet in TL to access packet containing this TL:
				# packet1( TL[packet2->"access to packet1"] )
				v._triggelistpacket_parent = self._packet
				# TriggerList observes changes on packets:
				# base packet <- TriggerList (observes changes, set changed status
				# in basepacket) <- contained packet (changes)
				# Add change listener to the packet this TL is contained in.
				lwrapper = lambda: self._notify_change()
				v._add_change_listener(lwrapper)
			else:
				# Remove any old listener
				v._remove_change_listener()
				# Remove old parent
				v._triggelistpacket_parent = None
		self._notify_change()

	def _notify_change(self):
		"""
		Update _header_changed and _header_format_changed of the Packet having
		this TriggerList as field and _cached_result.
		Called by: this list on changes or Packets in this list
		"""
		self._packet._header_value_changed = True
		self._packet._header_format_changed = True
		# List changed: old cache of TriggerList not usable anymore
		self._cached_result = None

	def bin(self):
		"""
		Output the TriggerLists elements as concatenated bytestring.
		Custom implementations for tuple-handling can be set by overwriting _pack().
		"""
		if self._cached_result is None:
			result_arr = []
			entry_type = None

			for entry in self:
				entry_type = type(entry)

				if entry_type is bytes:
					result_arr.append(entry)
				elif entry_type is tuple:
					result_arr.append(self._pack(entry))
				else:
					# This Must be a packet, otherthise invalid entry!
					result_arr.append(entry.bin())

			self._cached_result = b"".join(result_arr)
		elif type(self._cached_result) == memoryview:
			self._cached_result = self._cached_result.tobytes()

		return self._cached_result

	def _pack(self, tuple_entry):
		"""
		This can  be overwritten to convert tuples in TriggerLists to bytes (see layer567/http.py)
		return -- byte string representation of this tuple entry
			eg (b"Host", b"localhost") -> b"Host: localhost"
		"""
		return tuple_entry[1]

	def __repr__(self):
		self._lazy_dissect()
		return super().__repr__()

	def __str__(self):
		self._lazy_dissect()
		tl_descr_l = []
		contains_pkt = False

		for val_tl in self:
			if type(val_tl) in TRIGGERLIST_CONTENT_SIMPLE:
				tl_descr_l.append("%s" % str(val_tl))
			else:
				# assume packet
				#pkt_fqn = val_tl.__module__[9:] + "." + val_tl.__class__.__name__
				#tl_descr_l.append(pkt_fqn)
				tl_descr_l.append("%s" % val_tl)
				contains_pkt = True

		if not contains_pkt or len(tl_descr_l) == 0:
			# Oneline output
			return "[" + ", ".join(tl_descr_l) + "]"
		else:
			# Multiline output
			final_descr = ["(see below)\n" + "-" * 10 + "\n"]

			for idx, val in enumerate(tl_descr_l):
				idx_descr = "%s[%d]" % (self._headerfield_name[1:], idx)
				final_descr.append("-> %s:\n%s\n" % (idx_descr, val))
			final_descr.append("-" * 10)
			return "".join(final_descr)
