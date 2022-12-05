import struct
import logging

logger = logging.getLogger("pypacker")

# Allows to activate/decative the auto-update of a header field.
# Note: _update_fields() has to be implemented
FIELD_FLAG_AUTOUPDATE	= 1
# Identifies the header field defining the next higher layer type
# Allows to auto-set the value on concatenation: "pkt = eth0 + ip0" sets type field in eth0
# Auto-sets FIELD_FLAG_AUTOUPDATE
# Note: _update_fields() has to be implemented and _update_higherlayer_id() has to be called in it.
FIELD_FLAG_IS_TYPEFIELD	= 2


def get_setter(varname, is_field_type_simple=True, is_field_static=True):
	"""
	varname -- name of the variable to set the property for
	is_field_type_simple -- get property for simple static or dynamic type if True, else TriggerList
	is_field_static -- if is_field_type_simple is True: get static type (int, fixed size bytes, ...),
		else dynamic (format "xs") which can change in format (eg DNS names)

	return -- set-property for simple types or triggerlist
	"""
	varname_shadowed = "_%s" % varname
	varname_shadowed_active = varname_shadowed + "_active"
	varname_shadowed_format = varname_shadowed + "_format"
	object__setattr__ = object.__setattr__
	object__getattribute__ = object.__getattribute__

	def setfield_simple(obj, value):
		"""
		Set value for a simple field

		value -- bytes, int or None
		"""
		if obj._unpacked == False:
			# obj._unpacked = None means: dissect not yet finished
			obj._unpack()

		is_active = obj.__getattribute__(varname_shadowed_active)

		# Toggle active/inactive
		if (value is None and is_active) or (value is not None and not is_active):
			object__setattr__(obj, varname_shadowed_active, not is_active)
			obj._header_format_changed = True
			# logger.debug("deactivating field: %s" % varname_shadowed)

		# Simple dynamic field: update format
		if not is_field_static and value is not None:
			format_new = "%ds" % len(value)
			format_old = object__getattribute__(obj, varname_shadowed_format)

			# Avoid unneeded updates
			if format_new != format_old:
				# logger.debug(">>> changing format for dynamic field: %r / %s / %s" %
				# (obj.__class__, varname_shadowed, format_new))
				object__setattr__(obj, varname_shadowed_format, format_new)
				obj._header_format_changed = True

		#logger.debug("setting simple field: %r=%r" % (varname_shadowed, value))
		if type(value) != memoryview:
			# Allow "self.xyz = some_memoryview" _dissect, avoids "xyz.tobytes()"
			# Actual value is not needed -> will be set in _unpack()
			object__setattr__(obj, varname_shadowed, value)
		obj._header_value_changed = True
		obj._notify_changelistener()

	def setfield_triggerlist(obj, value):
		"""
		Clear list and add value as only value.

		value -- Packet, bytes (single or as list)
		"""
		tl = obj.__getattribute__(varname_shadowed)

		if type(tl) is list:
			# We need to create the original TriggerList in order to unpack correctly
			# _triggerlistName = [b"bytes", callback] or
			# _triggerlistName = [b"", callback] (default initiation)
			# logger.debug(">>> initiating TriggerList")
			tl = obj._header_fields_dyn_dict[varname_shadowed](
				obj,
				dissect_callback=tl[1],
				buffer=tl[0],
				headerfield_name=varname_shadowed
			)
			object.__setattr__(obj, varname_shadowed, tl)

		# This will trigger unpacking
		del tl[:]

		# TriggerList: avoid overwriting dynamic fields eg when using keyword constructor Class(key=val)
		if type(value) is list:
			tl.extend(value)
		else:
			tl.append(value)
		obj._header_value_changed = True
		obj._notify_changelistener()

	if is_field_type_simple:
		return setfield_simple

	return setfield_triggerlist


def get_getter(varname, is_field_type_simple=True):
	"""
	varname -- name of the variable to set the property for
	is_field_type_simple -- get property for simple static or dynamic type if True, else TriggerList
	return -- get-property for simple type or triggerlist
	"""
	varname_shadowed = "_%s" % varname

	def getfield_simple(obj):
		"""
		Unpack field ondemand
		"""
		# logger.debug("getting value for simple field: %s" % varname_shadowed)
		if obj._unpacked == False:
			# obj._unpacked = None means: dissect not yet finished
			obj._unpack()
		# logger.debug("getting simple field: %r=%r" %
		# (varname_shadowed, obj.__getattribute__(varname_shadowed)))
		return obj.__getattribute__(varname_shadowed)

	def getfield_triggerlist(obj):
		tl = obj.__getattribute__(varname_shadowed)
		# logger.debug(">>> getting Triggerlist for %r: %r" % (obj.__class__, tl))

		if type(tl) is list:
			# _triggerlistName = [b"bytes", callback] or
			# _triggerlistName = [b"", callback] (default initiation)
			tl = obj._header_fields_dyn_dict[varname_shadowed](
				obj,
				dissect_callback=tl[1],
				buffer=tl[0],
				headerfield_name=varname_shadowed
			)
			object.__setattr__(obj, varname_shadowed, tl)

		return tl

	if is_field_type_simple:
		return getfield_simple

	return getfield_triggerlist


def configure_packet_header(t, hdrs, header_fmt):
	if hdrs is None:
		return

	# Create a property for every field: property a -> get/set access to _a_shadowed.
	# Using properties will slow down access to header fields but it's needed:
	# This way we get informed about get-access (needed to check for unpack)
	# more efficiently than using __getattribute__ (slow access for header
	# fields vs. slow access for ALL class members).
	# Every header field will get two additional values set:
	# var_active = indicates if header is active
	# var_format = indicates the header format
	for hdr in hdrs:
		# Sanity checks
		# Max packet fields: [name, format, value, flags, {value:key})
		if len(hdr) > 4:
			logger.warning("Amount of field definitions > 4: %r", hdr)

		if hdr[1] is not None:
			try:
				struct.Struct(hdr[1])
			except struct.error:
				raise Exception("Invalid format specified in class %s for header '%s': '%s'" %
					(t.__module__ + "." + t.__name__, hdr[0], hdr[1]))

			if hdr[2] is not None:
				try:
					struct.Struct(hdr[1]).pack(hdr[2])
				except struct.error:
					raise Exception("Invalid value specified in class %s for header '%s' with format '%s': '%s'" %
						(t.__module__ + "." + t.__name__, hdr[0], hdr[1], hdr[2]))

		shadowed_name = "_%s" % hdr[0]
		t._header_field_names_shadowed.append(shadowed_name)
		setattr(t, shadowed_name + "_active", True)

		# Remember header format
		# t._header_field_infos[shadowed_name] = [True, hdr[1]]
		is_field_type_simple = False
		is_field_static = True

		if hdr[1] is not None or (hdr[2] is None or type(hdr[2]) == bytes):
			# Simple static or simple dynamic type
			# we got one of: ("name", format, ???) = static or
			# ("name", None, [None, b"xxx"]) = dynamic
			# -> Format given = static, Format None = dynamic
			is_field_type_simple = True

			if hdr[1] is None:
				# assume simple dynamic field
				is_field_static = False

		setattr(t, shadowed_name + "_format", hdr[1])

		if is_field_type_simple:
			# Assume simple static or simple dynamic type
			fmt = hdr[1]

			if hdr[2] is not None:
				# value given: field is active
				if fmt is None:
					# dynamic field
					fmt = "%ds" % len(hdr[2])
					setattr(t, shadowed_name + "_format", fmt)
				header_fmt.append(fmt)
				t._header_cached.append(hdr[2])
				# logger.debug("--------> field is active: %r" % hdr[0])
			#else:
			#	setattr(t, shadowed_name + "_active", False)

			# Only simple fields can get deactivated
			setattr(t, shadowed_name + "_active", True if hdr[2] is not None else False)

			# Check for auto-update
			if len(hdr) >= 4:
				field_flags = hdr[3]

				if field_flags & FIELD_FLAG_IS_TYPEFIELD != 0:
					#logger.debug("setting _id_fieldname: %r" % (hdr[0]))
					setattr(t, "_id_fieldname", hdr[0])
					# xxx__au_active must be set: read by _update_higherlayer_id
					field_flags |= FIELD_FLAG_AUTOUPDATE

				if field_flags & FIELD_FLAG_AUTOUPDATE != 0:
					#logger.debug("marking %s as auto-update" % hdr[0])
					# remember which fields are auto-update ones, default is active
					setattr(t, hdr[0] + "_au_active", True)

			# Setting/getting value is done via properties.
			# Set initial value via shadowed variable:
			# _varname <- varname [optional in subclass: <- varname_s]
			# logger.debug("init simple type: %s=%r" % (shadowed_name, hdr[2]))
			setattr(t, shadowed_name, hdr[2])
			setattr(t, hdr[0], property(
				get_getter(hdr[0], is_field_type_simple=True),
				get_setter(hdr[0], is_field_type_simple=True, is_field_static=is_field_static)
			))
		else:
			# Assume TriggerList
			# Triggerlists don't have initial default values (and can't get deactivated)
			t._header_fields_dyn_dict[shadowed_name] = hdr[2]
			# Initial value of TiggerLists is: values to init empty list
			setattr(t, shadowed_name, [b"", None])
			setattr(t, hdr[0], property(
				get_getter(hdr[0], is_field_type_simple=False),
				get_setter(hdr[0], is_field_type_simple=False, is_field_static=is_field_static)
			))
			# Format and value needed for correct length in _unpack()
			# Default is empty TriggerList -> 0 bytes
			header_fmt.append("0s")
			t._header_cached.append(b"")


def configure_packet_header_sub(t, hdrs_sub):
	if hdrs_sub is None:
		return

	for name_cbget_cbset in hdrs_sub:
		if len(name_cbget_cbset) < 2:
			logger.warning("subheader length < 2: %d", len(name_cbget_cbset))
			continue
		# logger.debug("setting subheader: %s", name_cbget_cbset[0])

		# (name, cb_get, cb_set)
		if len(name_cbget_cbset) == 3:
			setattr(t, name_cbget_cbset[0], property(name_cbget_cbset[1], name_cbget_cbset[2]))
		# (name, cb_get)
		else:
			setattr(t, name_cbget_cbset[0], property(name_cbget_cbset[1]))


class MetaPacket(type):
	"""
	This Metaclass is a more efficient way of setting attributes than using __init__.
	This is done by reading name, format and default value out of a mendatory __hdr__
	tuple in every subclass. This configuration is set one time when loading the module
	(not at instantiation). Attributes can be normally accessed using "obj.field" notation.
	General note: Callflaw is: __new__ (loading module) -> __init__ (initiate class)

	Header defintition example:
	__hdr__ = (
		("header1", "H", 123), # simple static field
		("header2", "H", None), # simple static field, inactive
		("header3", None, b"xxx"), # simple dynamic field
		("header4", None, None), # simple dynamic field, inactive
		("header5", None, Triggerlist) # TriggerList field
	)

	For values <1 byte a subheader definition eases up setting/getting those values:

	__hdr_sub__ = (
		("header1_sub",
			lambda val: val & 1							# callback to retrieve value
			lambda obj, val: obj.__setattr__(val & 1)	# callback to set value
		),
		...
	)

	CAUTION:
	- List et al are _SHARED_ among all instantiated classes! A copy is needed on
	changes to them without side effects
	- New protocols: header field names must be unique among other variable and method names
	"""
	def __new__(cls, clsname, clsbases, clsdict):
		# Slots (dct["__slots__"] = ...) can't be used because:
		# Setting default values (eg for _header_fields_dyn_dict) must
		# be done in __init__ which increases delay (init for every instantiation...)
		# Sidenote: Setting default values here creates readonly exception later:
		# __slots__ = ("var", ...) -> t.var = None -> p = Clz() -> p.var = 123 won't work (var is readonly)
		# See: https://stackoverflow.com/questions/820671/python-slots-and-attribute-is-read-only
		t = type.__new__(cls, clsname, clsbases, clsdict)
		# Dictionary of TriggerLists: name -> TriggerListClass
		t._header_fields_dyn_dict = {}
		# Cache header for performance reasons, will be set to bytes later on
		t._header_cached = []
		# All header names
		t._header_field_names_shadowed = []
		# All header formats including byte order
		header_fmt = [">"]

		# Varname holding the fieldname containing the id associated with body handler
		# eg Ethernet -> "type" or IP -> "p"
		t._id_fieldname = None

		# Get header-infos: [("name", "format", value), ...]
		hdrs = getattr(t, "__hdr__", None)
		configure_packet_header(t, hdrs, header_fmt)

		# Get sub-header-infos: [("name", cb_get, cb_set), ...]
		hdrs_sub = getattr(t, "__hdr_sub__", None)
		configure_packet_header_sub(t, hdrs_sub)

		# Get handler classes, assume Packet class has no member "__handler__"
		handler = getattr(t, "__handler__", None)

		if handler is not None and len(handler) > 0:
			if handler.__class__ is not dict:
				print("Invalid format of __handler__: not a dictionary! %r", handler)
			else:
				t.load_handler(t, handler)

		# Set of higher_layer classes which force dissecting (update dependants):
		# IP->TCP => IP changed -> TCP needs checksum update and
		# needs to be dissected for this -> TCP is update dependant of IP
		update_deps = getattr(t, "UPDATE_DEPENDANTS", set())
		t._update_dependants = set([ud.__class__ for ud in update_deps])

		# logger.debug(">>> translated header names: %s/%r" % (clsname, t._header_name_translate))
		# Current format as string
		t._header_format = struct.Struct("".join(header_fmt))
		# Track changes to header format (changes to simple dynamic fields or TriggerList)
		t._header_format_changed = False
		# Cached header, return this if nothing changed
		t._header_cached = t._header_format.pack(*t._header_cached)
		# logger.debug("formatstring is: %s" % header_fmt)
		# Body as raw byte string (None if handler is present)
		t._body_bytes = b""
		# Next lower layer: a = b + c -> b will be lower layer for c
		t._lower_layer = None
		t._higher_layer = None
		# Track changes to header values: This is needed for layers like TCP for
		# checksum-recalculation. Set to "True" on changes to header/body values, set to False on "bin()"
		# Track changes to header values
		t._header_value_changed = False
		# Track changes to body value like [None | bytes | body-handler] -> [None | bytes | body-handler]
		# Does not track achanges in body-handler itself
		t._body_value_changed = False
		# Objects which get notified on changes on header or body (shared),
		# eg packet_parent -> TriggerList[packet_sub, ...]:
		# Changes to packet_sub need to be known by packet_parent for format updates
		# and TriggerList to clear cache.
		# Needs to be None do identify uninitialized state.
		t._changelistener = None
		# Parent of the packet which is contained in a triggerlist
		# parent_packet.triggerlist[sub] -> sub._triggelistpacket_parent == parent_packet
		t._triggelistpacket_parent = None
		# Lazy handler data: [name, class, bytes]
		t._lazy_handler_data = None
		# Indicates if static header values got already unpacked
		# [True|False] = Status after dissect, None = pre-dissect (not unpacked)
		t._unpacked = None
		# Concatination of errors, see pypacker.py -> ERROR_...
		t._errors = 0
		return t
