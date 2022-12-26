# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
"""
Accessing via lists is faster than via __getattribute__
"""
import time

class A(object):
	def __init__(self):
		self._val = b"someval"

	def get_val_ga(self):
		return self.__getattribute__("_val")

	val = property(get_val_ga)

class B(object):
	def __init__(self):
		self._val = [b"someval"]

	def get_val_list(self):
		return self._val[0]

	val = property(get_val_list)


iters = 999999
start = time.time()

for i in range(iters):
	a = A()
	x = a.val
end = time.time()
print(f"diff: {end-start}")


start = time.time()

for i in range(iters):
	b = B()
	x = b.val
end = time.time()
print(f"diff: {end-start}")
