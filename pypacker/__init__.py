# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
import logging

logger = logging.getLogger("pypacker")
# logger.setLevel(logging.DEBUG)
logger.setLevel(logging.WARNING)


class NiceFormatter(logging.Formatter):
	FORMATS = {
		logging.DEBUG: "%(module)s -> %(funcName)s -> %(lineno)d: %(message)s",
		logging.INFO: "%(message)s",
		logging.WARNING: "WARNING: %(module)s: %(lineno)d: %(message)s",
		logging.ERROR: "ERROR: %(module)s: %(lineno)d: %(message)s",
		"DEFAULT": "%(message)s"}

	def __init__(self):
		super().__init__(fmt="%(levelno)d: %(msg)s", datefmt=None, style="%")

	def format(self, record):
		format_orig = self._style._fmt
		self._style._fmt = self.FORMATS.get(record.levelno, self.FORMATS["DEFAULT"])
		result = logging.Formatter.format(self, record)

		self._style._fmt = format_orig

		return result


logger_streamhandler = logging.StreamHandler()
logger_formatter = NiceFormatter()
logger_streamhandler.setFormatter(logger_formatter)

logger.addHandler(logger_streamhandler)
