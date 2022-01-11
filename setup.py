#!/usr/bin/env python

try:
	from setuptools import setup
except ImportError:
	from distutils.core import setup

setup(name="pypacker",
	version="5.1",
	author="Michael Stahn",
	author_email="michael.stahn.42@gmail.com",
	url="https://gitlab.com/mike01/pypacker",
	description="Pypacker: The fast and simple packet creating and parsing module",
	license="GPLv2",
	packages=[
		"pypacker",
		"pypacker.layer12",
		"pypacker.layer3",
		"pypacker.layer4",
		"pypacker.layer567"
	],
	package_data={"pypacker": ["oui_stripped.txt"]},
	classifiers=[
		"Development Status :: 6 - Mature",
		"Intended Audience :: Developers",
		"License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
		"Natural Language :: English",
		"Programming Language :: Python :: 3.3",
		"Programming Language :: Python :: 3.4",
		"Programming Language :: Python :: 3.5",
		"Programming Language :: Python :: 3.6",
		"Programming Language :: Python :: Implementation :: CPython",
		"Programming Language :: Python :: Implementation :: PyPy"
	],
	#install_requires=[
	#	"netifaces",
	#],
	python_requires=">=3.3.*"
)
