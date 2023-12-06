# set this to the NEXT (not yet published) version
VERSION="5.4"

if [ -z "$1" ]; then
	echo "Usage: $0 [stable | dev]"
	exit 1
fi

function msg {
	echo ""
	echo ">>> $1"
}

case "$1" in
"stable")
	pyfiles=$(find . -name "*.py")

	msg "Changing debug level to WARNING"
	sed -i -r "s/# *(logger.setLevel\(logging.WARNING\))/\1/g;s/^(logger.setLevel\(logging.DEBUG\))/# \1/g" pypacker/pypacker.py

	msg "Replacing version numbers"
	sed -i -r "s/version=\".*\"/version=\"$VERSION\"/g" setup.py

	msg "Searching untracked NOT ignored files... did you forget to add anything?"
	git ls-files --others --exclude-from=.gitignore

	msg "Any TODOs open?"
	for pyfile in $pyfiles; do
		grep --color=auto -H "TODO" "$pyfile"
	done

	msg "Non disabled debug output"
	grep --color=auto -ir "^[^#]*logger.debug" *

	msg "Raw print calls"
	grep --color=auto -r "print(" --exclude "test_pypacker.py" --exclude "README.md" --exclude "switch_setup.sh"\
		--exclude "sniff_n_dump.py" --exclude "list_packet_classes.py" --exclude-dir "examples"

	#msg "doing style checks"
	#msg "PEP8"
	#pep8  --config=./qa_config.txt ./

	msg "flake8"
	flake8 --config=./qa_config.txt ./pypacker

	#msg "Pylint"
	#pylint --rcfile=./.pylintrc $pydir/*.py

	#if [ "$2" = "rebuilddoc" ]; then
	#	msg "regenerating doc"
	#	export PYTHONPATH=$PYTHONPATH:$(pwd)
	#	rm -rf ./doc
	#	cd ./doc_sphinx_generated
	#	make clean html
	#	cd ..
	#	cp -r ./doc_sphinx_generated/_build/html/ ./doc
	#	git add doc
	#fi

	msg "Header definition: string instead of bytes?"
	grep --color=auto -ir -Po "\"\ds\", *\".+"

	msg "set(...) instead of {...}? (still needed for list which need to be made unique)"
	grep --color=auto -ir -Po " set\([^\)]"

	msg "Lower case hex numbers/upper case hex strings?"
	for f in $pyfiles; do
		# Hex numbers in uppercase
		grep --color=auto -H -P "0x[0-9]{0,1}[a-f]{1,2}" $f
		# Hex bytes in lowercase
		grep --color=auto -H -P "\\\\x[0-9]{0,1}[A-F]{1,2}" $f
	done

	msg "Old style unpack like unpack('H', value)? (non precompiled structs)"
	grep --color=auto -ir -P "unpack\([\"\']" | grep --color=auto  -P ".py:"


	if [ "$2" == "v" ]; then
		msg "re-adding tag 'v$VERSION'"
		git tag --del "v$VERSION" 1>&/dev/null
		# remove remote tag
		#git push origin :refs/tags/"v$VERSION" 1>&/dev/null
		git tag "v$VERSION"
	fi

	msg "If everything is OK call: git push -u origin master --tags"
	# PyPi upload
	# Source: https://packaging.python.org/tutorials/packaging-projects/#uploading-your-project-to-pypi
	# # Create package in dist/
	# python setup.py sdist
	# # Upload. Chose correct version in dist/
	# python3 -m twine upload --repository-url  https://upload.pypi.org/legacy/ dist/pypacker-...
;;
"dev")
	msg "Changing debug level to DEBUG"
	sed -i -r "s/# *(logger.setLevel\(logging.DEBUG\))/\1/;s/^(logger.setLevel\(logging.WARNING\))/# \1/g" pypacker/pypacker.py
;;
esac
