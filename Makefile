# How to Make a Release
# ---------------------
#
# This file answers the question "how to make a release" hopefully
# better than a document does (only meejah and warner may currently do
# the "upload to PyPI" part anyway)
#

default:
	echo "see Makefile"
	echo "Make a new tag, then 'make release'"
	echo "git tag

release:
	@echo "Is checkout clean?"
	git diff-files --quiet
	git diff-index --quiet --cached HEAD --

	@echo "Install required build software"
	python3 -m pip install docutils

	@echo "Test README"
	python3 setup.py check -s

	@echo "Is GPG Agent running, and has key?"
	gpg --pinentry=loopback -u meejah@meejah.ca --armor --clear-sign NEWS

	@echo "Build and sign wheel"
	python3 setup.py bdist_wheel
	gpg --pinentry=loopback -u meejah@meejah.ca --armor --detach-sign dist/spake2-`git describe --abbrev=0 | tail -c +2`-py3-none-any.whl
	ls dist/*`git describe --abbrev=0 | tail -c +2`*

	@echo "Build and sign source-dist"
	python3 setup.py sdist
	gpg --pinentry=loopback -u meejah@meejah.ca --armor --detach-sign dist/spake2-`git describe --abbrev=0 | tail -c +2`.tar.gz
	ls dist/*`git describe --abbrev=0 | tail -c +2`*

release-test:
	gpg --verify dist/spake2-`git describe --abbrev=0 | tail -c +2`.tar.gz.asc
	gpg --verify dist/spake2-`git describe --abbrev=0 | tail -c +2`-py3-none-any.whl.asc
	python -m venv test_spake2_venv
	test_spake2_venv/bin/pip install --upgrade pip
	test_spake2_venv/bin/pip install dist/spake2-`git describe --abbrev=0 | tail -c +2`-py3-none-any.whl
	test_spake2_venv/bin/python -c "import spake2"
	test_spake2_venv/bin/pip uninstall -y spake2
	test_spake2_venv/bin/pip install dist/spake2-`git describe --abbrev=0 | tail -c +2`.tar.gz
	test_spake2_venv/bin/python -c "import spake2"
	rm -rf test_spake2_venv

release-upload:
	twine upload --username __token__ --password `cat PRIVATE-release-token` dist/spake2-`git describe --abbrev=0 | tail -c +2`-py3-none-any.whl dist/spake2-`git describe --abbrev=0 | tail -c +2`-py3-none-any.whl.asc dist/spake2-`git describe --abbrev=0 | tail -c +2`.tar.gz dist/spake2-`git describe --abbrev=0 | tail -c +2`.tar.gz.asc
	mv dist/*-`git describe --abbrev=0 | tail -c +2`.tar.gz.asc signatures/
	mv dist/*-`git describe --abbrev=0 | tail -c +2`-py3-none-any.whl.asc signatures/
	git push origin-push `git describe --abbrev=0 | tail -c +2`
