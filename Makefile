PREFIX ?= /usr/local

.PHONY: install uninstall check test lint

install:
	PREFIX=$(PREFIX) ./install.sh

uninstall:
	PREFIX=$(PREFIX) ./install.sh --uninstall

check: lint test

lint:
	bash -n bin/nst-cockpit
	shellcheck -S warning -e SC2086,SC2016,SC2034,SC2046,SC2068 bin/nst-cockpit install.sh tests/run.sh
	groff -man -Tutf8 -ww -z man/nst-cockpit.8

test:
	tests/run.sh
