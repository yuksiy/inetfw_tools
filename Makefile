# System Configuration
srcdir = .

PERL ?= /usr/bin/perl
prefix ?= /usr/local
exec_prefix ?= $(prefix)

scriptbindir ?= $(prefix)/bin
datadir ?= $(scriptbindir)
datarootdir ?= $(prefix)/share

bindir ?= $(exec_prefix)/bin
libdir ?= $(exec_prefix)/lib
sbindir ?= $(exec_prefix)/sbin

sysconfdir ?= $(prefix)/etc
docdir ?= $(datarootdir)/doc/$(PROJ)
infodir ?= $(datarootdir)/info
mandir ?= $(datarootdir)/man
localstatedir ?= $(prefix)/var

CHECK_SCRIPT_SH = /bin/sh -n
CHECK_SCRIPT_PL = $(PERL) -c

INSTALL = /usr/bin/install -p
INSTALL_PROGRAM = $(INSTALL)
INSTALL_SCRIPT = $(INSTALL)
INSTALL_DATA = $(INSTALL) -m 644


# Inference Rules

# Macro Defines
PROJ = inetfw_tools
VER = 1.0.1
TAG = v$(VER)

TAR_SORT_KEY ?= 6,6

SUBDIRS-TEST-SCRIPTS-SH = \

SUBDIRS-TEST = \
				$(SUBDIRS-TEST-SCRIPTS-SH) \

SUBDIRS = \
				$(SUBDIRS-TEST) \

PROGRAMS = \

SCRIPTS-SH = \

SCRIPTS-PL = \
				inetfw.pl \
				inetfw_netsh.pl \

SCRIPTS-OTHER = \
				inetfw_netsh_main.bat \

SCRIPTS = \
				$(SCRIPTS-SH) \
				$(SCRIPTS-PL) \
				$(SCRIPTS-OTHER) \

DATA = \

DOC = \
				LICENSE \
				README.md \
				TODO \
				examples/README.md \
				examples/default.win10home/output/netsh-advfirewall-firewall-show-rule.cmd.ja.tsv \
				examples/default.win10home/output/netsh-advfirewall-firewall-show-rule.cmd.ja.tsv.err \
				examples/default.win10home/output/netsh-advfirewall-firewall-show-rule.cmd.ja.txt \
				examples/default.win10home/output/netsh-advfirewall-firewall-show-rule.cmd.ja.txt.err \
				examples/default.win10home/output/netsh-advfirewall-firewall-show-rule.ja.tsv \
				examples/default.win10home/output/netsh-advfirewall-firewall-show-rule.ja.tsv.err \
				examples/default.win10home/output/netsh-advfirewall-firewall-show-rule.ja.txt \
				examples/default.win10home/output/netsh-advfirewall-show-allprofiles.cmd.ja.tsv \
				examples/default.win10home/output/netsh-advfirewall-show-allprofiles.ja.tsv \
				examples/default.win10home/output/netsh-advfirewall-show-allprofiles.ja.txt \
				examples/default.win10home/spreadsheet/firewall-profile.ods \
				examples/default.win10home/spreadsheet/firewall-rule.ods \

# Target List
test-recursive \
:
	@target=`echo $@ | sed s/-recursive//`; \
	list='$(SUBDIRS-TEST)'; \
	for subdir in $$list; do \
		echo "Making $$target in $$subdir"; \
		echo " (cd $$subdir && $(MAKE) $$target)"; \
		(cd $$subdir && $(MAKE) $$target); \
	done

all: \
				$(PROGRAMS) \
				$(SCRIPTS) \
				$(DATA) \

# Check
check: check-SCRIPTS-SH check-SCRIPTS-PL

check-SCRIPTS-SH:
	@list='$(SCRIPTS-SH)'; \
	for i in $$list; do \
		echo " $(CHECK_SCRIPT_SH) $$i"; \
		$(CHECK_SCRIPT_SH) $$i; \
	done

check-SCRIPTS-PL:
	@list='$(SCRIPTS-PL)'; \
	for i in $$list; do \
		echo " $(CHECK_SCRIPT_PL) $$i"; \
		$(CHECK_SCRIPT_PL) $$i; \
	done

# Test
test:
	$(MAKE) test-recursive

# Install
install: install-SCRIPTS install-DATA install-DOC

install-SCRIPTS:
	@list='$(SCRIPTS)'; \
	for i in $$list; do \
		dir="`dirname \"$(DESTDIR)$(scriptbindir)/$$i\"`"; \
		if [ ! -d "$$dir/" ]; then \
			echo " mkdir -p $$dir/"; \
			mkdir -p $$dir/; \
		fi;\
		echo " $(INSTALL_SCRIPT) $$i $(DESTDIR)$(scriptbindir)/$$i"; \
		$(INSTALL_SCRIPT) $$i $(DESTDIR)$(scriptbindir)/$$i; \
	done

install-DATA:
	@list='$(DATA)'; \
	for i in $$list; do \
		dir="`dirname \"$(DESTDIR)$(datadir)/$$i\"`"; \
		if [ ! -d "$$dir/" ]; then \
			echo " mkdir -p $$dir/"; \
			mkdir -p $$dir/; \
		fi;\
		echo " $(INSTALL_DATA) $$i $(DESTDIR)$(datadir)/$$i"; \
		$(INSTALL_DATA) $$i $(DESTDIR)$(datadir)/$$i; \
	done

install-DOC:
	@list='$(DOC)'; \
	for i in $$list; do \
		dir="`dirname \"$(DESTDIR)$(docdir)/$$i\"`"; \
		if [ ! -d "$$dir/" ]; then \
			echo " mkdir -p $$dir/"; \
			mkdir -p $$dir/; \
		fi;\
		echo " $(INSTALL_DATA) $$i $(DESTDIR)$(docdir)/$$i"; \
		$(INSTALL_DATA) $$i $(DESTDIR)$(docdir)/$$i; \
	done

# Pkg
pkg:
	@$(MAKE) DESTDIR=$(CURDIR)/$(PROJ)-$(VER).$(ENVTYPE) install; \
	tar cvf ./$(PROJ)-$(VER).$(ENVTYPE).tar ./$(PROJ)-$(VER).$(ENVTYPE) > /dev/null; \
	tar tvf ./$(PROJ)-$(VER).$(ENVTYPE).tar 2>&1 | sort -k $(TAR_SORT_KEY) | tee ./$(PROJ)-$(VER).$(ENVTYPE).tar.list.txt; \
	gzip -f ./$(PROJ)-$(VER).$(ENVTYPE).tar; \
	rm -fr ./$(PROJ)-$(VER).$(ENVTYPE)

# Dist
dist:
	@git archive --format=tar --prefix=$(PROJ)-$(VER)/ $(TAG) > ../$(PROJ)-$(VER).tar; \
	tar tvf ../$(PROJ)-$(VER).tar 2>&1 | sort -k $(TAR_SORT_KEY) | tee ../$(PROJ)-$(VER).tar.list.txt; \
	gzip -f ../$(PROJ)-$(VER).tar
