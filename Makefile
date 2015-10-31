# ------------------------------------------------------------------------------
# Copyright (C) 2008 Robert Ernst <robert.ernst@aon.at>
#
# This file may be distributed and/or modified under the terms of the
# GNU General Public License version 2 as published by the Free Software
# Foundation and appearing in the file LICENSE.GPL included in the
# packaging of this file.
#
# This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
# WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
# 
# See COPYING for GPL licensing information.
#



# ------------------------------------------------------------------------------
# Build instructions
#
# For cross-compilation, define CC, e.g. CC=arm-linux-gcc
# For debugging code, add -DDEBUG -g to OFLAGS
# For optimizing code, add -O2 to OFLAGS
# For compiling for FreeBSD, change CFLAGS from -D__LINUX__  to -D__FREEBSD__
# For compiling the demo extension, add -D__DEMO__ to CFLAGS
# To compile the programm, simply call 'make'
#

CC	= gcc
STRIP	= strip
HEADERS	= mini_snmpd.h
SOURCES	= mini_snmpd.c protocol.c mib.c globals.c utils.c linux.c freebsd.c
VERSION = 1.1
VENDOR	= .1.3.6.1.4.1
OFLAGS	= -O2 -DDEBUG -g
CFLAGS	= -Wall -Werror -DVERSION="\"$(VERSION)\"" -DVENDOR="\"$(VENDOR)\"" \
	  $(OFLAGS) -D__TRAPS__ -D__LINUX__ -D__DEMO__
LDFLAGS	= $(OFLAGS)
TARGET	= mini_snmpd
MAN 	= mini_snmpd.8
DOC 	= CHANGELOG COPYING README TODO



# ------------------------------------------------------------------------------
# Do not change content below
#

.PHONY: build strip install tags clean dist

$(TARGET): $(SOURCES:.c=.o)
	$(CC) $(LDFLAGS) $(SOURCES:.c=.o) -o $(TARGET)

$(SOURCES:.c=.o): $(HEADERS)

%.o : %.c
	$(CC) -c $(CFLAGS) $(@:.o=.c) -o $@

build: $(TARGET)

strip: $(TARGET)
	$(STRIP) $(TARGET)

install:
	install -d -m 0775 $(INSTALL_ROOT)/sbin/
	install -d -m 0775 $(INSTALL_ROOT)/share/doc/$(TARGET)-$(VERSION)
	install -d -m 0775 $(INSTALL_ROOT)/share/man/man8
	install -m 0775 $(TARGET) $(INSTALL_ROOT)/sbin/
	install -m 0664 $(MAN) $(INSTALL_ROOT)/share/man/man8/
	install -m 0664 $(DOC) $(INSTALL_ROOT)/share/doc/$(TARGET)-$(VERSION)/

tags:
	ctags *.[ch]

clean:
	rm -f $(SOURCES:.c=.o) $(TARGET) $(TARGET).tar.gz

dist:
	mkdir -p tmp
	cd tmp && cvs export -rHEAD tools/$(TARGET)
	cd tmp/tools && tar -cvzf $(TARGET).tar.gz $(TARGET)
	cp tmp/tools/$(TARGET).tar.gz .
	rm -rf tmp

