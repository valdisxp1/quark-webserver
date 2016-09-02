# quark version
VERSION = 0

# Customize below to fit your system

# paths
PREFIX = /usr/local
MANPREFIX = ${PREFIX}/share/man

# includes and libs
INCS = -I. -I/usr/include
LIBS = -L/usr/lib -lc

# flags
CPPFLAGS = -DVERSION=\"${VERSION}\" -D_DEFAULT_SOURCE
CFLAGS = -g -std=c99 -pedantic -Wall -Os ${INCS} ${CPPFLAGS}
LDFLAGS = ${LIBS}

# compiler and linker
CC = cc
