##
##  Makefile for pp
##

CFLAGS = -W -Wall -std=c99 -O2 -s
#CFLAGS = -W -Wall -std=c99 -g

#CC_LINUX32        = /opt/hashcat-toolchain/linux32/bin/i686-hashcat-linux-gnu-gcc
#CC_LINUX64        = /opt/hashcat-toolchain/linux64/bin/x86_64-hashcat-linux-gnu-gcc
CC_LINUX32        = gcc
CC_LINUX64        = gcc
CC_WINDOWS32      = /usr/bin/i686-w64-mingw32-gcc
CC_WINDOWS64      = /usr/bin/x86_64-w64-mingw32-gcc
CC_OSX32          = /usr/bin/i686-apple-darwin10-gcc
CC_OSX64          = /usr/bin/i686-apple-darwin10-gcc

CFLAGS_LINUX32    = $(CFLAGS) -m32 -DLINUX
CFLAGS_LINUX64    = $(CFLAGS) -m64 -DLINUX
CFLAGS_WINDOWS32  = $(CFLAGS) -m32 -DWINDOWS
CFLAGS_WINDOWS64  = $(CFLAGS) -m64 -DWINDOWS
CFLAGS_OSX32      = $(CFLAGS) -m32 -DOSX
CFLAGS_OSX64      = $(CFLAGS) -m64 -DOSX

#LIBGMP_LINUX32    = /opt/hashcat-toolchain/gmp/linux32
#LIBGMP_LINUX64    = /opt/hashcat-toolchain/gmp/linux64
LIBGMP_LINUX32    = .
LIBGMP_LINUX64    = .
LIBGMP_WIN32      = /opt/hashcat-toolchain/gmp/win32
LIBGMP_WIN64      = /opt/hashcat-toolchain/gmp/win64
LIBGMP_OSX32      = /opt/hashcat-toolchain/gmp/osx32
LIBGMP_OSX64      = /opt/hashcat-toolchain/gmp/osx64

all: pp64.bin

pp32: pp32.bin pp32.exe pp32.app
pp64: pp64.bin pp64.exe pp64.app

clean:
	rm -f pp32.bin pp64.bin pp32.exe pp64.exe pp32.app pp64.app

pp32.bin: pp.c
	$(CC_LINUX32)   $(CFLAGS_LINUX32)   -o $@ $^ -I$(LIBGMP_LINUX32)/include -L$(LIBGMP_LINUX32)/lib -lgmp

pp64.bin: pp.c
	$(CC_LINUX64)   $(CFLAGS_LINUX64)   -o $@ $^ -I$(LIBGMP_LINUX64)/include -L$(LIBGMP_LINUX64)/lib -lgmp

pp32.exe: pp.c
	$(CC_WINDOWS32) $(CFLAGS_WINDOWS32) -o $@ $^ -I$(LIBGMP_WIN32)/include   -L$(LIBGMP_WIN32)/lib   -lgmp

pp64.exe: pp.c
	$(CC_WINDOWS64) $(CFLAGS_WINDOWS64) -o $@ $^ -I$(LIBGMP_WIN64)/include   -L$(LIBGMP_WIN64)/lib   -lgmp

pp32.app: pp.c
	$(CC_OSX32)     $(CFLAGS_OSX32)     -o $@ $^ -I$(LIBGMP_OSX32)/include   -L$(LIBGMP_OSX32)/lib   -lgmp

pp64.app: pp.c
	$(CC_OSX64)     $(CFLAGS_OSX64)     -o $@ $^ -I$(LIBGMP_OSX64)/include   -L$(LIBGMP_OSX64)/lib   -lgmp

