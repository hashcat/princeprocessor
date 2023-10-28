##
##  Makefile for pp
##

CFLAGS = -W -Wall -std=c99 -O2 -s
#CFLAGS = -W -Wall -std=c99 -g

UNAME                   := $(shell uname -s)

CC_LINUX32        = gcc
CC_LINUX64        = gcc
CC_WINDOWS32      = /usr/bin/i686-w64-mingw32-gcc
CC_WINDOWS64      = /usr/bin/x86_64-w64-mingw32-gcc
CC_OSX32          = /usr/bin/i686-apple-darwin10-gcc
CC_OSX64          = /usr/bin/i686-apple-darwin10-gcc
CC_APPLE_ARM64    = gcc

CFLAGS_LINUX32    = $(CFLAGS) -m32 -DLINUX
CFLAGS_LINUX64    = $(CFLAGS) -m64 -DLINUX
CFLAGS_WINDOWS32  = $(CFLAGS) -m32 -DWINDOWS
CFLAGS_WINDOWS64  = $(CFLAGS) -m64 -DWINDOWS
CFLAGS_OSX32      = $(CFLAGS) -m32 -DOSX
CFLAGS_OSX64      = $(CFLAGS) -m64 -DOSX
CFLAGS_APPLE_ARM64= $(CFLAGS) -arch arm64 -DAPPLE

ifeq ($(UNAME),Darwin)

all: ppAppleArm64.bin

ppAppleArm64: ppAppleArm64.bin

clean:
	rm -f ppAppleArm64.bin

else

all: pp64.bin

pp32: pp32.bin pp32.exe pp32.app
pp64: pp64.bin pp64.exe pp64.app

clean:
	rm -f pp32.bin pp64.bin pp32.exe pp64.exe pp32.app pp64.app

endif

pp32.bin: pp.c mpz_int128.h
	$(CC_LINUX32)   $(CFLAGS_LINUX32)   -o $@ pp.c

pp64.bin: pp.c mpz_int128.h
	$(CC_LINUX64)   $(CFLAGS_LINUX64)   -o $@ pp.c

pp32.exe: pp.c mpz_int128.h
	$(CC_WINDOWS32) $(CFLAGS_WINDOWS32) -o $@ pp.c

pp64.exe: pp.c mpz_int128.h
	$(CC_WINDOWS64) $(CFLAGS_WINDOWS64) -o $@ pp.c

pp32.app: pp.c mpz_int128.h
	$(CC_OSX32)     $(CFLAGS_OSX32)     -o $@ pp.c

pp64.app: pp.c mpz_int128.h
	$(CC_OSX64)     $(CFLAGS_OSX64)     -o $@ pp.c

ppAppleArm64.bin: pp.c mpz_int128.h
	$(CC_APPLE_ARM64) $(CFLAGS_APPLE_ARM64) -o $@ pp.c
