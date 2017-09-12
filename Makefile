#
# File          : Makefile
# Description   : Build file for CSE543 project 1, applied cryptography
#                 


# Environment Setup
#LIBDIRS=-L. -L/opt/local/lib
#INCLUDES=-I. -I/opt/local/include
CC=gcc 
CFLAGS=-c $(INCLUDES) -g -Wall
LINK=gcc -g
LDFLAGS=$(LIBDIRS)
AR=ar rc
RANLIB=ranlib

# Suffix rules
.c.o :
	${CC} ${CFLAGS} $< -o $@

#
# Setup builds

TARGETS=cse543-p1
LIBS=-lcrypto -lm

#
# Project Protections

p1 : $(TARGETS)

cse543-p1 : cse543-pwdmgr.o cse543-kvs.o cse543-cracker.o cse543-ssl.o cse543-util.o
	$(LINK) $(LDFLAGS) cse543-pwdmgr.o cse543-kvs.o cse543-cracker.o cse543-ssl.o cse543-util.o $(LIBS) -o $@

clean:
	rm -f *.o *~ $(TARGETS)

BASENAME=p1
tar: 
	tar cvfz $(BASENAME).tgz -C ..\
	    $(BASENAME)/Makefile \
            $(BASENAME)/cse543-pwdmgr.c \
            $(BASENAME)/cse543-cracker.c \
            $(BASENAME)/cse543-cracker.h \
	    $(BASENAME)/cse543-kvs.c \
	    $(BASENAME)/cse543-kvs.h \
	    $(BASENAME)/cse543-ssl.c \
	    $(BASENAME)/cse543-ssl.h \
	    $(BASENAME)/cse543-util.c \
	    $(BASENAME)/cse543-util.h \
	    $(BASENAME)/rockyou.txt.6.4.a.mc1 \
	    $(BASENAME)/hash.h \

