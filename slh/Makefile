#	Makefile
#	Markku-Juhani O. Saarinen <mjos@iki.fi>.  See LICENSE.	

#	===	This is a PC-target makefile for the core SLH-DSA implementation.
#		No hardware acceleration if used like this -- mainly useful for
#		debug purposes.

TARGET	?=	kat_test
CSRC	=	$(wildcard *.c)
DEBUG	?=  0

EXCLUDE_LIST = kat_test.c ACVP_keygen_test.c ACVP_sig_test.c ACVP_ver_test.c

EXCLUDE_LIST := $(filter-out $(TARGET).c,$(EXCLUDE_LIST))
CSRC := $(filter-out $(EXCLUDE_LIST),$(CSRC))

# ifeq ($(TARGET),kat_test)
# 	CSRC	+=	../drv/kat_drbg.c
# endif
CSRC	+=	../drv/kat_drbg.c

ifeq ($(DEBUG),1)
    CFLAGS += -g -O0 -DDEBUG
    BUILD_MODE := debug
endif

OBJS	= 	$(CSRC:.c=.o)
KATNUM	?=	1

CC 		=	gcc
CFLAGS	+=	-Wall -march=native -Ofast -DNDEBUG
#CFLAGS	+=	-Wall -Wextra -Wshadow -fsanitize=address,undefined -g
CFLAGS	+=	-I. -I../drv -DKATNUM=$(KATNUM)
LDLIBS	+=

$(TARGET):	$(OBJS)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)

%.o:	%.[cS]
	$(CC) $(CFLAGS) -c $^ -o $@

test:	$(TARGET)
	./$(TARGET)	
	sha256sum *.rsp > t.log
	cat t.log ../kat/kat$(KATNUM)-sha256.txt | sort | uniq -c -w 64
	@echo "NOTE >2<- indicates test vector comparison match, 1 is a failure."
clean:
	$(RM) -rf $(TARGET) $(OBJS) *.rsp *.req *.log