
RM = /bin/rm -f
INCS += -I.
CFLAGS += ${INCS} -Wall -g -O0

ROGUEAP_OBJS = bscanningap.o clusterap.o compare.o control.o fdb.o netlink.o \
		parse_message.o rogue_ap.o rogue_debug.o sock_domain.o timer.o wireless.o

ROGUEAP_SRCS = $(ROGUEAP_OBJS:.o=.c)

ROGUEAP_DEPS := $(ROGUEAP_OBJS:.o=.d)

ROGUEAP_APP = rogueap

$(ROGUEAP_APP): $(ROGUEAP_OBJS) 

	$(CC) $(ROGUEAP_OBJS) $(CFLAGS) -luci -lpthread -o $(ROGUEAP_APP)

%.o:%.c
	${CC} -c ${CFLAGS} $< -o $@

install:
	cp rogueap ../../res
clean: 
	$(RM) $(ROGUEAP_APP) $(ROGUEAP_OBJS) $(ROGUEAP_DEPS)

clean_deps:
	$(ROGUEAP_DEPS)
	
-include $(ROGUEAP_DEPS)
