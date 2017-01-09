CFLAGS += -Wall -g -O0

RM = /bin/rm -f

CLUSTER_MGT_OBJS = cluster_mgt.o libhccp.o timerlib.o sock_domain.o common.o approtocol.o hccpprotocol.o Log.o

CLUSTER_MGT_SRCS = $(CLUSTER_MGT_OBJS:.o=.c)

CLUSTER_MGT_DEPS := $(CLUSTER_MGT_OBJS:.o=.d)

CLUSTER_MGT_APP = cluster_mgt

$(CLUSTER_MGT_APP): $(CLUSTER_MGT_OBJS) 

	$(CC) $(CLUSTER_MGT_OBJS) $(CFLAGS)    -lpthread -o $(CLUSTER_MGT_APP)

%.o:%.c
	${CC} -c ${CFLAGS} $< -o $@

install:
	cp cluster_mgt ../../res
	
clean: 
	$(RM) $(CLUSTER_MGT_APP) $(CLUSTER_MGT_OBJS) $(CLUSTER_MGT_DEPS)

