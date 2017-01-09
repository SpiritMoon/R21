CFLAGS += -Wall  -g -O0
LIBS_DEPEND=-lpthread

OBJS=cluster_cor.o libhccp.o
obj += tools/
TOOL_DIR= ./tools

__TOOL=cluster_cli
__TARGET=cluster_cor
TARGET=$(__TARGET)
TOOL=$(__TOOL)
#INC = -I./igmpsnpcom

.PHONY:all
all:$(TARGET) $(TOOL)

.PHONY: clean
clean:
	rm -f $(OBJS) $(TARGET)
	make clean -C  $(TOOL_DIR)

$(TOOL):
	make -C  $(TOOL_DIR)

$(TARGET):$(OBJS)
	${CC} ${CFLAGS} ${LDFLAGS}  -o $(TARGET) $(OBJS) ${LIBS_DEPEND}
%.o:%.c
#	${CC} -c ${CFLAGS} ${INC} $< -o $@
	${CC} -c ${CFLAGS} $< -o $@


