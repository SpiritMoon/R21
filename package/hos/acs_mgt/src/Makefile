
LIBS_DEPEND=-lhccp -lpthread

OBJS=acs_mgt.o timerlib.o

CFLAGS=-Wall

obj += tools/

__TARGET=acs_mgt
TARGET=$(__TARGET)

.PHONY:all
all:$(TARGET)

.PHONY: clean
clean:
	rm -f $(OBJS) $(TARGET)

$(TARGET):$(OBJS)
	${CC} ${CFLAGS} ${LDFLAGS}  -o $(TARGET) $(OBJS) ${LIBS_DEPEND}
%.o:%.c
	${CC} -c ${CFLAGS} $< -o $@


