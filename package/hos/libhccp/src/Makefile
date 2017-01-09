

OBJS=libhccp.c
_OBJS=libhccp.o

__TARGET=libhccp.a
TARGET=$(__TARGET)

.PHONY:all
all:$(TARGET)

.PHONY: clean
clean:
	rm -f $(_OBJS) $(TARGET)

$(TARGET):$(_OBJS)
	$(AR) cr $(TARGET) $(_OBJS)
$(_OBJS):$(OBJS)
	${CC} ${CFLAGS} ${LDFLAGS}  -c $(OBJS) -o $(_OBJS)
	
%.o:%.c
	${CC} -c ${CFLAGS} $< -o $@
