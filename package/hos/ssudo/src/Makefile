
OBJS=ssudo.o
__TARGET=ssudo
TARGET=$(__TARGET)
LIBS_DEPEND=

.PHONY:all
all:$(TARGET)

.PHONY: clean
clean:
	rm -f $(OBJS) $(TARGET)

$(TARGET):$(OBJS)
	${CC} ${LDFLAGS} $(LIBS_DEPEND) -o $(TARGET) $(OBJS)
%.o:%.c
	${CC} -c ${CFLAGS}  $< -o $@
