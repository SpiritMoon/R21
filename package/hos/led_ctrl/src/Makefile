
OBJS=led_ctrl.o
__TARGET=led_ctrl
TARGET=$(__TARGET)
LIBS_DEPEND=-pthread -lubus -lubox

.PHONY:all
all:$(TARGET)

.PHONY: clean
clean:
	rm -f $(OBJS) $(TARGET)

$(TARGET):$(OBJS)
	${CC} ${LDFLAGS} $(LIBS_DEPEND) -o $(TARGET) $(OBJS)
%.o:%.c
	${CC} -c ${CFLAGS} -pthread $< -o $@
