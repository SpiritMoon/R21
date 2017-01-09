OBJS=tech_support_command.o
__TARGET=tech_support_command
TARGET=$(__TARGET)

.PHONY:all
all:$(TARGET)

.PHONY: clean
clean:
	rm -f $(OBJS) $(TARGET)

$(TARGET):$(OBJS)
	${CC} ${LDFLAGS} $(LIBS_DEPEND) -o $(TARGET) $(OBJS)
%.o:%.c
	${CC} -c ${CFLAGS} -pthread $< -o $@


