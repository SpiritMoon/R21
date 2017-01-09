
OBJS=configd.o
TARGET=configd

.PHONY:all
all:$(TARGET)

$(TARGET):$(OBJS)
	${CC} ${LDFLAGS} -o $(TARGET) $(OBJS)

%.o:%.c
	${CC} -c ${CFLAGS} $< -o $@

.PHONY: clean
clean:
	rm -f $(OBJS) $(TARGET)

