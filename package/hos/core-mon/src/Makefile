
OBJS=core-monitor.o utils.o mem-check.o app-check.o web-login-check.o \
		online-user-check.o	common.o
TARGET=core-mon
LINK=-lpthread -lrt

.PHONY:all
all:$(TARGET)

$(TARGET):$(OBJS)
	$(CC) $(LDFLAGS) $(LINK) -o $(TARGET) $(OBJS)

%.o:%.c
	$(CC) -c $(CFLAGS) $< -o $@

.PHONY: clean
clean:
	rm -f $(OBJS) $(TARGET)

