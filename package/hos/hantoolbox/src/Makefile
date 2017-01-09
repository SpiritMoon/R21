TARGET	:=hantoolbox
OBJS	:=hantoolbox.o str2hexascii.o

all:$(OBJS)
	${CC} ${LDFLAGS} -o $(TARGET) $^

%.o:%.c
	${CC} ${CFLAGS} -c -o $@ $^

clean:
	rm -rf $(TARGET) $(OBJS)
