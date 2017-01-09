
CCFG_BIN=cluster-cfg
CCFG_OBJS=cluster-cfg.o

ENC_BIN=enc-plain
ENC_OBJS=encrypt_plain_passwd.o

TARGETS=${CCFG_BIN} ${ENC_BIN}
OBJS=${CCFG_OBJS} ${ENC_OBJS}

.PHONY:all
all: ${TARGETS}

${ENC_BIN}: ${ENC_OBJS}
	${CC} ${LDFLAGS} -o ${ENC_BIN} ${ENC_OBJS}

${TARGET}: ${CCFG_OBJS}
	${CC} ${LDFLAGS} -o ${CCFG_BIN} ${CCFG_OBJS}

%.o:%.c
	${CC} -c ${CFLAGS} $< -o $@

.PHONY: clean
clean:
	rm -f $(OBJS) $(TARGETS)

