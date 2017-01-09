#CC=mips-openwrt-linux-uclibc-gcc

#AR=mips-openwrt-linux-uclibc-ar

#OBJCOPY=mips-openwrt-linux-uclibc-objcopy

#LD=mips-openwrt-linux-uclibc-ld

CFLAGS=-O3 -fPIC -Wall -ffunction-sections

LIBS= -L. -lcgic -ldbusapi -lm -lxml2 -lz 

#LD_PATH = -L../../../../../staging_dir/target-mips_34kc_uClibc-0.9.33.2/usr/lib/
LD_PATH = -L $(STAGING_DIR)/usr/lib
LDFLAGS = -shared -Wl,-soname,libcgic.so.0
LDFLAGS_CGI += -Wl,--gc-sections 

INCLUDE += -I.
       
XML_LIB = -lxml2 -lz

CGIFILES_WP := $(shell echo wp_*.c)
CGIFILES_WS := $(shell echo ws_*.c)

CGIOBJS_WP := $(CGIFILES_WP:.c=.o)
CGIOBJS_WS := $(CGIFILES_WS:.c=.o)

ALL_CGIFILES := $(CGIFILES_WP:.c=.cgi)

sources=$(CGIOBJS_WP) $(CGIOBJS_WS)

all: $(ALL_CGIFILES) userm_cli


%.cgi:%.o libdbusapi.a libcgic.so 
	$(CC) $<  -o $@_temp $(LDFLAGS_CGI) $(LD_PATH) $(LIBS)
	$(OBJCOPY) -S --strip-all $@_temp $@;rm -f $@_temp

install: libcgic.a
	cp libcgic.a /usr/lib
	cp cgic.h /usr/include
	@echo libcgic.a is in /usr/lib. cgic.h is in /usr/include.

libcgic.so: cgic.o
	$(CC) -fPIC $(LDFLAGS) -o libcgic.so.0.1 $^
	ln -s libcgic.so.0.1 libcgic.so.0
	ln -s libcgic.so.0.1 libcgic.so
#	cp libcgic.so.0.1 /usr/lib
#	$(AR) rc libcgic.a cgic.o
#	$(RANLIB) libcgic.a

libdbusapi.a:$(CGIOBJS_WS)
#	$(CC) -shared -fPIC -Wl,-soname,libdbusapi.so.0 -o libdbusapi.so.0.1 $^
#	ln -s libdbusapi.so.0.1 libdbusapi.so.0
#	ln -s libdbusapi.so.0.1 libdbusapi.so
	$(AR) rc libdbusapi.a $(CGIOBJS_WS)  
	$(RANLIB) libdbusapi.a

%.d: %.c
	set -e; rm -f $@; \
	$(CC) -MM $(CFLAGS) $(INCLUDE) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

userm_cli:user_data_info.o
	$(CC) $^ $(LD_PATH)  -o $@
.c.o:
	$(CC) $(CFLAGS) -I$(INCLUDE) -c $< -o $@

clean:
	rm -f *.o *.a *.d *.so* capture *.cgi

