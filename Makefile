INST_PREFIX ?= /usr/local/openresty
INST_LIBDIR ?= $(INST_PREFIX)/lualib
INST_LUADIR ?= $(INST_PREFIX)/site/lualib
INSTALL ?= install
UNAME ?= $(shell uname)
CFLAGS := -O2 -g -Wall -fpic -std=c99 -Wno-pointer-to-int-cast -Wno-int-to-pointer-cast
C_SO_NAME := librax.so
LDFLAGS := -shared

# on Mac OS X, one should set instead:
# for Mac OS X environment, use one of options
ifeq ($(UNAME),Darwin)
  C_SO_NAME := librax.dylib
	LDFLAGS := -bundle -undefined dynamic_lookup
endif

MY_CFLAGS := $(CFLAGS) -DBUILDING_SO
MY_LDFLAGS := $(LDFLAGS) -fvisibility=hidden

OBJS := src/rax.o src/easy_rax.o

.PHONY: default
default: compile


### clean:        Remove generated files
.PHONY: clean
clean:
	rm -f $(C_SO_NAME) $(OBJS)


### compile:      Compile library
.PHONY: compile

compile: $(C_SO_NAME)

${OBJS} : %.o : %.c
	$(CC) $(MY_CFLAGS) -c $< -o $@

${C_SO_NAME} : ${OBJS}
	$(CC) $(MY_LDFLAGS) $(OBJS) -o $@


### install:      Install the library to runtime
.PHONY: install
install:
	$(INSTALL) -d $(INST_LUADIR)/resty/
	$(INSTALL) resty/rax.lua $(INST_LUADIR)/resty/
	$(INSTALL) -d $(INST_LIBDIR)/
	$(INSTALL) $(C_SO_NAME) $(INST_LIBDIR)/