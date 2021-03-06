VER ?= 1.0.0
VER_MJR := $(shell echo $(VER) | awk -F '.' '{print $$1}')

BLD_INC_PATH = $(BLD_PREFIX)$(INC_PATH)
BLD_LIB_PATH = $(BLD_PREFIX)$(LIB_PATH)
BLD_BIN_PATH = $(BLD_PREFIX)$(BIN_PATH)
BLD_ETC_PATH = $(BLD_PREFIX)$(ETC_PATH)
BLD_INIT_PATH = $(BLD_PREFIX)$(INIT_PATH)
BLD_SYSTEMD_INIT_PATH = $(BLD_PREFIX)$(SYSTEMD_INIT_PATH)

LIB = libheartbeat_api.so
EXEC = heartbeat_client
PUB_INC = heartbeat_api.h

LIB_VER = $(LIB).$(VER)
LIB_VER_MJR = $(LIB).$(VER_MJR)

BLD_ROOT = ../..
RELEASE_ROOT = ../release

MY_CFLAGS = -fPIC -g -O2 -Wall -Wextra -Werror -I../heartbeat

LIB_SRCS = heartbeat_api.c
LIB_OBJS = $(LIB_SRCS:.c=.o)
LIB_LDFLAGS = -fPIC -g  -shared
LIB_LDLIBS =  -lrt

EXEC_SRCS = heartbeat_client.c
EXEC_OBJS = $(EXEC_SRCS:.c=.o)
EXEC_LDFLAGS = -g -rdynamic
EXEC_LDLIBS =  -L. -L../heartbeat -L${STAGING_DIR}/usr/local/lib -lheartbeat_api -lheartbeat -lalarm_clock -lrt -ldl

.PHONY: all customer_build build debug deliver clean

all: $(LIB) $(LIB_VER) $(LIB_VER_MJR) $(EXEC)

customer_build: 
	$(MAKE) -C . build BLD_CFLAGS="-I ${BLD_ROOT}/${BLD_INC_PATH}" BLD_LDFLAGS="-L ${BLD_ROOT}/${BLD_LIB_PATH}"
	chmod 755 $(LIB_VER)  $(EXEC)
	cp $(PUB_INC)         ${BLD_ROOT}/$(BLD_INC_PATH)/cgcs
	cp $(LIB_VER)         ${BLD_ROOT}/$(BLD_LIB_PATH)
	ln -sf $(LIB_VER)     ${BLD_ROOT}/$(BLD_LIB_PATH)/$(LIB_VER_MJR)
	ln -sf $(LIB_VER_MJR) ${BLD_ROOT}/$(BLD_LIB_PATH)/$(LIB)
	cp $(EXEC)            ${BLD_ROOT}/$(BLD_BIN_PATH)

build: $(LIB) $(LIB_VER) $(LIB_VER_MJR) $(EXEC)
	mkdir -p --mode=755   ${RELEASE_ROOT}/$(BLD_LIB_PATH)
	mkdir -p --mode=755   ${RELEASE_ROOT}/$(BLD_BIN_PATH)
	cp $(LIB_VER)         ${RELEASE_ROOT}/$(BLD_LIB_PATH)/
	ln -sf $(LIB_VER)     ${RELEASE_ROOT}/$(BLD_LIB_PATH)/$(LIB_VER_MJR)
	ln -sf $(LIB_VER_MJR) ${RELEASE_ROOT}/$(BLD_LIB_PATH)/$(LIB)
	cp $(EXEC)            ${RELEASE_ROOT}/$(BLD_BIN_PATH)/
	chmod -R 644          ${RELEASE_ROOT}/$(BLD_LIB_PATH)/*
	chmod -R 755          ${RELEASE_ROOT}/$(BLD_BIN_PATH)/*

%.o : %.c
	$(CC) $(MY_CFLAGS) $(BLD_CFLAGS) -c -o $@ $<

$(LIB): $(LIB_VER_MJR)
	ln -sf $(LIB_VER_MJR) $(LIB)

$(LIB_VER_MJR): $(LIB_VER)
	ln -sf $(LIB_VER)     $(LIB_VER_MJR)

$(LIB_VER): $(LIB_OBJS)
	$(CC) $(LIB_LDFLAGS) $(BLD_LDFLAGS) -Wl,-soname,$(LIB_VER_MJR) -o $(LIB_VER) $(LIB_OBJS) $(LIB_LDLIBS)

$(EXEC): $(EXEC_OBJS) $(LIB)
	$(CC) $(EXEC_LDFLAGS) $(BLD_LDFLAGS) -o $(EXEC) $(EXEC_OBJS) $(EXEC_LDLIBS)

debug: $(LIB_OBJS)
	$(CC) $(LIB_LDFLAGS) $(BLD_LDFLAGS) -o $(LIB) $(LIB_OBJS) $(LIB_LDLIBS)

deliver:

clean:
	@rm -f $(LIB) $(EXEC) $(LIB_OBJS) $(EXEC_OBJS) *.o *.so

