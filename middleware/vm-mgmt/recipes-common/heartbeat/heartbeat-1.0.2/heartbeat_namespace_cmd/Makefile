VER ?= 1.0.0
VER_MJR ?= $(shell echo $(VER) | awk -F '.' '{print $$1}')

BLD_INC_PATH = $(BLD_PREFIX)$(INC_PATH)
BLD_LIB_PATH = $(BLD_PREFIX)$(LIB_PATH)
BLD_BIN_PATH = $(BLD_PREFIX)$(BIN_PATH)
BLD_ETC_PATH = $(BLD_PREFIX)$(ETC_PATH)
BLD_INIT_PATH = $(BLD_PREFIX)$(INIT_PATH)
BLD_SYSTEMD_INIT_PATH = $(BLD_PREFIX)$(SYSTEMD_INIT_PATH)

EXEC = heartbeat_namespace_cmd

BLD_ROOT = ../..
RELEASE_ROOT = ../release

MY_CFLAGS = -fPIC -g -O2 -Wall -Wextra -Werror -I../heartbeat -I../heartbeat_api

EXEC_SRCS = heartbeat_namespace_cmd.c
EXEC_OBJS = $(EXEC_SRCS:.c=.o)
EXEC_LDFLAGS = -g -rdynamic
EXEC_LDLIBS =  -L../heartbeat -L../heartbeat_api -lheartbeat_api -lheartbeat -lalarm_clock -ltrap_handler -latomic -lrt -ldl

.PHONY: all customer_build build debug deliver clean

all: $(EXEC)

customer_build: 
	$(MAKE) -C . build BLD_CFLAGS="-I ${BLD_ROOT}/${BLD_INC_PATH}" BLD_LDFLAGS="-L ${BLD_ROOT}/${BLD_LIB_PATH}"
	chmod 755 $(EXEC)
	cp $(EXEC)    ${BLD_ROOT}/${BLD_BIN_PATH}

build: $(EXEC)
	mkdir -p --mode=755 ${RELEASE_ROOT}/$(BLD_BIN_PATH)
	chmod 755 $(EXEC)
	cp $(EXEC)          ${RELEASE_ROOT}/$(BLD_BIN_PATH)/

%.o : %.c
	$(CC) $(MY_CFLAGS) $(BLD_CFLAGS) -c -o $@ $<

$(EXEC): $(EXEC_OBJS) 
	$(CC) $(EXEC_LDFLAGS) $(BLD_LDFLAGS) -o $(EXEC) $(EXEC_OBJS) $(EXEC_LDLIBS)

debug: $(EXEC_OBJS)
	$(CC) $(EXEC_LDFLAGS) $(BLD_LDFLAGS) -o $(EXEC) $(EXEC_OBJS) $(EXEC_LDLIBS)

deliver:

clean:
	@rm -f $(EXEC) $(EXEC_OBJS) *.o *.so

