VER ?= 1.0
VER_MJR ?= $(shell echo $(VER) | awk -F '.' '{print $$1}')

LIB = libalarm_clock.so
EXEC = alarm_test
PUB_INC = alarm_clock_types.h alarm_clock.h

LIB_VER = $(LIB).$(VER)
LIB_VER_MJR = $(LIB).$(VER_MJR)

BLD_INC_PATH = $(BLD_PREFIX)/$(INC_PATH)
BLD_LIB_PATH = $(BLD_PREFIX)/$(LIB_PATH)
BLD_BIN_PATH = $(BLD_PREFIX)/$(BIN_PATH)


BLD_ROOT = ..

MY_CFLAGS = -fPIC -g -O2 -Wall -Wextra -Werror  -I ${BLD_ROOT}/${BLD_INC_PATH}

LIB_SRCS = alarm_clock.c
LIB_OBJS = $(LIB_SRCS:.c=.o)
LIB_LDFLAGS = -fPIC -g  -shared
LIB_LDLIBS =  -latomic -lrt

EXEC_SRCS = alarm_test.c
EXEC_OBJS = $(EXEC_SRCS:.c=.o)
EXEC_LDFLAGS = -g -rdynamic
EXEC_LDLIBS =  -L. -lalarm_clock -latomic -lrt -ldl

.PHONY: all customer_build build debug deliver clean

all: $(LIB) $(LIB_VER) $(LIB_VER_MJR) $(EXEC)

customer_build: 
	$(MAKE) -C . build BLD_CFLAGS="-I ${BLD_ROOT}/${BLD_INC_PATH}" BLD_LDFLAGS="-L ${BLD_ROOT}/${BLD_LIB_PATH}"
	chmod 755 $(LIB_VER)
	cp $(PUB_INC)         ${BLD_ROOT}/${BLD_INC_PATH}/cgcs
	cp $(LIB_VER)         ${BLD_ROOT}/${BLD_LIB_PATH}
	ln -sf $(LIB_VER)     ${BLD_ROOT}/${BLD_LIB_PATH}/$(LIB_VER_MJR)
	ln -sf $(LIB_VER_MJR) ${BLD_ROOT}/${BLD_LIB_PATH}/$(LIB)

build: $(LIB) $(LIB_VER) $(LIB_VER_MJR) $(EXEC)

%.o : %.c
	$(CC) $(MY_CFLAGS) $(BLD_CFLAGS) -c -o $@ $<

$(LIB_VER_MJR): $(LIB_VER)
	ln -sf $(LIB_VER) $(LIB_VER_MJR)

$(LIB): $(LIB_VER_MJR)
	ln -sf $(LIB_VER_MJR) $(LIB)

$(LIB_VER): $(LIB_OBJS)
	$(CC) $(LIB_LDFLAGS) $(BLD_LDFLAGS) -Wl,-soname,$(LIB_VER_MJR) -o $(LIB_VER) $(LIB_OBJS) $(LIB_LDLIBS)

$(EXEC): $(EXEC_OBJS) $(LIB)
	$(CC) $(EXEC_LDFLAGS) $(BLD_LDFLAGS) -o $(EXEC) $(EXEC_OBJS) $(EXEC_LDLIBS)

debug: $(LIB_OBJS)
	$(CC) $(LIB_LDFLAGS) -Wl,-soname,$(LIB_VER_MJR) -o $(LIB_VER) $(LIB_OBJS) $(LIB_LDLIBS)

deliver:

install_non_bb:
	install -d ${DEST_DIR}${LIB_DIR}
	install $(LIB_VER) ${DEST_DIR}${LIB_DIR}
	cp -P $(LIB_VER_MJR) $(LIB) $(DEST_DIR)${LIB_DIR}
	install -d ${DEST_DIR}${INC_DIR}/cgcs
	install -m 644 *.h ${DEST_DIR}${INC_DIR}/cgcs

clean:
	@rm -f $(LIB) $(LIB_VER) $(LIB_VER_MJR) $(EXEC) $(LIB_OBJS) $(EXEC_OBJS) *.o *.so

