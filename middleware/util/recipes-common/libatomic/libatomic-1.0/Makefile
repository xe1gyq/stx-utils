VER ?= 1.0
VER_MJR ?= $(shell echo $(VER) | awk -F '.' '{print $$1}')

LIB = libatomic.so
PUB_INC = atomic.h atomic_types.h

LIB_VER = $(LIB).$(VER)
LIB_VER_MJR = $(LIB).$(VER_MJR)

BLD_INC_PATH = $(BLD_PREFIX)/$(INC_PATH)
BLD_LIB_PATH = $(BLD_PREFIX)/$(LIB_PATH)
BLD_BIN_PATH = $(BLD_PREFIX)/$(BIN_PATH)


BLD_ROOT = ..

LIB_SRCS = atomic.c
LIB_OBJS = $(LIB_SRCS:.c=.o)
LIB_LDFLAGS = -fPIC -g -shared
LIB_LDLIBS =  

MY_CFLAGS = -fPIC -g -O0 -Wall -Wextra -Werror

all: $(LIB) $(LIB_VER) $(LIB_VER_MJR)

customer_build: $(LIB)
	$(MAKE) -C . build BLD_CFLAGS="-I ${BLD_ROOT}/${BLD_INC_PATH}"
	chmod 755 $(LIB_VER)
	cp $(PUB_INC)         ${BLD_ROOT}/${BLD_INC_PATH}/cgcs
	cp $(LIB_VER)         ${BLD_ROOT}/${BLD_LIB_PATH}
	ln -sf $(LIB_VER)     ${BLD_ROOT}/${BLD_LIB_PATH}/$(LIB_VER_MJR)
	ln -sf $(LIB_VER_MJR) ${BLD_ROOT}/${BLD_LIB_PATH}/$(LIB)

build: $(LIB) $(LIB_VER) $(LIB_VER_MJR)

%.o : %.c
	$(CC) $(MY_CFLAGS) $(BLD_CFLAGS) -c -o $@ $<

$(LIB_VER_MJR): $(LIB_VER)
	ln -sf $(LIB_VER) $(LIB_VER_MJR)

$(LIB): $(LIB_VER_MJR)
	ln -sf $(LIB_VER_MJR) $(LIB)

$(LIB_VER): $(LIB_OBJS)
	$(CC) $(LIB_LDFLAGS) $(BLD_LDFLAGS) -Wl,-soname,$(LIB_VER_MJR) -o $(LIB_VER) $(LIB_OBJS) $(LIB_LDLIBS)

debug: $(LIB_OBJS)
	$(CC) $(LIB_LDFLAGS) -Wl,-soname,$(LIB_VER_MJR) -o $(LIB_VER) $(LIB_OBJS) $(LIB_LDLIBS)

deliver:

install_non_bb:
	install -d ${DEST_DIR}${LIB_DIR}
	install $(LIB_VER) ${DEST_DIR}${LIB_DIR}
	ln -sf $(LIB_VER) $(LIB_VER).0
	cp -P $(LIB_VER).0 $(LIB_VER_MJR) $(LIB) $(DEST_DIR)${LIB_DIR}
	install -d ${DEST_DIR}${INC_DIR}/cgcs
	install -m 644 *.h ${DEST_DIR}${INC_DIR}/cgcs

clean:
	@rm -f $(LIB) $(LIB_VER) $(LIB_VER_MJR) $(LIB_OBJS) $(EXEC_OBJS) *.o *.so

