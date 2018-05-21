VER ?= 1.0.1
VER_MJR ?= $(shell echo $(VER) | awk -F '.' '{print $$1}')

BLD_INC_PATH = $(BLD_PREFIX)$(INC_PATH)
BLD_LIB_PATH = $(BLD_PREFIX)$(LIB_PATH)
BLD_BIN_PATH = $(BLD_PREFIX)$(BIN_PATH)
BLD_ETC_PATH = $(BLD_PREFIX)$(ETC_PATH)
BLD_INIT_PATH = $(BLD_PREFIX)$(INIT_PATH)
BLD_SYSTEMD_INIT_PATH = $(BLD_PREFIX)$(SYSTEMD_INIT_PATH)

HB_SETNS ?= $(shell grep -r setns /usr/include | grep extern | wc -l)

TMP_DIR := $$( cd ../..; pwd )
L2 := $$( cd ../..; ls )
TMP_BASE := $$( basename $(TMP_DIR) )
EXT := $(shell [ "$(TMP_BASE)" == "x86-wrsmllib32-linux" ] && echo "lib32-" )

BASE = ../../../$(EXT)
RET = ../../$(EXT)


.PHONY: customer_build build clean tar

customer_build:
	make -C heartbeat customer_build     VER=$(VER) VER_MJR=$(VER_MJR) BLD_PREFIX=$(BLD_PREFIX) BIN_PATH=$(BIN_PATH) INC_PATH=$(INC_PATH) LIB_PATH=$(LIB_PATH) ETC_PATH=$(ETC_PATH) VER=$(VER) VER_MJR=$(VER_MJR) HB_SETNS=$(HB_SETNS)
	make -C heartbeat_api customer_build VER=$(VER) VER_MJR=$(VER_MJR) BLD_PREFIX=$(BLD_PREFIX) BIN_PATH=$(BIN_PATH) INC_PATH=$(INC_PATH) LIB_PATH=$(LIB_PATH) ETC_PATH=$(ETC_PATH) VER=$(VER) VER_MJR=$(VER_MJR)
	make -C scripts customer_build       VER=$(VER) VER_MJR=$(VER_MJR) BLD_PREFIX=$(BLD_PREFIX) BIN_PATH=$(BIN_PATH) INC_PATH=$(INC_PATH) LIB_PATH=$(LIB_PATH) ETC_PATH=$(ETC_PATH) VER=$(VER) VER_MJR=$(VER_MJR INIT_PATH=$(INIT_PATH) SYSTEMD_INIT_PATH=$(SYSTEMD_INIT_PATH) BLD_TYPE=$(BLD_TYPE)

build:
	echo "HEARTBEAT_NAME=$(HEARTBEAT_NAME)"
	echo "HEARTBEAT_BUILD_DIR=$(HEARTBEAT_BUILD_DIR)"
	mkdir -p release
	@(cd heartbeat ; make clean ; make build               VER=$(VER) VER_MJR=$(VER_MJR) BLD_PREFIX=$(BLD_PREFIX) INC_PATH=$(INC_PATH) LIB_PATH=$(LIB_PATH) BIN_PATH=$(BIN_PATH) ETC_PATH=$(ETC_PATH) HB_SETNS=$(HB_SETNS))
	@(cd heartbeat_api ; make clean ; make build           VER=$(VER) VER_MJR=$(VER_MJR) BLD_PREFIX=$(BLD_PREFIX) INC_PATH=$(INC_PATH) LIB_PATH=$(LIB_PATH) BIN_PATH=$(BIN_PATH) ETC_PATH=$(ETC_PATH))
	@(cd heartbeat_namespace_cmd ; make clean ; make build VER=$(VER) VER_MJR=$(VER_MJR) BLD_PREFIX=$(BLD_PREFIX) INC_PATH=$(INC_PATH) LIB_PATH=$(LIB_PATH) BIN_PATH=$(BIN_PATH) ETC_PATH=$(ETC_PATH))
	@(cd heartbeat_shutdown_cmd ; make clean ; make build  VER=$(VER) VER_MJR=$(VER_MJR) BLD_PREFIX=$(BLD_PREFIX) INC_PATH=$(INC_PATH) LIB_PATH=$(LIB_PATH) BIN_PATH=$(BIN_PATH) ETC_PATH=$(ETC_PATH))
	@(cd scripts ; make clean ; make build                 VER=$(VER) VER_MJR=$(VER_MJR) BLD_PREFIX=$(BLD_PREFIX) INC_PATH=$(INC_PATH) LIB_PATH=$(LIB_PATH) BIN_PATH=$(BIN_PATH) ETC_PATH=$(ETC_PATH) INIT_PATH=$(INIT_PATH) SYSTEMD_INIT_PATH=$(SYSTEMD_INIT_PATH) BLD_TYPE=$(BLD_TYPE))
	@(cd release ; make -f ../Makefile tar                 VER=$(VER) VER_MJR=$(VER_MJR) BLD_PREFIX=$(BLD_PREFIX) INC_PATH=$(INC_PATH) LIB_PATH=$(LIB_PATH) BIN_PATH=$(BIN_PATH) ETC_PATH=$(ETC_PATH) HEARTBEAT_NAME=$(HEARTBEAT_NAME) HEARTBEAT_BUILD_DIR=$(HEARTBEAT_BUILD_DIR))

clean:
	@( cd heartbeat ; make clean     VER=$(VER) VER_MJR=$(VER_MJR) )
	@( cd heartbeat_api ; make clean VER=$(VER) VER_MJR=$(VER_MJR) )
	@( if test -d heartbeat_namespace_cmd; then cd heartbeat_namespace_cmd ; make clean VER=$(VER) VER_MJR=$(VER_MJR); fi )
	@( if test -d heartbeat_namespace_cmd; then cd heartbeat_shutdown_cmd ; make clean VER=$(VER) VER_MJR=$(VER_MJR); fi )
	@( cd scripts ; make clean VER=$(VER) VER_MJR=$(VER_MJR) )

tar:
	echo "HEARTBEAT_NAME=$(HEARTBEAT_NAME)"
	echo "HEARTBEAT_BUILD_DIR=$(HEARTBEAT_BUILD_DIR)"
	echo TMP_DIR=$(TMP_DIR)
	echo TMP_BASE=$(TMP_BASE)
	echo TEST=$(TEST)
	echo BASE=$(BASE)
	echo RET=$(RET)
	pwd
	mkdir -p $(BLD_ETC_PATH)
	mkdir -p etc/init.d
	mkdir -p $(BLD_LIB_PATH)
	mkdir -p $(BLD_BIN_PATH)
	chmod 755 $(BLD_ETC_PATH)
	chmod 755 etc/init.d
	chmod 755 $(BLD_LIB_PATH)
	chmod 755 $(BLD_BIN_PATH)
	cp ../scripts/sample_health_check_script       $(BLD_ETC_PATH)/
	cp ../scripts/sample_corrective_action_script  $(BLD_ETC_PATH)/
	cp ../scripts/sample_event_handling_script     $(BLD_ETC_PATH)/
	cp ../scripts/sample_request_health_checks     $(BLD_ETC_PATH)/
	chmod 755 $(BLD_ETC_PATH)/sample_health_check_script
	chmod 755 $(BLD_ETC_PATH)/sample_corrective_action_script
	chmod 755 $(BLD_ETC_PATH)/sample_event_handling_script
	chmod 755 $(BLD_ETC_PATH)/sample_request_health_checks
	cp ../scripts/heartbeat_init                   etc/init.d/
	chmod 755 etc/init.d/heartbeat_init
	cp --preserve=links $(STAGING_DIR)/${LIB_PATH}/libalarm_clock.so*  $(BLD_LIB_PATH)
	cp --preserve=links $(STAGING_DIR)/${LIB_PATH}/libatomic.so*       $(BLD_LIB_PATH)
	$(eval ALARM_CLOCK_DIR := $(shell ls -1 -v $(BASE)libalarm-clock/ | tail -n 1))
	$(eval ALARM_CLOCK_VER := $(shell echo $(ALARM_CLOCK_DIR) | /usr/bin/awk -F '-' '{ print $$1 }' ))
	$(eval ALARM_CLOCK_REL := $(shell echo $(ALARM_CLOCK_DIR) | /usr/bin/awk -F '-' '{ print $$2 }' ))
	$(eval ATOMIC_DIR := $(shell ls -1 -v $(BASE)libatomic/ | tail -n 1))
	$(eval ATOMIC_VER := $(shell echo $(ATOMIC_DIR) | /usr/bin/awk -F '-' '{ print $$1 }' ))
	$(eval ATOMIC_REL := $(shell echo $(ATOMIC_DIR) | /usr/bin/awk -F '-' '{ print $$2 }' ))
	tar czvf ../heartbeat.tgz etc/heartbeat etc/init.d/heartbeat_init $(BLD_LIB_PATH) $(BLD_BIN_PATH)
	mkdir -p $(HEARTBEAT_NAME)/heartbeat-$(VER)
	mkdir -p $(HEARTBEAT_NAME)/libalarm-clock-$(ALARM_CLOCK_VER)
	mkdir -p $(HEARTBEAT_NAME)/libatomic-$(ATOMIC_VER)
	pwd
	cd ..; tar czvf release/$(HEARTBEAT_NAME)/heartbeat-$(VER)/t.tgz --no-recursion `find . | grep -E '[.][/](heartbeat|heartbeat_api|scripts|Makefile|LICENSE|scripts[/][^/]*[^.][^s][^h])($$|[/]Makefile|[/].*[.][ch]$$)' | grep -v heartbeat_os.c`
	pwd
	cd $(BASE)libalarm-clock/$(ALARM_CLOCK_DIR)/; tar czvf $(RET)$(HEARTBEAT_BUILD_DIR)/release/$(HEARTBEAT_NAME)/libalarm-clock-$(ALARM_CLOCK_VER)/t.tgz --no-recursion `find . | grep -E '[.][/](Makefile|LICENSE$$|[^/]*[.][ch]$$)'`
	pwd
	cd $(BASE)libatomic/$(ATOMIC_DIR)/; tar czvf $(RET)$(HEARTBEAT_BUILD_DIR)/release/$(HEARTBEAT_NAME)/libatomic-$(ATOMIC_VER)/t.tgz --no-recursion `find . | grep -E '[.][/](Makefile|LICENSE$$|[^/]*[.][ch]$$)'`
	pwd
	cd $(HEARTBEAT_NAME)/heartbeat-$(VER)/;tar xzvf t.tgz; rm t.tgz
	pwd
	cd $(HEARTBEAT_NAME)/libalarm-clock-$(ALARM_CLOCK_VER)/;tar xzvf t.tgz; rm t.tgz
	pwd
	cd $(HEARTBEAT_NAME)/libatomic-$(ATOMIC_VER)/;tar xzvf t.tgz; rm t.tgz
	pwd
	cp ../Makefile.src $(HEARTBEAT_NAME)/Makefile
	cp ../README.src $(HEARTBEAT_NAME)/README
	cp ../README2.src $(HEARTBEAT_NAME)/README2
	cp ../ACPI-shutdown.README $(HEARTBEAT_NAME)/ACPI-shutdown.README
	cp ../Heartbeat.pdf $(HEARTBEAT_NAME)/Heartbeat.pdf
	tar czvf ../$(HEARTBEAT_NAME).tgz $(HEARTBEAT_NAME)
	
