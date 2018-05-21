VER ?= 1.0.0
VER_MJR ?= $(shell echo $(VER) | awk -F '.' '{print $$1}')

BLD_INC_PATH = $(BLD_PREFIX)$(INC_PATH)
BLD_LIB_PATH = $(BLD_PREFIX)$(LIB_PATH)
BLD_BIN_PATH = $(BLD_PREFIX)$(BIN_PATH)
BLD_ETC_PATH = $(BLD_PREFIX)$(ETC_PATH)
BLD_INIT_PATH = $(BLD_PREFIX)$(INIT_PATH)
BLD_SYSTEMD_INIT_PATH = $(BLD_PREFIX)$(SYSTEMD_INIT_PATH)

BLD_ROOT = ../..
RELEASE_ROOT = ../release

.PHONY: customer_build build clean

customer_build: heartbeat_init.sh heartbeat_systemd_init.sh sample_request_health_checks.sh ssh_instance.sh
	cp heartbeat_init.sh $(BLD_ROOT)/$(BLD_INIT_PATH)/heartbeat_init 
	cp heartbeat_systemd_init.sh $(BLD_ROOT)/$(BLD_ETC_PATH)/heartbeat_systemd_init
	cp heartbeat.service $(BLD_ROOT)/$(BLD_SYSTEMD_INIT_PATH) 
	cp heartbeat.conf cloud_functions $(BLD_ROOT)/$(BLD_ETC_PATH) 
	cp sample_corrective_action_script  sample_health_check_script  sample_event_handling_script $(BLD_ROOT)/$(BLD_ETC_PATH)
	cp sample_request_health_checks.sh  $(BLD_ROOT)/$(BLD_ETC_PATH)/sample_request_health_checks
	cp ssh_instance.sh $(BLD_ROOT)/$(BLD_BIN_PATH)/ssh_instance
	chmod 755 $(BLD_ROOT)/$(BLD_INIT_PATH)/heartbeat_init
	chmod 755 $(BLD_ROOT)/$(BLD_ETC_PATH)/heartbeat_systemd_init
	chmod 644 $(BLD_ROOT)/$(BLD_SYSTEMD_INIT_PATH)/heartbeat.service
	chmod 644 $(BLD_ROOT)/$(BLD_ETC_PATH)/cloud_functions
	chmod 644 $(BLD_ROOT)/$(BLD_ETC_PATH)/heartbeat.conf
	chmod 755 $(BLD_ROOT)/$(BLD_BIN_PATH)/ssh_instance
	chmod 755 $(BLD_ROOT)/$(BLD_ETC_PATH)/sample_corrective_action_script 
	chmod 755 $(BLD_ROOT)/$(BLD_ETC_PATH)/sample_health_check_script
	chmod 755 $(BLD_ROOT)/$(BLD_ETC_PATH)/sample_request_health_checks
	chmod 755 $(BLD_ROOT)/$(BLD_ETC_PATH)/sample_event_handling_script

build: heartbeat_init.sh heartbeat_systemd_init.sh sample_request_health_checks.sh ssh_instance.sh

.SUFFIXES:

heartbeat_init.sh: heartbeat_init
	sed "s|\$$SUB_BIN_PATH|$(BIN_PATH)|g" heartbeat_init | sed "s|\$$SUB_LIB_PATH|$(LIB_PATH)|g" > heartbeat_init.sh

heartbeat_systemd_init.sh: heartbeat_systemd_init
	sed "s|\$$SUB_BIN_PATH|$(BIN_PATH)|g" heartbeat_systemd_init | sed "s|\$$SUB_LIB_PATH|$(LIB_PATH)|g" > heartbeat_systemd_init.sh

sample_request_health_checks.sh: sample_request_health_checks
	sed "s|\$$SUB_BIN_PATH|$(BIN_PATH)|g"  sample_request_health_checks | sed "s|\$$SUB_LIB_PATH|$(LIB_PATH)|g" > sample_request_health_checks.sh

ssh_instance.sh: ssh_instance
	sed "s|\$$SUB_BIN_PATH|$(BIN_PATH)|g"  ssh_instance | sed "s|\$$SUB_LIB_PATH|$(LIB_PATH)|g" > ssh_instance.sh

clean:
	rm -f heartbeat_init.sh heartbeat_systemd_init.sh sample_request_health_checks.sh ssh_instance.sh
