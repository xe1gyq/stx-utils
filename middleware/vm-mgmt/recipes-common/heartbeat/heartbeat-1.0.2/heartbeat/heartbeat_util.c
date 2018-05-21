/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

/**
*/
#include "heartbeat_macro.h"
#include "heartbeat_message.h"
#include "heartbeat_types.h"
#include "heartbeat_common.h"


#include <ctype.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <resolv.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> 
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>


hb_server_client_t* find_server_client_from_hostname(ns_data_t* ns, const char* host_name)
    {
    int i;
    hb_server_client_t *scp;

    for(i=0; i<HB_MAX_CLIENTS; i++)
        {
        scp = ns->server.connections[i];
        if (scp)
            {
            PRINT_INFO("%s vs %s\n", scp->name, host_name);
            if (0==strncmp(scp->name, host_name, sizeof(scp->name)))
                return scp;
            }
        }

    return NULL;
    }



