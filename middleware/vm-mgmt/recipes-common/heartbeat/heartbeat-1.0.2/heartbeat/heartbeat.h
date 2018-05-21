/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

#ifndef __HEARTBEAT_H__
#define __HEARTBEAT_H__

/**
*/

#include "heartbeat_types.h"

/* TODO
#include <time.h>

#define BUFFER_SIZE 1024
#define SECRET_SIZE 16
#define NAME_SIZE 64
#define HEARTBEAT_PORT 5000

typedef struct client_data_s client_data_t;
struct client_data_s
   {
   client_data_t *next;
   int socket;
   int pid;
   int seq;
   struct timespec heartbeat_interval;
   struct timespec first_heartbeat_delay;
   struct timespec last_heartbeat;
   struct timespec next_heartbeat;
   char secret[SECRET_SIZE];
   char name[SECRET_SIZE];
   };
*/

extern void init_ns(ns_data_t *ns, hb_client_t *client);

extern void init_server(hb_server_t *server, ns_data_t *ns);

extern void server_shutdown(hb_server_t *server);

extern void server_loop(ns_data_t *ns);


#endif /* __HEARTBEAT_H__ */
