/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

/**
*/
#include <cgcs/trap_handler.h>
#include "heartbeat_macro.h"
#include "heartbeat_api.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/select.h>

void usage()
    {
    printf("heartbeat_namespace_cmd [--port <port>] [--addr <ip_addr> | --host <hostname>] [--ns_host <hostname>] [--ns_create | --ns_destroy]  <ns_name>\n");
    printf("\n");
    exit(-1);
    }

int unhealthy = 0;
int request_pause = 0;
int pause_timeout = 60;
char* health_script = NULL;
char* event_handling_script = NULL;

void sighup_handler(int sig)
    {
    sig=sig;
    hb_exit("heartbeat_shutdown_if exiting due to SIGHUP");
    exit(-1);
    }

void sigusr1_handler(int sig)
    {
    sig=sig;
    }

void sigusr2_handler(int sig)
    {
    sig=sig;
    }

int main(int argc, char *argv[])
    {
    int i;
    int s_port = -1;
    int sa_idx = 0;
    int host_idx = 0;
    int ns_host_idx = 0;
    int ns_idx = 0;
    int ns_create_flag = 0;
    int ns_destroy_flag = 0;
    int rc;
    struct sigaction sa;

    init_trap_handler();

    hb_role = hbr_control_interface;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigusr1_handler;
    sigaction(SIGUSR1, &sa, NULL);
    sa.sa_handler = sigusr2_handler;
    sigaction(SIGUSR2, &sa, NULL);
    sa.sa_handler = sighup_handler;
    sigaction(SIGHUP, &sa, NULL);

    PRINT_DEBUG("PID = %d\n", getpid());

    for(i=1; i<argc; i++)
        {
        if (0==strcmp(argv[i], "--port"))
            {
            i++;
            if (i<argc)
               s_port = atoi(argv[i]);
            else
               usage();
            }
        else if (0==strcmp(argv[i], "--addr"))
            {
            i++;
            if (i<argc)
                sa_idx = i;
            else
               usage();
            }
        else if (0==strcmp(argv[i], "--host"))
            {
            i++;
            if (i<argc)
                host_idx = i;
            else
               usage();
            }
        else if (0==strcmp(argv[i], "--ns_host"))
            {
            i++;
            if (i<argc)
                ns_host_idx = i;
            else
               usage();
            }
        else if (0==strcmp(argv[i], "--ns_create"))
            {
            ns_create_flag = 1; 
            i++;
            if (i<argc)
                ns_idx = i;
            else
               usage();
            }
        else if (0==strcmp(argv[i], "--ns_destroy"))
            {
            ns_destroy_flag = 1; 
            i++;
            if (i<argc)
                ns_idx = i;
            else
                usage();
            }
        else if (0==strcmp(argv[i], "--help"))
           usage();
        else
           usage();
        }

    if (sa_idx)
        {
        rc = hb_set_server_addr(argv[sa_idx]);
        if (rc)
            PRINT_ERR("hb_set_server_addr failed with rc %d\n", rc);
        }

    if (host_idx)
        {
        rc = hb_set_server_hostname(argv[host_idx]);
        if (rc)
            PRINT_ERR("hb_set_server_hostname failed with rc %d\n", rc);
        }

    if (s_port != -1)
        {
        rc = hb_set_server_port(s_port);
        if (rc)
            PRINT_ERR("hb_set_server_port failed with rc %d\n", rc);
        }

    if ((ns_idx == 0) || !(ns_create_flag || ns_destroy_flag))
        {
        usage();
        }

    rc = hb_init_client("heartbeat_shutdown_if",
                        "heartbeat_shutdown_if_id",
                        "heartbeat_shutdown_if_n",
                        HB_DEFAULT_FIRST_MS, 
                        HB_DEFAULT_INTERVAL_MS,
                        HB_DEFAULT_VOTE_MS,
                        HB_DEFAULT_SHUTDOWN_MS,
                        HB_DEFAULT_SUSPEND_MS,
                        HB_DEFAULT_RESUME_MS,
                        HB_DEFAULT_DOWNSCALE_MS,
                        HB_DEFAULT_RESTART_MS);
    PRINT_DEBUG("hb_init_client rc = %d\n", rc);

    PRINT_DEBUG("socket = %d\n", hb_get_socket());

    if (ns_create_flag)
        hb_ns_create_notify(argv[ns_idx], ns_host_idx ? argv[ns_host_idx] : NULL);

    if (ns_destroy_flag)
        hb_ns_destroy_notify(argv[ns_idx], ns_host_idx ? argv[ns_host_idx] : NULL);

    exit(0);
    }
