/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

/**
*/
#include <cgcs/trap_handler.h>

#include <cgcs/nova_util.h>

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
    int i;

    printf("heartbeat_shutdown_cmd [--port <port>] [--addr <ip_addr> | --host <hostname>] \n");
    printf("                       [--instance_id <id> | --instance_name <name> | --name <name> ] \n");
    printf("                       [--timeout <millisec>] --type <event_type> --msg <msg>\n");
    printf("                       [--debug <lvl>]\n");
    printf("\n");
    printf("    where <event_type> is one of: ");
    for(i=0; i<hbet_max; i++)
        printf("%s%s", (i ? ", " : ""), hb_get_event_name(i));
    printf("\n");
    printf("\n");
    printf("    where <msg> is one of: ");
    for(i=0; i<hbnt_max; i++)
        printf("%s%s", (i ? ", " : ""), hb_get_notification_name(i));
    printf("\n");
    printf("\n");
    printf("   e.g. --instance_id aca42644-cebe-476a-85ee-a0d0cbfbc2ae \n");
    printf("   e.g. --instance_name instance-00000009 \n");
    printf("   e.g. --name my_instance \n");
    printf("\n");
    exit(-1);
    }

int unhealthy = 0;
int request_pause = 0;
int heartbeat_timeout_ms = 60 * 1000;
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

void hb_handle_shutdown_response(ns_data_t           *ns,
                                 heartbeat_message_t *message,
                                 hb_server_client_t  *p)
    {
    heartbeat_event_vote_t vote;
    heartbeat_event_t event_type;
    heartbeat_notification_t notification_type;
    
    ns=ns;
    p=p;

    event_type = ntohs(message->body.shutdown_response_body.event_type);
    notification_type = ntohs(message->body.shutdown_response_body.notification_type);
    vote = ntohs(message->body.shutdown_response_body.event_vote);

    PRINT_INFO("Response to %s %s request was %d (%s)\n", 
               hb_get_notification_name(notification_type), hb_get_event_name(event_type), vote, hb_get_vote_name(vote));

    if (notification_type == hbnt_revocable)
        {
        if (vote == hbev_reject)
            {
            PRINT_INFO("VM voted to reject %s: %s\n", hb_get_event_name(event_type), message->body.shutdown_response_body.err_msg);
            printf("%s\n", message->body.shutdown_response_body.err_msg);
            }
        }

    switch(vote)
        {
        case hbev_accept:
        case hbev_complete:
            hb_exit("heartbeat_shutdown_if: normal exit");
            exit(HB_SHUTDOWN_RC_ACCEPT);
            break;
        case hbev_reject:
            hb_exit("heartbeat_shutdown_if: normal exit");
            exit(HB_SHUTDOWN_RC_REJECT);
            break;
        case hbev_timeout_error:
            PRINT_ERR("VM timed out on '%s'\n", hb_get_event_name(event_type));
            hb_exit("heartbeat_shutdown_if: timeout");
            exit(HB_SHUTDOWN_RC_TIMEOUT);
            break;
        case hbev_proxy_error:
        case hbev_not_found_error:
        case hbev_busy_error:
        case hbev_script_error:
        case hbev_waiting:
            hb_exit("heartbeat_shutdown_if: error");
            exit(HB_SHUTDOWN_RC_ERROR);
            break;
        default:
            hb_exit("heartbeat_shutdown_if: unknown vote response");
            exit(HB_SHUTDOWN_RC_ERROR);
            break;
        }

    hb_exit("heartbeat_shutdown_if: unexpected exit");
    exit(HB_SHUTDOWN_RC_ERROR);
    }


int main(int argc, char *argv[])
    {
    int i;
    int s_port = -1;
    int sa_idx = 0;
    int name_idx = 0;
    int instance_name_idx = 0;
    int instance_id_idx = 0;
    int host_idx = 0;
    int type_idx = 0;
    int msg_idx = 0;
    int timeout_ms = HB_DEFAULT_VM_TIMEOUT_MS;

    int vote_ms      = HB_DEFAULT_VOTE_MS;
    int shutdown_ms  = HB_DEFAULT_SHUTDOWN_MS;
    int suspend_ms   = HB_DEFAULT_SUSPEND_MS;
    int resume_ms    = HB_DEFAULT_RESUME_MS;
    int downscale_ms = HB_DEFAULT_DOWNSCALE_MS;
    int restart_ms   = HB_DEFAULT_RESTART_MS;

    int rc;
    int sock;
    struct sigaction sa;
    heartbeat_notification_t notification_type = hbnt_unknown;
    heartbeat_event_t event_type = hbet_unknown;
    char *instance_id = NULL;
    char *instance_name = NULL;
    char *name = NULL;

    init_trap_handler();

    hb_role = hbr_control_interface;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigusr1_handler;
    sigaction(SIGUSR1, &sa, NULL);
    sa.sa_handler = sigusr2_handler;
    sigaction(SIGUSR2, &sa, NULL);
    sa.sa_handler = sighup_handler;
    sigaction(SIGHUP, &sa, NULL);

    hb_debug_info = 1;
    hb_debug_message = 1;
    hb_debug_debug = 1;


    for(i=1;i<argc;i++)
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
        else if (0==strcmp(argv[i], "--timeout"))
            {
            i++;
            if (i<argc)
               timeout_ms = atoi(argv[i]);
            else
               usage();
            }
        else if (0==strcmp(argv[i], "--instance_id"))
            {
            i++;
            if (i<argc)
                instance_id_idx = i;
            else
               usage();
            }
        else if (0==strcmp(argv[i], "--name"))
            {
            i++;
            if (i<argc)
                name_idx = i;
            else
               usage();
            }
        else if ((0==strcmp(argv[i], "--instance_name")) ||
                 (0==strcmp(argv[i], "--instance")))
            {
            i++;
            if (i<argc)
                instance_name_idx = i;
            else
               usage();
            }
        else if (0==strcmp(argv[i], "--msg"))
            {
            i++;
            if (i<argc)
                msg_idx = i;
            else
               usage();
            }
        else if (0==strcmp(argv[i], "--type"))
            {
            i++;
            if (i<argc)
                type_idx = i;
            else
               usage();
            }
        else if (0==strcmp(argv[i], "--help"))
           {
           usage();
           }
        else if (0==strcmp(argv[i], "--debug"))
            {
            i++;
            if (i<argc)
               {
               switch(atoi(argv[i]))
                  {
                  case 0:
                     hb_debug_info = 1;
                     hb_debug_message = 0;
                     hb_debug_debug = 0;
                     break;
                  case 1:
                     hb_debug_info = 1;
                     hb_debug_message = 1;
                     hb_debug_debug = 0;
                     break;
                  case 2:
                     hb_debug_info = 1;
                     hb_debug_message = 1;
                     hb_debug_debug = 1;
                     break;
                  default:
                     usage();
                     break;
                  }
               }     
            else     
               usage();
            }        
        else
            {
            printf("Unknown arguement %s\n", argv[i]);
            usage();
            }
        }

    if (sa_idx)
        {
        rc = hb_set_server_addr(argv[sa_idx]);
        if (rc)
            {
            PRINT_ERR("hb_set_server_addr failed with rc %d\n", rc);
            printf("hb_set_server_addr failed with rc %d\n", rc);
            }
        }

    if (host_idx)
        {
        rc = hb_set_server_hostname(argv[host_idx]);
        if (rc)
            {
            PRINT_ERR("hb_set_server_hostname failed with rc %d\n", rc);
            printf("hb_set_server_hostname failed with rc %d\n", rc);
            }
        }

    if (s_port != -1)
        {
        rc = hb_set_server_port(s_port);
        if (rc)
            {
            PRINT_ERR("hb_set_server_port failed with rc %d\n", rc);
            printf("hb_set_server_port failed with rc %d\n", rc);
            }
        }

    if (msg_idx)
        {
        notification_type = notification_str_to_idx(argv[msg_idx]);
        }

    if (type_idx)
        {
        event_type = shutdown_str_to_idx(argv[type_idx]);
        }

    if (event_type == hbet_unknown)
        {
        if (type_idx)
            printf("unknown event_type '%s'\n", argv[type_idx]);
        else
            printf("unspecified event_type\n");
        usage();
        }

    if (notification_type == hbnt_unknown)
        {
        if (msg_idx)
            printf("unknown msg type '%s'\n", argv[msg_idx]);
        else
            printf("unspecified msg type\n");
        usage();
        }

    if (instance_id_idx)
        {
        instance_id = argv[instance_id_idx];
        }

    if (instance_name_idx)
        {
        instance_name = argv[instance_name_idx];
        }

    if (name_idx)
        {
        name = argv[name_idx];
        }

    if (!instance_id && !name_idx && !instance_name_idx)
        {
        PRINT_ERR("Failed to provide one of instance_id, instance_name, name\n");
        printf("Failed to provide one of instance_id, instance_name, name\n");
        usage();
        }

    bind_handle_shutdown_response_fptr(hb_handle_shutdown_response);

    if (notification_type == hbnt_revocable)
        {
        if (timeout_ms)
            vote_ms = timeout_ms;
        }
    else
        {
        switch(event_type)
            {
            case hbet_stop:
            case hbet_reboot:
                if (timeout_ms)
                    shutdown_ms = timeout_ms;
                break;
            case hbet_suspend:
            case hbet_pause:
            case hbet_live_migrate_begin:
            case hbet_cold_migrate_begin:
                if (timeout_ms)
                    suspend_ms = timeout_ms;
                break;
            case hbet_unpause:
            case hbet_resume:
            case hbet_live_migrate_end:
                if (timeout_ms)
                    resume_ms = timeout_ms;
                break;
            case hbet_cold_migrate_end:
                if (timeout_ms)
                    restart_ms = timeout_ms;
                break;
            case hbet_downscale:
                if (timeout_ms)
                    downscale_ms = timeout_ms;
                break;
            case hbet_unknown:
            default:
                timeout_ms = HB_DEFAULT_REBOOT_MS;
                usage();
                break;
            }
        }

    rc = hb_init_client("heartbeat_shutdown_if",
                        "heartbeat_shutdown_if_id",
                        "heartbeat_shutdown_if_n",
                        heartbeat_timeout_ms, 
                        heartbeat_timeout_ms, 
                        vote_ms,
                        shutdown_ms,
                        suspend_ms,
                        resume_ms,
                        downscale_ms,
                        restart_ms);
    PRINT_DEBUG("hb_init_client rc = %d\n", rc);

    sock = hb_get_socket();
    PRINT_DEBUG("socket = %d\n", sock);

    rc = hb_shutdown_request(event_type, notification_type, instance_id, instance_name, name, timeout_ms);
    if (rc == HB_RC_OK)
        {
        hb_exit("heartbeat_shutdown_if: success");
        return HB_SHUTDOWN_RC_ACCEPT;
        }
    else if (rc == HB_RC_TIMEOUT_ERR)
        {
        hb_exit("heartbeat_shutdown_if: timeout");
        return HB_SHUTDOWN_RC_TIMEOUT;
        }

    hb_exit("heartbeat_shutdown_if: hb_shutdown_request failed");
    exit(HB_SHUTDOWN_RC_ERROR);
    }
