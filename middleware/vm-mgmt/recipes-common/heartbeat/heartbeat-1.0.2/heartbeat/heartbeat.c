/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

/**
*/
#include "heartbeat_macro.h"
#include <cgcs/alarm_clock.h>
#include "heartbeat_message.h"
#include "heartbeat_types.h"
#include "heartbeat_common.h"
#include "heartbeat_virtio.h"
#include "heartbeat_poll.h"
#include "heartbeat_util.h"
#include "heartbeat_role.h"
#include "network_namespace.h"


#include <cgcs/atomic.h>

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



int syslog_fd = -1;

pid_t child_pid = 0;

int   exit_loop = 0;

/* Seconds for init handshake */
#define INIT_TIMEOUT 5


#define POLLERRORS (POLLRDHUP | POLLERR | POLLHUP | POLLNVAL)


int server_flag=0;
int client_flag=0;

int s_port = HB_DEFAULT_SERVER_PORT;
int c_port = HB_DEFAULT_CLIENT_PORT;

ns_data_t   server_ns;
hb_client_t client;

void init_pipe_message(heartbeat_message_t *response,
                       heartbeat_message_type_t  mtype);
void init_server_client_response(heartbeat_message_t      *response, 
                                 hb_server_client_t       *p, 
                                 heartbeat_message_type_t  mtype);
void init_server_client_message(heartbeat_message_t      *response, 
                                hb_server_client_t       *p,
                                heartbeat_message_type_t  mtype);
void end_server_client_session(ns_data_t          *ns, 
                               hb_server_client_t *p,
                               int                 need_dequeue);
void warn_end_server_client_session(ns_data_t          *ns,
                                    hb_server_client_t *p,
                                    int                 need_dequeue);

int take_corrective_action(hb_server_client_t *scp,
                           char               *err_msg,
                           int                 disconnet_in);

void handle_shutdown_request(ns_data_t           *ns,
                             heartbeat_message_t *message,
                             hb_server_client_t  *scp,
                             hb_client_t         *client,
                             int                  reply_sock);

void handle_shutdown_response(ns_data_t           *ns,
                              heartbeat_message_t *message,
                              hb_server_client_t  *scp);

void server_shutdown(hb_server_t *server);

int expired_waiting_init(alarm_t* p);

int expired_waiting_challenge(alarm_t* p);

int expired_waiting_response(alarm_t* p);

int expired_paused(alarm_t* p);

int expired_waiting_resume(alarm_t* p);

int expired_waiting_shutdown_response(alarm_t* p);

void handle_vote(heartbeat_delayed_message_t *delayed,
                 hb_server_client_t          *voting_scp,
                 heartbeat_event_vote_t       vote,
                 char                        *err_msg);

int decrement_outstanding_votes(heartbeat_delayed_message_t *delayed, 
                                hb_server_client_t          *voting_scp,
                                hb_server_client_t          *expired_scp,
                                int                          timeout,
                                int                          need_queue);

int delayed_action_cleanup(ns_data_t                   *ns,
                           hb_server_client_t          *scp,
                           heartbeat_delayed_message_t *delayed,
                           heartbeat_event_t            event_type,
                           heartbeat_notification_t     msg_type,
                           hb_server_client_t          *expired_scp,
                           int                          timeout,
                           int                          need_queue);




void usage()
    {
    int i;

    printf("heartbeat [--control | --compute | --vm] [ARGS]\n");
    printf("   Where ARGS may be any of: \n");
    printf("      --server_port <portnum>   Override our default server side port %d\n", HB_DEFAULT_SERVER_PORT);
    printf("      --client_port <portnum>   Override default port our client will connect to %d\n", HB_DEFAULT_CLIENT_PORT);
    printf("      --client_host <hostname>  Hostname our client will connect to in absence of virtio device %s\n", HEARTBEAT_VIRTIO_FILE);
    printf("      --client_addr <hostip>    ip address our client will connect to in absence of virtio device %s \n", HEARTBEAT_VIRTIO_FILE);
    printf("      --first <millisec>        \n");
    printf("      --interval <millisec>     \n");
    printf("      --name <name>             eg. my_instance  \n");
    printf("      --instance_id <id>        eg. 581d1606-48d3-4842-8951-52d11ddf5abd   \n");
    printf("      --instance_name <name>    eg. instance-0000006a \n");
    printf("      --corrective <action>     \n");
    printf("      --corrective_var <int>    \n");
    printf("      --corrective_script <quoted_script> \n");
    printf("      --event_handling_script <quoted_script> \n");
    printf("      --daemon \n");
    printf("      --pmon \n");
    printf("      --debug [0-2] \n");
    printf("\n");
    printf("    where <action> is one of: ");
    for(i=0; i<hbca_corrective_action_max; i++)
        printf("%s%s", (i ? ", " : ""), hb_get_corrective_action_name(i));
    printf("\n");
    exit(EXIT_FAILURE);
    }

typedef struct
    {
    char *cmd;
    int   rc;
    } hb_system_data_t;

void* hb_system_helper(void* arg)
    {
    hb_system_data_t *data = arg;
    void* rp = NULL;

    if (!data)
        {
        PRINT_ERR("No data\n");
        }
    else
        {
        if (!data->cmd)
            {
            PRINT_ERR("No cammand\n");
            }
        else
            {
            data->rc = system(data->cmd);
            if (data->rc < 0)
                {
                PRINT_ERR("Failed to execute cmd '%s', system: %s\n", data->cmd, strerror(errno));
                }
            else
                {
                PRINT_INFO("Executed cmd '%s'\n", data->cmd);
                }
            free(data->cmd);
            }
        free(data);
        }
    return rp;
    }

int hb_system(const char* cmd)
    {
    hb_system_data_t *data;
    pthread_attr_t attr;
    pthread_t thread;
    int rc = 0;

    if (!cmd)
        {
        PRINT_ERR("No command\n");
        rc = -1;
        }
    else
        {
        data = (hb_system_data_t*)malloc(sizeof(hb_system_data_t));
        PRINT_DEBUG("malloc %p\n", data);
        if (!data)
            {
            PRINT_ERR("Failed to execute cmd '%s', malloc: %s\n", cmd, strerror(errno));
            rc = -1;
            }
        else
            {
            data->cmd = strdup(cmd);
            if (!data->cmd)
                {
                PRINT_ERR("Failed to execute cmd '%s', malloc: %s\n", cmd, strerror(errno));
                free(data);
                rc = -1;
                }
            else
                { 
                pthread_attr_init(&attr);
                pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
                rc = pthread_create(&thread, &attr, hb_system_helper, data);
                if (rc < 0)
                    {
                    PRINT_ERR("Failed to execute system cmd '%s': pthread_create: %s\n", cmd, strerror(errno));
                    PRINT_DEBUG("free %p\n", data);
                    free(data->cmd);
                    free(data);
                    }

                pthread_attr_destroy(&attr);
                }
            }
        }
    return rc;
    }

ssize_t hb_sc_read(hb_server_client_t* scp, heartbeat_message_t *message, size_t size)
    {
    return hb_read(HB_GET_SCP_FD(scp), message, size);
    }


ssize_t hb_sc_write(hb_server_client_t* scp, heartbeat_message_t *message, size_t size)
    {
    scp->sequence++;
    message->header.sequence = htonl(scp->sequence);
    return hb_write(HB_GET_SCP_FD(scp), message, size);
    }

 
ns_traverse_func_return_t close_all_ns_helper(ns_data_t *ns, void *arg)
    {
    heartbeat_message_t message;

    arg = arg;
    init_pipe_message(&message, hbm_network_namespace);
    message.body.network_namespace_body.ns_event = hb_ns_destroy;
    strncpy(message.body.network_namespace_body.ns_name, ns->ns_name, 
            sizeof(message.body.network_namespace_body.ns_name));
    message.body.network_namespace_body.network_hostname[0] = '\0';

    hb_write(ns->pipe_fd[WRITE_PIPE], &message, sizeof(message));
    return ns_traverse_continue;
    }

void close_all_ns()
    {
    ns_traverse(close_all_ns_helper, NULL);
    }

void heartbeat_exit(int exit_code, const char* log)
    {
    static int heartbeat_exit_in_progress = 0;

    if (heartbeat_exit_in_progress)
        {
        PRINT_ERR("Nested call to heartbeat_exit: %d: %s\n", exit_code, log);
        closelog();
        exit(exit_code);
        }

    heartbeat_exit_in_progress=1;
    PRINT_INFO("heartbeat_exit: %d: %s\n", exit_code, log);
    close_all_ns();
    if (server_flag)
        server_shutdown(&(server_ns.server));
    if (client_flag)
        client_disconnect(&client, true, log);
    closelog();
    exit(exit_code);
    }


void server_shutdown(hb_server_t *server)
    {
    int i;

    for(i=0; i<HB_MAX_CLIENTS; i++)
        if (server->connections[i])
            warn_end_server_client_session(server->ns, server->connections[i], true);
    usleep(100000);
    for(i=0; i<HB_MAX_CLIENTS; i++)
        if (server->connections[i])
            end_server_client_session(server->ns, server->connections[i], false);
    if (server->sock >= 0)
        {
        #ifdef HB_USE_SELECT
            FD_CLR(server->sock, &(server->ns->read_socks));
        #endif /* HB_USE_SELECT */
        #ifdef HB_USE_POLL
            hb_pollfd_remove_fd(&(server->ns->pollfd_data), server->sock);
        #endif /* HB_USE_POLL */

        close(server->sock);
        server->sock = -1;
        }
    }

void init_server(hb_server_t *server, ns_data_t *ns)
    {
    int i;
    int reuse_addr = 1;  /* Used so we can re-bind to our port while a previous
                            connection is still in TIME_WAIT state. 
                          */
    int rc;

    memset(server, 0, sizeof(*server));
    server->ns = ns;
    server->port = s_port;

    for(i=0; i<HB_MAX_CLIENTS; i++)
        server->connections[i]=NULL;

    /* Obtain a file descriptor for our "listening" socket */
    server->sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (server->sock < 0)
        {
        PRINT_ERR("ns=%s, socket: %s\n", ns->ns_name, strerror(errno));
        heartbeat_exit(EXIT_FAILURE, __FUNCTION__);
        }

    /* So that we can re-bind to it without TIME_WAIT problems */
    setsockopt(server->sock, SOL_SOCKET, SO_REUSEADDR, &reuse_addr,
               sizeof(reuse_addr));

    /* Set socket to non-blocking */
    hb_setnonblocking(server->sock);

    memset((char *) &server->address, 0, sizeof(server->address));
    server->address.sin_family = AF_INET;
    server->address.sin_addr.s_addr = htonl(INADDR_ANY);
    server->address.sin_port = htons(server->port);

    PRINT_DEBUG("bind: sock = %d, port = %d\n", server->sock, server->port);
    rc = bind(server->sock, 
              (struct sockaddr *) &server->address,
              sizeof(server->address));
    if (rc < 0 ) 
        {
        PRINT_ERR("ns=%s, bind: %s\n", ns->ns_name, strerror(errno));
        PRINT_INFO("ns=%s, close server sock=%d\n", ns->ns_name, server->sock);
        close(server->sock);
        server->sock = -1;
        heartbeat_exit(EXIT_FAILURE, __FUNCTION__);
        }

    /* Set up queue for incoming connections. */
    PRINT_DEBUG("ns=%s, listen: sock = %d, port = %d\n", ns->ns_name, server->sock, server->port);
    rc = listen(server->sock, HB_LISTEN_QUEUE_BACKLOG);
    if (rc < 0 ) 
        {
        PRINT_ERR("ns=%s, listen: %s\n", ns->ns_name, strerror(errno));
        PRINT_INFO("ns=%s, close server sock=%d\n", ns->ns_name, server->sock);
        close(server->sock);
        server->sock = -1;
        heartbeat_exit(EXIT_FAILURE, __FUNCTION__);
        }

    #ifdef HB_USE_SELECT
        if (ns->highsock < server->sock)
            ns->highsock = server->sock;

        FD_SET(server->sock, &(ns->read_socks));
    #endif /* HB_USE_SELECT */
    #ifdef HB_USE_POLL
        hb_pollfd_add(&(ns->pollfd_data),
                      server->sock,
                      hbft_server,
                      -1,
                      server);
    #endif /* HB_USE_POLL */
    }


int delayed_action_cleanup(ns_data_t                   *ns,
                           hb_server_client_t          *scp,
                           heartbeat_delayed_message_t *delayed,
                           heartbeat_event_t            event_type,
                           heartbeat_notification_t     msg_type,
                           hb_server_client_t          *expired_scp,
                           int                          timeout,
                           int                          need_queue)
    {
    int restore_state = false;
    int corrective_action = false;
    int stop_timer = false;
    char corrective_action_msg[HB_LOG_MSG_SIZE];

    memset(corrective_action_msg, 0, sizeof(corrective_action_msg));

    if (scp || (delayed && delayed->outstanding < 10))
        PRINT_DEBUG("delayed = %p, ns = %p (%s), scp  = %p (%s), event_type = %d (%s), msg_type = %d (%s), timeout = %d\n",
                    delayed, ns, ns ? ns->ns_name : "", scp, scp ? scp->name : "", 
                    event_type, hb_get_event_name(event_type), msg_type, hb_get_notification_name(msg_type), timeout);
    if (!scp)
        if (delayed && delayed->scp && (delayed->scp->delayed_response == delayed))
           scp = delayed->scp;

    if (scp && (scp->delayed_response != delayed))
        {
        PRINT_ERR("scp delayed != delayed for %s\n", scp->name);
        }

    if (!scp)
        goto cleanup;


    switch(event_type)
        {
        case hbet_unknown:
            restore_state = true;
            break;

        case hbet_pause:
        case hbet_suspend:
            if (scp && delayed && delayed->for_my_client && (msg_type == hbnt_irrevocable))
                {
                if (scp->state != hbs_server_nova_paused)
                    {
                    scp->state = hbs_server_nova_paused;
                    stop_timer = true;
                    hb_set_expire_func_scp(scp, expired_waiting_resume);
                    hb_set_first_timeout_scp(scp, SERVER_SUSPEND_TIMEOUT_SECS, 0);
                    if (need_queue || (scp != expired_scp))
                        {
                        if (timeout)
                            hb_enqueue_first_ns_scp(ns, scp);
                        else
                            hb_requeue_first_ns_scp(ns, scp);
                        }
                    PRINT_DEBUG("nova commands pause/suspend of instance %s\n", scp->name);
                    }
                }
            else
                restore_state = true;

            break;

        case hbet_unpause:
        case hbet_resume:
            if (scp && delayed && delayed->for_my_client && (scp->state == hbs_server_nova_paused))
                {
                PRINT_DEBUG("nova commands unpause/resume of instance %s\n", scp->name);
                /* hb_enqueue_ns_scp(ns, scp); */
                }
            restore_state = true;
            break;

        case hbet_stop:
        case hbet_reboot:
            if (scp && delayed && delayed->for_my_client && (msg_type == hbnt_irrevocable))
                {
                if (timeout)
                    {
                    corrective_action = true;
                    strncpy(corrective_action_msg, "Timeout on notification of stop or reboot", sizeof(corrective_action_msg));
                    }
                stop_timer = true;
                }
            else
                restore_state = true;
            break;

        case hbet_downscale:
            if (scp && delayed && delayed->for_my_client && (msg_type == hbnt_irrevocable))
                stop_timer = true;
            else
                restore_state = true;
            break;

        case hbet_live_migrate_begin:
        case hbet_cold_migrate_begin:
            if (scp && delayed && delayed->for_my_client && (msg_type == hbnt_irrevocable))
                {
                if (scp->state != hbs_server_migrating)
                    {
                    scp->state = hbs_server_migrating;
                    stop_timer = true;
                    hb_set_expire_func_scp(scp, expired_waiting_resume);
                    hb_set_first_timeout_scp(scp, SERVER_SUSPEND_TIMEOUT_SECS, 0);
                    if (need_queue || (scp != expired_scp))
                        {
                        if (timeout)
                            hb_enqueue_first_ns_scp(ns, scp);
                        else
                            hb_requeue_first_ns_scp(ns, scp);
                        }
                    PRINT_DEBUG("nova commands migration of instance %s\n", scp->name);
                    }
                }
            else
                restore_state = true;

            break;

        case hbet_live_migrate_end:
        case hbet_cold_migrate_end:
            if (scp && delayed && delayed->for_my_client && (scp->state == hbs_server_migrating))
                {
                PRINT_DEBUG("nova commands migrate_end of instance %s\n", scp->name);
                /* hb_enqueue_ns_scp(ns, scp); */
                }
            restore_state = true;
            break;

        default:
            /* No action required. */
            break;
        }

    PRINT_INFO("restore_state = %d, state = %s, saved state = %s\n", restore_state, hb_get_state_name(scp->state), hb_get_state_name(scp->save_state));
    if (restore_state)
        {
        PRINT_DEBUG("saved state %d (%s)\n", scp->save_state, hb_get_state_name(scp->save_state));

        scp->state = scp->save_state;

        switch(scp->state)
            {
            case hbs_server_waiting_init:
            case hbs_server_nova_paused:
            case hbs_server_migrating:
                PRINT_ERR("Unexpected saved state after shutdown voting or notification %d (%s)\n",
                          scp->state, hb_get_state_name(scp->state));
            case hbs_server_waiting_challenge:
            case hbs_server_waiting_response:
                scp->state = hbs_server_waiting_challenge;
                PRINT_DEBUG("hbs_server_waiting_challenge program alarm alarm %p\n", &(scp->alarm));
                hb_set_expire_func_scp(scp, expired_waiting_challenge);
                if ((event_type == hbet_unpause) ||
                    (event_type == hbet_resume) ||
                    (event_type == hbet_live_migrate_end) ||
                    (event_type == hbet_cold_migrate_end))
                    {
                    hb_set_first_timeout_scp(scp,
                                             scp->first_delay.tv_sec,
                                             scp->first_delay.tv_nsec);
                    }
                else
                    {
                    hb_set_first_timeout_scp(scp,
                                             scp->interval.tv_sec,
                                             scp->interval.tv_nsec);
                    }
                if (need_queue || (scp != expired_scp))
                    hb_requeue_first_ns_scp(ns, scp); 
                break;
            case hbs_server_paused:
                PRINT_DEBUG("hbs_server_paused program alarm alarm %p\n", &(scp->alarm));
                hb_set_expire_func_scp(scp, expired_waiting_resume);
                hb_set_first_timeout_scp(scp,
                                         scp->pause_delay.tv_sec,
                                         scp->pause_delay.tv_nsec);
                if (need_queue || (scp != expired_scp))
                    hb_requeue_first_ns_scp(ns, scp); 
                break;
            default:
                PRINT_ERR("Unexpected saved state after shutdown voting or notification %d (%s)\n",
                          scp->state, hb_get_state_name(scp->state));
                scp->state = hbs_server_waiting_challenge;
                hb_set_first_timeout_scp(scp,
                                         scp->first_delay.tv_sec,
                                         scp->first_delay.tv_nsec);
                if (need_queue || (scp != expired_scp))
                    hb_requeue_first_ns_scp(ns, scp);
                break;
            }

        PRINT_DEBUG("restored state %d (%s)\n", scp->state, hb_get_state_name(scp->state));
        }

    /* clean up */
  cleanup:
    if (scp || (delayed && delayed->outstanding < 10))
        PRINT_DEBUG("cleanup delayed %p, outstanding %d\n", delayed, delayed ? (int)delayed->outstanding : 0);
    if (delayed && (delayed->outstanding==0))
        {
        int count = 0;

        if (delayed->ns && (delayed->ns->delayed_response == delayed))
            {
            count++;
            delayed->ns->delayed_response = NULL;
            PRINT_DEBUG("set delayed NULL for ns=%p (%s)\n", delayed->ns, delayed->ns->ns_name); 
            }

        if (scp && scp->delayed_response == delayed)
            {
            count++;
            scp->delayed_response = NULL;
            PRINT_DEBUG("set delayed NULL for server_client=%p (%s)\n", scp, scp->name); 
            }

        if (ns->client && ns->client->delayed_response == delayed)
            {
            count++;
            ns->client->delayed_response = NULL;
            PRINT_DEBUG("set delayed NULL for client=%p (%s)\n", ns->client, ns->client->name); 
            if (delayed->need_client_state_cleanup)
                hb_set_expire_func_client(ns->client, expired_waiting_client_activity);
            }

        PRINT_DEBUG("free delayed %p\n", delayed);
        free(delayed);
        }

    if (!scp)
        return ALARM_CLOCK_CONTINUE;

    PRINT_INFO("corrective_action = %d: %s\n", corrective_action, corrective_action_msg);
    if (corrective_action)
        {
        take_corrective_action(scp, corrective_action_msg, false);
        end_server_client_session(ns, scp, false);

        return ALARM_CLOCK_DELETED;
        }

    PRINT_INFO("stop_timer = %d\n", stop_timer);
    if (stop_timer)
        return ALARM_CLOCK_DELETED; 
    else
        return ALARM_CLOCK_CONTINUE;
    }


int expired_waiting_shutdown_script(alarm_t* p)
    {
    ns_data_t   *ns = NULL;
    hb_client_t *client = NULL;
    heartbeat_delayed_message_t *delayed = NULL;

    PRINT_INFO("alarm_t %p\n", p);
    ns = alarm_get_util_ptr(p);
    if (!ns)
        {
        PRINT_ERR("ns is null");
        return ALARM_CLOCK_CONTINUE;
        }

    client = ns->client;
    if (!client)
        {
        PRINT_ERR("client is null");
        return ALARM_CLOCK_CONTINUE;
        }

    PRINT_INFO("ns = %p(%s), client = %p (%s)\n", ns, ns->ns_name, client, client->name);
    delayed = client->delayed_response;

    if (delayed)
        {
        PRINT_INFO("killing delayed action script pid=%d\n", delayed->pid);
        if (delayed->pid)
            kill(delayed->pid, SIGTERM);
        else
            pthread_cancel(delayed->thread); 
        }

    hb_set_expire_func_client(client, expired_waiting_client_activity);
    return ALARM_CLOCK_CONTINUE;
    }


int expired_waiting_init(alarm_t* p)
    {
    int i;
    int sock;
    hb_server_client_t *scp;
    ns_data_t          *ns;

    i = alarm_get_id(p);
    ns = alarm_get_util_ptr(p);
    scp = ns->server.connections[i];
    PRINT_INFO("alarm = %p, i = %d, ns = %p (%s), scp = %p (%s)\n", p, i, ns, ns->ns_name, scp, scp->name);
    sock = HB_GET_SCP_FD(scp);
    end_server_client_session(ns, scp, false);
    PRINT_ERR("Connection times out without init message: FD=%d; Slot=%d\n",
              sock, i);
    return ALARM_CLOCK_DELETED;
    }

int expired_waiting_resume(alarm_t* p)
    {
    int i;
    ns_data_t  *ns;
    hb_server_client_t *scp;

    i = alarm_get_id(p);
    ns = alarm_get_util_ptr(p);
    scp = ns->server.connections[i];
    PRINT_INFO("p = %p, i=%d, ns = %p (%s), scp = %p (%s)\n", p, alarm_get_id(p), ns, ns->ns_name, scp, scp->name);
    return expired_waiting_challenge(p);
    }


int expired_waiting_challenge(alarm_t* p)
    {
    int i;
    hb_server_client_t *scp;
    ns_data_t          *ns;
    heartbeat_message_t message;

    i = alarm_get_id(p);
    ns = alarm_get_util_ptr(p);
    scp = ns->server.connections[i];
    PRINT_DEBUG("p = %p, i = %d, ns = %p (%s), scp = %p (%s)\n", p, i, ns, ns->ns_name, scp, scp->name);

    if (!scp)
        {
        // Alarm vs a disconnected client
        PRINT_ERR("Alarm vs a disconnected client\n");
        return ALARM_CLOCK_DELETED;
        }

    scp->state = hbs_server_waiting_response;
    hb_set_expire_func_scp(scp, expired_waiting_response);

    scp->heartbeat_challenge = rand();
    init_server_client_message(&message, scp, hbm_challenge);
    message.body.challenge_body.heartbeat_challenge = htonl(scp->heartbeat_challenge);

    PRINT_MESSAGE("send hbm_challenge %d to '%s'\n", scp->heartbeat_challenge, scp->name);
    hb_sc_write(scp, &message, sizeof(message));

    return ALARM_CLOCK_CONTINUE;
    }


int expired_paused(alarm_t* p)
    {
    int i;
    hb_server_client_t *scp;
    ns_data_t          *ns;
    heartbeat_message_t message;

    i = alarm_get_id(p);
    ns = alarm_get_util_ptr(p);
    scp = ns->server.connections[i];
    PRINT_DEBUG("p = %p, i = %d, ns = %p (%s), scp = %p (%s)\n", p, i, ns, ns->ns_name, scp, scp->name);

    scp->state = hbs_server_waiting_response;
    hb_set_expire_func_scp(scp, expired_waiting_response);

    scp->heartbeat_challenge = rand();
    init_server_client_message(&message, scp, hbm_challenge);
    message.body.challenge_body.heartbeat_challenge = htonl(scp->heartbeat_challenge);

    PRINT_MESSAGE("send hbm_challenge %d to '%s'\n", scp->heartbeat_challenge, scp->name);
    hb_sc_write(scp, &message, sizeof(message));

    return ALARM_CLOCK_CONTINUE;
    }


int expired_waiting_response(alarm_t* p)
    {
    int i;
    int sock;
    hb_server_client_t *scp;
    ns_data_t          *ns;

    i = alarm_get_id(p);
    ns = alarm_get_util_ptr(p);
    scp = ns->server.connections[i];
    PRINT_INFO("p = %p, i = %d, ns = %p (%s), scp = %p (%s)\n", p, i, ns, ns->ns_name, scp, scp->name);
    sock = HB_GET_SCP_FD(scp);

    PRINT_ERR("Timedout waiting for response: FD=%d; Slot=%d\n", sock, i);

    take_corrective_action(scp, "Heartbeat timed out", false);
    end_server_client_session(ns, scp, false);

    return ALARM_CLOCK_DELETED;
    }


hb_server_client_t* handle_new_connection_common(ns_data_t *ns, int fd)
    {
    int i;    
    hb_server_client_t* scp;

    /* find a spot for the new connection in ns->server.connections. */
    for (i = 0; i < HB_MAX_CLIENTS; i++)
        {
        if (ns->server.connections[i] == NULL)
            {
            PRINT_INFO("Connection accepted:   ns=%s; FD=%d; Slot=%d\n",
                       ns->ns_name, fd, i);
            scp = (hb_server_client_t*)malloc(sizeof(hb_server_client_t));
            if (scp)
                {
                memset(scp, 0, sizeof(*scp));
                scp->sock = -1;
                ns->server.connections[i] = scp;
                scp->delayed_response = NULL;
                PRINT_DEBUG("set delayed NULL for server_client=%p (%s)\n", scp, scp->name); 
                scp->client_role = hbr_unknown;
                scp->state = hbs_server_waiting_init;
                scp->ns = ns;
                scp->health_state = hbh_healthy;
                ac_init_alarm(&(scp->alarm),
                                INIT_TIMEOUT, INIT_TIMEOUT, ALARM_CLOCK_FOREVER, expired_waiting_init, i, ns);
                PRINT_DEBUG("init alarm %p (%s)\n", &(scp->alarm), scp->name);

                /* TODO other init? */
                hb_enqueue_ns_scp(ns, scp);
                PRINT_DEBUG("enqueue alarm %p (%s) on clock %p (%s)\n", &(scp->alarm), scp->name, &(ns->alarm_clock), ns->ns_name);
                return scp;
                }
            else
                {
                PRINT_ERR("handle_new_connection: malloc failure\n");
                i = HB_MAX_CLIENTS;
                }
            }
        }

    return NULL;
    }

void handle_new_vio_connection(ns_data_t *ns, int fd) 
    {
    vio_record_t *vio = NULL;
    hb_server_client_t* scp = NULL;

    PRINT_DEBUG("handle_new_vio_connection\n");

    scp = handle_new_connection_common(ns, fd);
    if (scp)
        vio = vio_ptr_find_by_fd(fd);

    if (scp && vio)
        {
        scp->vio = vio;
        vio->scp = scp;

        #ifdef HB_USE_SELECT
            if (ns->highsock < fd)
                ns->highsock = fd;

            FD_SET(fd, &(ns->read_socks));
            FD_CLR(fd, &(vio_data.waiting_socks));
        #endif /* HB_USE_SELECT */
        #ifdef HB_USE_POLL
            hb_pollfd_modify_fd(&(ns->pollfd_data), fd, vio ? hbft_server_client_vio : hbft_server_client, -1, scp);
        #endif /* HB_USE_POLL */
        }
    else
        {
        /* No room left in the queue! */
        PRINT_ERR("handle_new_vio_connection: No room left for new client.\n");

        heartbeat_message_t response;
        init_pipe_message(&response, hbm_init_fail);
        PRINT_MESSAGE("send hbm_init_fail\n");
        hb_write(fd, &response, sizeof(response));

        end_server_client_session(ns, scp, 1);
        }
    }

void handle_new_connection(ns_data_t *ns) 
    {
    int new_sock; 
    struct sockaddr_in remote_addr;
    unsigned int len;
    hb_server_client_t* scp = NULL;

    PRINT_DEBUG("handle_new_connection\n");
    len = sizeof(remote_addr);
    new_sock = accept(ns->server.sock, (struct sockaddr *)&remote_addr, &len);
    if (new_sock < 0)
        {
        PRINT_ERR("accept: %s\n", strerror(errno));
        heartbeat_exit(EXIT_FAILURE, __FUNCTION__);
        }

    hb_setnonblocking(new_sock);

    scp = handle_new_connection_common(ns, new_sock);
    if (scp)
        {
        scp->remote_addr = remote_addr;
        scp->sock = new_sock;

        #ifdef HB_USE_SELECT
            if (ns->highsock < new_sock)
                ns->highsock = new_sock;

            FD_SET(new_sock, &(ns->read_socks));
        #endif /* HB_USE_SELECT */
        #ifdef HB_USE_POLL
            hb_pollfd_add(&(ns->pollfd_data),
                          new_sock,
                          hbft_server_client,
                          -1,
                          scp);
        #endif /* HB_USE_POLL */
        }
    else
        {
        /* No room left in the queue! */
        PRINT_ERR("handle_new_connection: No room left for new client.\n");
        PRINT_INFO("close server_client sock=%d\n", new_sock);

        heartbeat_message_t response;
        init_pipe_message(&response, hbm_init_fail);
        PRINT_MESSAGE("send hbm_init_fail\n");
        hb_write(new_sock, &response, sizeof(response));

        close(new_sock);
        }
    }


int validate_response(hb_server_client_t *scp, 
                      heartbeat_message_t *m,
                      heartbeat_message_type_t mtype)
    {
    uint32_t expected_response = 0;
    uint32_t response = 0;
    uint32_t expected_sequence = 0;
    uint32_t sequence = 0;
    heartbeat_id_t heartbeat_id;
    const char* who;

    who = hb_get_message_type_name(mtype);
    heartbeat_id = ntohl(m->header.heartbeat_id);

    expected_sequence = scp->sequence+1;
    sequence = ntohl(m->header.sequence);

    switch (mtype)
        {
        case hbm_exit:
            response = ntohl(m->body.exit_body.heartbeat_response);
            expected_response = compute_response(scp->heartbeat_algorithm,
                                                 scp->heartbeat_secret,
                                                 scp->heartbeat_challenge_stored);
            break;
        case hbm_timeouts:
            response = ntohl(m->body.exit_body.heartbeat_response);
            expected_response = compute_response(scp->heartbeat_algorithm,
                                                 scp->heartbeat_secret,
                                                 scp->heartbeat_challenge_stored);
            break;
        case hbm_challenge:
            break;
        case hbm_response:
            response = ntohl(m->body.response_body.heartbeat_response);
            expected_response = compute_response(scp->heartbeat_algorithm,
                                                 scp->heartbeat_secret,
                                                 scp->heartbeat_challenge);
            break;
        case hbm_pause:
            response = ntohl(m->body.pause_body.heartbeat_response);
            expected_response = compute_response(scp->heartbeat_algorithm,
                                                 scp->heartbeat_secret,
                                                 scp->heartbeat_challenge_stored);
            break;
        case hbm_pause_ack:
            break;
        case hbm_resume:
            response = ntohl(m->body.resume_body.heartbeat_response);
            expected_response = compute_response(scp->heartbeat_algorithm,
                                                 scp->heartbeat_secret,
                                                 scp->heartbeat_challenge_stored);
            break;
        case hbm_resume_ack:
            break;
        case hbm_child_error:
            response = ntohl(m->body.child_error_body.heartbeat_response);
            expected_response = compute_response(scp->heartbeat_algorithm,
                                                 scp->heartbeat_secret,
                                                 scp->heartbeat_challenge_stored);
            break;
        case hbm_shutdown_response:
            break;
        case hbm_shutdown_request:
            break;
        case hbm_network_namespace:
            break;
        case hbm_nova_cmd:
            break;
        case hbm_init:
        case hbm_init_ack:
        case hbm_init_fail:
        case hbm_server_exit:
        case hbm_ping:
            scp->sequence = sequence;
            PRINT_DEBUG("sequence = %d for '%s'\n", sequence, scp->name);

            return 0;
        default:
            PRINT_ERR("Unhandled message type %d\n", mtype);
            return 0;
        }

    PRINT_DEBUG("response %d, expected_response %d\n", response, expected_response);
    PRINT_DEBUG("heartbeat_id = %d vs client heartbeat_id = %d\n", heartbeat_id, scp->heartbeat_id);
    if (heartbeat_id != scp->heartbeat_id)  
        {
        PRINT_ERR("TODO %s had invalid heartbeat_id: %d\n", who, heartbeat_id);
        return -1;
        }

    if (expected_sequence != sequence)
        {
        if ((expected_sequence != (sequence+1)) && (expected_sequence != (sequence-1)))
            {
            PRINT_ERR("TODO %s invalid sequence: %d vs expected %d\n", who, sequence, expected_sequence);
            return -2;
            }
        else
            {
            PRINT_INFO("%s: async message, allowing unexpected sequence: %d vs expected %d\n", who, sequence, expected_sequence);
            }
        }

    if (expected_response != response)
        {
        PRINT_ERR("TODO %s invalid response: %d vs expected %d\n", who, response, expected_response);
        return -3;
        }

    scp->sequence = sequence;
    PRINT_DEBUG("sequence = %d for '%s'\n", sequence, scp->name);

    return 0;
    }


void warn_end_server_client_session(ns_data_t          *ns,
                                    hb_server_client_t *scp,
                                    int                 need_dequeue)
    {
    heartbeat_message_t message;

    ns = ns;
    if (scp->state != hbs_server_nova_paused && scp->state != hbs_server_migrating)
        {
        if (need_dequeue)
            if (ac_alarm_on_queue(&(scp->alarm)))
                hb_dequeue_scp(scp);

        init_server_client_message(&message, scp, hbm_server_exit);
        PRINT_MESSAGE("send hbm_server_exit '%s'\n", scp->name);
        hb_sc_write(scp, &message, sizeof(message));
        }
    }

void end_server_client_session(ns_data_t          *ns, 
                               hb_server_client_t *scp,
                               int                 need_dequeue)
    {
    int idx;
    int sock;
    vio_record_t *vio = NULL;

    idx = alarm_get_id(&(scp->alarm));
    sock = scp->sock;
    vio = scp->vio;
        
    PRINT_DEBUG("scp '%s', ns '%s'\n", scp ? scp->name : "null", ns ? ns->ns_name : "null");

    if (need_dequeue)
        if (ac_alarm_on_queue(&(scp->alarm)))
            hb_dequeue_scp(scp);

    if (scp->delayed_response)
        {
        decrement_outstanding_votes(scp->delayed_response, scp, NULL, false, false);
        }

    scp->vio = NULL;
    free(scp);

    PRINT_INFO("close server_client sock=%d, vio=%p\n", sock, vio);

    if (ns->server.connections[idx] != scp)
        {
        int i=0;
        for(i=0; i<HB_MAX_CLIENTS; i++)
            if (ns->server.connections[i] == scp)
                {
                idx = i;
                break;
                }

        PRINT_ERR("alarm provided invalid idx %d, correct is %d\n", idx, i);
        if (i < HB_MAX_CLIENTS)
            idx = i;
        else
            idx = -1;
        }

    if (idx >= 0)
        ns->server.connections[idx] = NULL;

    if (sock >= 0)
        {
        #ifdef HB_USE_SELECT
            FD_CLR(sock, &(ns->read_socks));
        #endif /* HB_USE_SELECT */
        #ifdef HB_USE_POLL
            hb_pollfd_remove_fd(&(ns->pollfd_data), sock);
        #endif /* HB_USE_POLL */

        close(sock);
        }

    if (vio)
        {
        vio_disconnect(vio, ns);
        }
    }


void init_pipe_message(heartbeat_message_t *response,
                       heartbeat_message_type_t  mtype)
    {
    heartbeat_message_header_t *h   = &(response->header);

    strncpy(h->magic, HB_MAGIC, sizeof(h->magic));
    h->version = htons(HB_CURRENT_VERSION);
    h->mtype = htons(mtype);
    h->sequence = htonl(0);
    h->heartbeat_id = htonl(0);
    h->size = htonl((uint32_t)sizeof(*response));
    }

void init_server_client_message(heartbeat_message_t      *response, 
                                hb_server_client_t       *scp,
                                heartbeat_message_type_t  mtype)
    {
    heartbeat_message_header_t *h   = &(response->header);

    strncpy(h->magic, HB_MAGIC, sizeof(h->magic));
    h->version = htons(scp->version);
    h->mtype = htons(mtype);
    h->sequence = htonl(scp->sequence);
    h->heartbeat_id = htonl((uint32_t)scp->heartbeat_id);
    h->size = htonl((uint32_t)sizeof(*response));
    }


void init_server_client_response(heartbeat_message_t      *response, 
                                 hb_server_client_t       *scp,
                                 heartbeat_message_type_t  mtype)
    {
    heartbeat_message_header_t *h   = &(response->header);

    strncpy(h->magic, HB_MAGIC, sizeof(h->magic));
    h->version = htons(scp->version);
    h->mtype = htons(mtype);
    h->sequence = htonl(scp->sequence);
    h->heartbeat_id = htonl((uint32_t)scp->heartbeat_id);
    h->size = htonl((uint32_t)sizeof(*response));
    }



int take_corrective_action(hb_server_client_t *scp, char* err_msg, int disconnect_in)
    {
    int disconnect=1;
    char command[64+HB_INSTANCE_ID_SIZE+2*HB_NAME_SIZE+HB_LOG_MSG_SIZE+HB_SCRIPT_SIZE];

    if (disconnect_in)
        {
        switch (scp->state)
            {
            case hbs_server_nova_paused:
            case hbs_server_migrating:
                return 0;
    
            case hbs_server_waiting_init:
            case hbs_server_waiting_challenge:
            case hbs_server_waiting_response:
            case hbs_server_paused:
            case hbs_server_corrective_action:
            default:
                // fall through
                break;
            }
        }

    switch(scp->corrective_action)
        {
        case hbca_script:
            snprintf(command, sizeof(command), "INSTANCE_ID=\"%s\"; CORRECTIVE_ACTION_VAR=%d; INSTANCE_PID=%d; INSTANCE_NAME=\"%s\"; %s &",
                     scp->instance_id, scp->corrective_action_var, scp->pid, scp->name, scp->corrective_action_script);
            PRINT_INFO("corrective action being taken against '%s': %s\n", scp->name, command);
            hb_system(command);
            break;
        case hbca_process_restart:
            snprintf(command, sizeof(command), "/etc/init.d/%s restart &", scp->instance_id);
            PRINT_INFO("corrective action being taken against '%s': %s\n", scp->name, command);
            hb_system(command);
            break;
        case hbca_process_signal:
            snprintf(command, sizeof(command), "kill -%d %d",
                     scp->corrective_action_var ? scp->corrective_action_var : SIGTERM, scp->pid);
            PRINT_INFO("corrective action being taken against '%s': %s\n", scp->name, command);
            kill(scp->pid, scp->corrective_action_var ? scp->corrective_action_var : SIGTERM);
            break;
        case hbca_log:
        case hbca_process_set_instance_health:
        case hbca_instance_reboot:
        case hbca_instance_stop:
        case hbca_instance_delete:
            if (scp->health_state != hbh_unhealthy)
                {
                scp->health_state = hbh_unhealthy;
                strncpy(scp->health_err_msg, err_msg, sizeof(scp->health_err_msg));
                PRINT_ERR("Server health flag set to unhealthy for: name='%s', instance_id='%s' pid=%d, err_msg=%s, "
                          "corrective_action=%s\n",
                          scp->name, scp->instance_id, scp->pid, err_msg,
                          hb_get_corrective_action_name(scp->corrective_action));
                }
            disconnect=0;
            break;
        default:
            PRINT_ERR("Heartbeat has detected the following entity "
                      "requires manual corrective action: name='%s', instance_id='%s' pid=%d, msg='%s'\n",
                      scp->name, scp->instance_id, scp->pid, err_msg);
            break;
        }

    return disconnect;
    }



void handle_network_namespace_event(ns_data_t           *ns,
                                    heartbeat_message_t *message)
    {
    ns_data_t *old_ns;
    ns_data_t *new_ns;
    int        rc;
    const char *ns_name;
    const char *ns_host_name;
    hb_ns_event_t event;
    int host_specified = 0;
    int host_match = 0;
    hb_client_t    *cp;
    hb_server_client_t *dest_scp;
    int i;

    cp = ns->client;

    ns_name = message->body.network_namespace_body.ns_name;
    ns_host_name = message->body.network_namespace_body.network_hostname;
    event = ntohs(message->body.network_namespace_body.ns_event);

    host_specified = (ns_host_name[0] != '\0');
    if (host_specified)
        host_match = ((0 == strcmp(ns_host_name, hb_hostname))
                   || (cp && (0 == strcmp(ns_host_name, cp->name))));

    if (hb_role == hbr_control)
        {
        if (!host_specified)
            {
            PRINT_INFO("for unknown\n");
            for(i=0; i<HB_MAX_CLIENTS; i++)
                {
                dest_scp = server_ns.server.connections[i];
                if (dest_scp && dest_scp->client_role == hbr_compute)
                    {
                    PRINT_INFO("forward message to '%s', fd=%d\n", ns_host_name, HB_GET_SCP_FD(dest_scp));
                    hb_sc_write(dest_scp, message, sizeof(*message));
                    }
                }
            }

        if (host_specified && !host_match)
            {
            dest_scp = find_server_client_from_hostname(ns, ns_host_name);
            if (dest_scp)
                {
                PRINT_INFO("forward message to '%s', fd=%d\n", ns_host_name, HB_GET_SCP_FD(dest_scp));
                hb_sc_write(dest_scp, message, sizeof(*message));
                }
            else
                PRINT_ERR("Host '%s' not found\n", ns_host_name);
            }
        }

    if (!host_specified || host_match)
        {
        old_ns = ns_find_ns_name(ns_name);

        switch (event)
            {
            case hb_ns_create:
                if (old_ns)
                    {
                    PRINT_INFO("hb_ns_create failed, '%s' already known\n", ns_name);
                    return;
                    }

                if (!ns_check(ns_name))
                    {
                    PRINT_INFO("hb_ns_create failed, '%s' is not a valid namespace\n", ns_name);
                    return;
                    }

                new_ns = ns_add(ns_name);
                if (!new_ns)
                    {
                    PRINT_INFO("hb_ns_create: ns_add failed for '%s'\n", ns_name);
                    return;
                    }

                break;
            case hb_ns_destroy:
                if (!old_ns)
                    {
                    PRINT_INFO("hb_ns_destroy failed, '%s' not known\n", ns_name);
                    return;
                    }

                if (ns == old_ns)
                    {
                    /* Delete myself */
                    rc = ns_delete(ns_name);
                    if (rc < 0)
                        {
                        PRINT_INFO("hb_ns_destroy failed, '%s' not known\n", ns_name);
                        return;
                        }
                    }
                else
                    {
                    /* forward message to the namespace */
                    PRINT_INFO("forward hb_ns_destroy message into namespace '%s', fd=%d\n", ns_name, old_ns->pipe_fd[WRITE_PIPE]);
                    hb_write(old_ns->pipe_fd[WRITE_PIPE], message, sizeof(*message));
                    }
                break;
            }
        }
    }


void pipe_disconnect(ns_data_t *ns)
    {
    if (ns->pipe_fd[READ_PIPE] >= 0)
        {
        PRINT_INFO("close read pipe fd=%d\n", ns->pipe_fd[READ_PIPE]);

        #ifdef HB_USE_SELECT
            FD_CLR(ns->pipe_fd[READ_PIPE], &(ns->read_socks));
        #endif /* HB_USE_SELECT */
        #ifdef HB_USE_POLL
            hb_pollfd_remove_fd(&(ns->pollfd_data), ns->pipe_fd[READ_PIPE]);
        #endif /* HB_USE_POLL */

        close(ns->pipe_fd[READ_PIPE]);
        ns->pipe_fd[READ_PIPE] = -1;
        }
    if (ns->pipe_fd[WRITE_PIPE] >= 0)
        {
        PRINT_INFO("close rite pipe fd=%d\n", ns->pipe_fd[WRITE_PIPE]);
        close(ns->pipe_fd[WRITE_PIPE]);
        ns->pipe_fd[WRITE_PIPE] = -1;
        }
    }

int pipe_reconnect(ns_data_t *ns)
    {
    PRINT_INFO("pipe_reconnect \n");
    pipe_disconnect(ns);
    return pipe_connect(ns);
    }


void handle_pipe_disconnect(ns_data_t *ns)
    {
    /* TODO client side corrective action */
    PRINT_INFO("handle_pipe_disconnect\n");
    pipe_reconnect(ns);
    heartbeat_exit(EXIT_FAILURE, __FUNCTION__);
    }



void set_timeouts_from_init(heartbeat_message_t* init_msg)
    {
    heartbeat_message_t to_msg;

    if (hb_role != hbr_compute)
        return;

    if (ntohs(init_msg->body.init_body.role) != hbr_vm)
        return;

    memset(&to_msg, 0, sizeof(to_msg));
    init_pipe_message(&to_msg, hbm_timeouts);
    to_msg.body.timeouts_body.first_hb_secs = init_msg->body.init_body.first_hb_secs;
    to_msg.body.timeouts_body.first_hb_nsecs = init_msg->body.init_body.first_hb_nsecs;
    to_msg.body.timeouts_body.hb_interval_secs = init_msg->body.init_body.hb_interval_secs;
    to_msg.body.timeouts_body.hb_interval_nsecs = init_msg->body.init_body.hb_interval_nsecs;
    to_msg.body.timeouts_body.vote_secs = init_msg->body.init_body.vote_secs;
    to_msg.body.timeouts_body.vote_nsecs = init_msg->body.init_body.vote_nsecs;
    to_msg.body.timeouts_body.shutdown_notice_secs = init_msg->body.init_body.shutdown_notice_secs;
    to_msg.body.timeouts_body.shutdown_notice_nsecs = init_msg->body.init_body.shutdown_notice_nsecs;
    to_msg.body.timeouts_body.suspend_notice_secs = init_msg->body.init_body.suspend_notice_secs;
    to_msg.body.timeouts_body.suspend_notice_nsecs = init_msg->body.init_body.suspend_notice_nsecs;
    to_msg.body.timeouts_body.resume_notice_secs = init_msg->body.init_body.resume_notice_secs;
    to_msg.body.timeouts_body.resume_notice_nsecs = init_msg->body.init_body.resume_notice_nsecs;
    to_msg.body.timeouts_body.downscale_notice_secs = init_msg->body.init_body.downscale_notice_secs;
    to_msg.body.timeouts_body.downscale_notice_nsecs = init_msg->body.init_body.downscale_notice_nsecs;
    to_msg.body.timeouts_body.restart_secs = init_msg->body.init_body.restart_secs;
    to_msg.body.timeouts_body.restart_nsecs = init_msg->body.init_body.restart_nsecs;
    to_msg.body.timeouts_body.role = init_msg->body.init_body.role;
    strncpy(to_msg.body.timeouts_body.instance_id, init_msg->body.init_body.instance_id, sizeof(to_msg.body.timeouts_body.instance_id));
    strncpy(to_msg.body.timeouts_body.name, init_msg->body.init_body.name, sizeof(to_msg.body.timeouts_body.name));
    strncpy(to_msg.body.timeouts_body.instance_name, init_msg->body.init_body.instance_name, sizeof(to_msg.body.timeouts_body.instance_name));

    hb_write(server_ns.pipe_fd[WRITE_PIPE], &to_msg, sizeof(to_msg));
    }

int handle_pipe_connection(ns_data_t *ns)
    {
    heartbeat_message_t message;
    int rc;
    uint16_t version;
    uint16_t mtype;
    uint32_t sequence;
    uint32_t size;
    long secs;
    long nsecs;

    PRINT_DEBUG("handle_pipe_connection\n");
    rc = hb_read(ns->pipe_fd[READ_PIPE], &message, sizeof(message));
    if (rc <= 0)
        {
        /* Connection closed, close this end
           and free up entry in server.connections */
        PRINT_ERR("Pipe Connection lost: FD=%d, rc=%d: %s\n", ns->pipe_fd[READ_PIPE], rc, strerror(errno));

        handle_pipe_disconnect(ns);
        return HB_RC_IO_ERR;
        }

    if (rc < (int)sizeof(message))
        {
        /* Connection closed, close this end
           and free up entry in server.connections */
        PRINT_ERR("Short message on pipe: FD=%d\n", ns->pipe_fd[READ_PIPE]);

        /* TODO client side corrective action */
        return HB_RC_MESSAGING_ERR;
        }

    /* message processing*/
    if (strncmp(message.header.magic, HB_MAGIC, sizeof(message.header.magic)) != 0)
        {
        PRINT_ERR("Bad Magic: %c%c%c%c\n", message.header.magic[0], message.header.magic[1], message.header.magic[2], message.header.magic[3]);

        /* TODO corrective action? close socket? ignore for now */
        return HB_RC_MESSAGING_ERR;
        }

    version  = ntohs(message.header.version);
    mtype    = ntohs(message.header.mtype);
    sequence = ntohl(message.header.sequence);
    size     = ntohl(message.header.size);

    sequence = sequence;
    size = size;
    PRINT_MESSAGE("recv fd=%d, type=%s, ns=%s\n", ns->pipe_fd[READ_PIPE], hb_get_message_type_name(mtype), ns->ns_name);

    if (version > HB_CURRENT_VERSION)
        {
        PRINT_ERR("Bad version: %d\n", version);
        /* TODO corrective action? close socket? ignore for now */
        return 0;
        }

    switch(mtype)
        {
        case hbm_init:
            PRINT_ERR("hbm_init message recieved by pipe\n");
            break;
        case hbm_init_ack:
            PRINT_ERR("hbm_init_ack message recieved by pipe\n");
            break;
        case hbm_init_fail:
            PRINT_ERR("hbm_init_fail message recieved by pipe\n");
            break;
        case hbm_exit:
            PRINT_ERR("hbm_exit message recieved by pipe\n");
            break;
        case hbm_challenge:
            PRINT_ERR("hbm_challenge message recieved by pipe\n");
            break;
        case hbm_response:
            PRINT_ERR("hbm_response message recieved by pipe\n");
            break;
        case hbm_pause:
            PRINT_ERR("hbm_pause message recieved by pipe\n");
            break;
        case hbm_pause_ack:
            PRINT_ERR("hbm_pause_ack message recieved by pipe\n");
            break;
        case hbm_resume:
            PRINT_ERR("hbm_resume message recieved by pipe\n");
            break;
        case hbm_resume_ack:
            PRINT_ERR("hbm_resume_ack message recieved by pipe\n");
            break;
        case hbm_child_error:
            PRINT_ERR("TODO hbm_child_error message recieved by pipe\n");
            break;
        case hbm_shutdown_request:
            PRINT_INFO("hbm_shutdown_request");

            hb_server_client_t *dest_scp = NULL;
            int                 response_ready = 0;
            heartbeat_event_vote_t vote = hbev_waiting;
            heartbeat_message_t response;
            heartbeat_delayed_message_t *delayed;
            heartbeat_event_t event_type;

            PRINT_INFO("hbm_shutdown_request message recieved by pipe '%s'\n", ns->ns_name);

            init_response_header(&response, &message, server_ns.client, hbm_shutdown_response);
            response.body.shutdown_response_body.event_vote = htons((uint16_t)vote);
            response.body.shutdown_response_body.heartbeat_response  = htonl(0);
            response.body.shutdown_response_body.proxy_heartbeat_response = message.body.shutdown_request_body.proxy_heartbeat_response;
            response.body.shutdown_response_body.event_type = message.body.shutdown_request_body.event_type;
            response.body.shutdown_response_body.notification_type = message.body.shutdown_request_body.notification_type;
            memset(&(response.body.shutdown_response_body.err_msg[0]), 0, sizeof(response.body.shutdown_response_body.err_msg));

            event_type = ntohs(message.body.shutdown_request_body.event_type);

            switch(ntohs(message.body.shutdown_request_body.inst_id_type))
                {
                case hii_inst_id:
                    dest_scp = find_server_client_from_instance_id(ns, message.body.shutdown_request_body.instance_id);
                    break;
                case hii_inst_name:
                    dest_scp = find_server_client_from_instance_name(ns, message.body.shutdown_request_body.instance_id);
                    break;
                case hii_name:
                    dest_scp = find_server_client_from_name(ns, message.body.shutdown_request_body.instance_id);
                    break;
                default:
                    PRINT_ERR("Unknown inst_id_type %d", ntohs(message.body.shutdown_request_body.inst_id_type));
                    break;
                }

            if (dest_scp)
                {
                if (dest_scp->delayed_response != NULL)
                    {
                    PRINT_ERR("Busy, can't handle shutdown_request at this time\n");
                    vote = hbev_busy_error;
                    snprintf(response.body.shutdown_response_body.err_msg, 
                             sizeof(response.body.shutdown_response_body.err_msg),
                             "Heartbeat server is busy and can't handle a '%s' request at this time", 
                             hb_get_event_name(event_type));
                    response_ready = 1;
                    break;
                    }

                delayed = (heartbeat_delayed_message_t*)malloc(sizeof(heartbeat_delayed_message_t));
                PRINT_DEBUG("malloc delayed %p\n", delayed);
                memset(delayed, 0, sizeof(*delayed));
                delayed->sock = server_ns.pipe_fd[WRITE_PIPE];
                delayed->outstanding = 1;
                delayed->ns = ns;
                delayed->scp = dest_scp;
                delayed->reply_scp = NULL;
                delayed->for_me = 0;
                delayed->for_my_client = 1;
                delayed->need_client_state_cleanup = 0;
                delayed->vote = hbev_waiting;
                delayed->notification_type = ntohs(message.body.shutdown_request_body.notification_type);
                delayed->event_type = ntohs(message.body.shutdown_request_body.event_type);

                memcpy(&(delayed->response), &response, sizeof(delayed->response));
                dest_scp->delayed_response = delayed;
                PRINT_DEBUG("set delayed=%p for server_client=%p (%s)\n", delayed, dest_scp, dest_scp->name); 

                dest_scp->heartbeat_challenge = rand();
                message.header.heartbeat_id = htonl(dest_scp->heartbeat_id);
                message.body.shutdown_request_body.heartbeat_challenge = htonl(dest_scp->heartbeat_challenge);

                secs = ntohl(message.body.shutdown_request_body.timeout_secs);
                nsecs = ntohl(message.body.shutdown_request_body.timeout_nsecs);
                hb_fix_shutdown_to(dest_scp, NULL, 
                                   ntohs(message.body.shutdown_request_body.event_type), 
                                   ntohs(message.body.shutdown_request_body.notification_type), 
                                   &secs, &nsecs);
                hb_set_first_timeout_scp(dest_scp, secs, nsecs);
                PRINT_DEBUG("alarm_set_first_timeout %p, %ld.%09ld", &(dest_scp->alarm), secs, nsecs);

                if ((dest_scp->state != hbs_server_nova_paused) && (dest_scp->state != hbs_server_migrating))
                    {
                    dest_scp->save_state = dest_scp->state;
                    PRINT_DEBUG("saving state %d (%s)\n", dest_scp->state, hb_get_state_name(dest_scp->state));
                    }

                dest_scp->state = hbs_client_waiting_shutdown_response;
                hb_set_expire_func_scp(dest_scp, expired_waiting_shutdown_response);
                hb_requeue_first_ns_scp(ns, dest_scp);
                hb_sc_write(dest_scp, &message, sizeof(message));
                }
            else
                {
                PRINT_ERR("unknown_recipient '%s'\n", message.body.shutdown_request_body.instance_id);
                vote = hbev_not_found_error;
                snprintf(response.body.shutdown_response_body.err_msg, 
                         sizeof(response.body.shutdown_response_body.err_msg),
                         "Heartbeat server couldn't locate recipient '%s'", 
                         message.body.shutdown_request_body.instance_id);
                response_ready = 1;
                }

            if (response_ready)
                {
                response.body.shutdown_response_body.event_vote = htons((uint16_t)vote);
                hb_write(server_ns.pipe_fd[WRITE_PIPE], &response, sizeof(response));
                }
            
            break;
        case hbm_shutdown_response:
            if (0 == strcmp(ns->ns_name, HB_NS_DEFAULT_NAME))
                {
                PRINT_INFO("hbm_shutdown_response message recieved by pipe '%s'\n", ns->ns_name);
                handle_shutdown_response(ns, &message, NULL);
                }
            else
                {
                PRINT_ERR("hbm_shutdown_response message recieved by pipe '%s'\n", ns->ns_name);
                }
            break;
        case hbm_network_namespace:
            if (0 == strcmp(ns->ns_name, HB_NS_DEFAULT_NAME))
                {
                PRINT_ERR("hbm_network_namespace message recieved by pipe '%s'\n", ns->ns_name);
                }
            else
                {
                PRINT_INFO("hbm_network_namespace message recieved by pipe '%s'\n", ns->ns_name);
                handle_network_namespace_event(ns, &message);
                }
            break;
        case hbm_nova_cmd:
            hb_handle_hbm_nova_cmd(ns, &message, hbft_ns_pipe);
            break;
        case hbm_server_exit:
            PRINT_ERR("hbm_server_exit message recieved by pipe\n");
            break;
        case hbm_ping:
            PRINT_INFO("hbm_server_exit message recieved by pipe\n");
            break;
        case hbm_timeouts:
            hb_handle_hbm_timeouts(ns, &message);
            break;
        default:
            PRINT_ERR("Bad message: %d\n", mtype);
            break;
        }

    return 0;
    }


/*****************************************************************************************
 *
 * Name    : handle_server_connection
 *
 * Purpose : Manage the server connection recovery and by handling all the messages
 *           that come in from the guest VM.
 *
 * Description:
 *
 *
 *
 */
void handle_server_connection(ns_data_t *ns, hb_server_client_t *scp)
    {
    heartbeat_message_t message;
    heartbeat_message_t response;
    int rc;
    int idx;
    uint16_t version;
    uint16_t mtype;
    uint32_t sequence;
    uint32_t size;
    char remote_addr_str[32];
    int save_errno;
    int mismatch = 0;
    int allow_init = 0;

    PRINT_DEBUG("handle_server_connection: state=%s\n", scp ? hb_get_state_name(scp->state) : "???");
    idx = alarm_get_id(&(scp->alarm));

    rc = hb_sc_read(scp, &message, sizeof(message));
    if (rc <= 0) 
        {
        save_errno = errno;
        if (hb_is_closed(HB_GET_SCP_FD(scp)))
            {
            /* Connection closed, close this end
               and free up entry in server_ns.server.connections */
            PRINT_INFO("Connection lost: FD=%d;  Slot=%d, rc=%d: %s\n", HB_GET_SCP_FD(scp), idx, rc, strerror(save_errno));

            take_corrective_action(scp, "Connection lost", true);
            end_server_client_session(ns, scp, true);
            }
        else
            {
            PRINT_INFO("zero byte read on FD=%d Slot=%d, rc=%d: %s\n", HB_GET_SCP_FD(scp), idx, rc, strerror(save_errno));
            }
        return;
        }
    if (rc < (int)sizeof(message)) 
        {
        PRINT_ERR("Short message: %d vs %d, FD=%d;  Slot=%d\n", rc, (int)sizeof(message), HB_GET_SCP_FD(scp), idx);

        take_corrective_action(scp, "Short message", true);
        end_server_client_session(ns, scp, true);
        return;
        }

    /* message processing*/
    if (strncmp(message.header.magic, HB_MAGIC, sizeof(message.header.magic)) != 0)
        {
        PRINT_ERR("Bad Magic: %c%c%c%c\n", message.header.magic[0], message.header.magic[1], message.header.magic[2], message.header.magic[3]); 
        /* TODO corrective action? close socket? ignore for now */
        return;
        }

    version  = ntohs(message.header.version);
    mtype    = ntohs(message.header.mtype);
    sequence = ntohl(message.header.sequence);
    size     = ntohl(message.header.size);

    sequence = sequence;
    size = size;

    PRINT_MESSAGE("recv fd=%d, type=%s, from=%p %s, ns=%s\n", HB_GET_SCP_FD(scp), hb_get_message_type_name(mtype), scp, scp->name, ns->ns_name);

    if (version > HB_CURRENT_VERSION)
        {
        PRINT_ERR("Bad version: %d\n", version); 
        /* TODO corrective action? close socket? ignore for now */
        return;
        }

    switch(mtype)
        {
        case hbm_init:
            mismatch = 0;
            allow_init = 0;

            if (scp->state != hbs_server_waiting_init)
                {
                PRINT_ERR("hbm_init message recieved when not in hbs_server_waiting_init state %d (%s), name '%s'\n", scp->state, hb_get_state_name(scp->state), scp->name);
                if (strcmp(scp->name, message.body.init_body.name))
                    {
                    mismatch=1;
                    PRINT_ERR("hbm_init name mismatch, %s vs %s\n", scp->name, message.body.init_body.name);
                    }
                if (strcmp(scp->instance_name, message.body.init_body.instance_name))
                    {
                    mismatch=1;
                    PRINT_ERR("hbm_init name mismatch, %s vs %s\n", scp->name, message.body.init_body.name);
                    }
                if (strcmp(scp->instance_id, message.body.init_body.instance_id))
                    {
                    mismatch=1;
                    PRINT_ERR("hbm_init name mismatch, %s vs %s\n", scp->name, message.body.init_body.name);
                    }

                if (mismatch)
                    {
                    take_corrective_action(scp, "Message failed authentication", false);
                    end_server_client_session(ns, scp, true);
                    allow_init = 0;
                    }
                else
                    {
                    PRINT_ERR("Credentials match on unexpected hbm_init message, assuming client self recovered and no corrective action required against '%s'\n", scp->name);

                    /* clean up any voting from our prior life */
                    if (scp->delayed_response)
                        {
                        decrement_outstanding_votes(scp->delayed_response, scp, NULL, false, true);
                        }

                    allow_init = 1;
                    }
                }
            else
                {
                allow_init = 1;
                }

            if (allow_init)
                {
                if (ac_alarm_on_queue(&(scp->alarm)))
                    hb_dequeue_scp(scp);

                scp->state = hbs_server_waiting_challenge;
                scp->client_role = ntohs(message.body.init_body.role);

                snprintf(remote_addr_str, sizeof(remote_addr_str), "%d.%d.%d.%d",
                         (scp->remote_addr.sin_addr.s_addr >> 0) & 0xff,
                         (scp->remote_addr.sin_addr.s_addr >> 8) & 0xff,
                         (scp->remote_addr.sin_addr.s_addr >> 16) & 0xff,
                         (scp->remote_addr.sin_addr.s_addr >> 24) & 0xff);

                scp->heartbeat_id = idx;
                scp->pid = ntohs(message.body.init_body.pid);
                strncpy(scp->name, message.body.init_body.name, sizeof(scp->name));
                strncpy(scp->instance_name, message.body.init_body.instance_name, sizeof(scp->instance_name));
                strncpy(scp->instance_id, message.body.init_body.instance_id, sizeof(scp->instance_id));
                PRINT_DEBUG("set server_client name, ns=%s scp=%p (%s, %s, %s)\n", ns->ns_name, scp, scp->name, scp->instance_id, scp->instance_name);

                if (scp->client_role == hbr_vm)
                    {
                    if (scp->vio)
                        {
                        if (scp->vio->instance_name)
                            {
                            strncpy(scp->instance_name, scp->vio->instance_name, sizeof(scp->instance_name));
                            set_instance_id_from_instance_name_via_proxy(scp, scp->instance_name);
                            }
                        }
                    else
                        {
                        set_instance_id_from_addr_via_proxy(scp, remote_addr_str);
                        }
                    }

                PRINT_DEBUG("final server_client name, %p (%s, %s, %s)\n", scp, scp->name, scp->instance_id, scp->instance_name);

                scp->version = HB_CURRENT_VERSION;
                scp->sequence = sequence;

                scp->heartbeat_algorithm = hb_algorithm_xor;
                scp->heartbeat_secret = rand();
                scp->heartbeat_challenge = rand();
                scp->heartbeat_challenge_stored = rand();

                scp->corrective_action = ntohs(message.body.init_body.corrective_action);
                scp->corrective_action_var = ntohs(message.body.init_body.corrective_action_var);
                strncpy(scp->corrective_action_script, 
                        message.body.init_body.corrective_action_script,
                        sizeof(scp->corrective_action_script));

                scp->child_corrective_action = ntohs(message.body.init_body.child_corrective_action);
                scp->child_corrective_action_var = ntohs(message.body.init_body.child_corrective_action_var);
                strncpy(scp->child_corrective_action_script, 
                        message.body.init_body.child_corrective_action_script, 
                        sizeof(scp->child_corrective_action_script));

                PRINT_DEBUG("%s: corrective_action=%s (%d), var=%d, script='%s'\n", scp->name, hb_get_corrective_action_name(scp->corrective_action), scp->corrective_action, scp->corrective_action_var, scp->corrective_action_script ? scp->corrective_action_script : "");
                scp->interval.tv_sec = ntohl(message.body.init_body.hb_interval_secs);
                scp->interval.tv_nsec = ntohl(message.body.init_body.hb_interval_nsecs);
                scp->first_delay.tv_sec = ntohl(message.body.init_body.first_hb_secs);
                scp->first_delay.tv_nsec = ntohl(message.body.init_body.first_hb_nsecs);
                scp->vote_to.tv_sec = ntohl(message.body.init_body.vote_secs);
                scp->vote_to.tv_nsec = ntohl(message.body.init_body.vote_nsecs);
                scp->shutdown_notice_to.tv_sec = ntohl(message.body.init_body.shutdown_notice_secs);
                scp->shutdown_notice_to.tv_nsec = ntohl(message.body.init_body.shutdown_notice_nsecs);
                scp->suspend_notice_to.tv_sec = ntohl(message.body.init_body.suspend_notice_secs);
                scp->suspend_notice_to.tv_nsec = ntohl(message.body.init_body.suspend_notice_nsecs);
                scp->resume_notice_to.tv_sec = ntohl(message.body.init_body.resume_notice_secs);
                scp->resume_notice_to.tv_nsec = ntohl(message.body.init_body.resume_notice_nsecs);
                scp->downscale_notice_to.tv_sec = ntohl(message.body.init_body.downscale_notice_secs);
                scp->downscale_notice_to.tv_nsec = ntohl(message.body.init_body.downscale_notice_nsecs);
                scp->restart_to.tv_sec = ntohl(message.body.init_body.restart_secs);
                scp->restart_to.tv_nsec = ntohl(message.body.init_body.restart_nsecs);

                PRINT_INFO("Accepting Connection from: name = %s, id = %s, inst_name = %s, role = %s, "
                           "addr = %s, name space = %s, corrective_action = %s, script = %s\n",
                           scp->name,
                           scp->instance_id,
                           scp->instance_name,
                           hb_get_role_name(scp->client_role),
                           remote_addr_str,
                           scp->ns ? scp->ns->ns_name : "???", 
                           hb_get_corrective_action_name(scp->corrective_action),
                           scp->corrective_action_script ? scp->corrective_action_script : "");

                hb_set_interval_scp(scp, scp->interval.tv_sec, scp->interval.tv_nsec);
                hb_set_first_timeout_scp(scp, scp->first_delay.tv_sec, scp->first_delay.tv_nsec);
                hb_set_expire_func_scp(scp, expired_waiting_challenge);
                hb_enqueue_ns_scp(ns, scp);
                PRINT_DEBUG("enqueue alarm %p (%s) on clock %p (%s)\n", &(scp->alarm), scp->name, &(ns->alarm_clock), ns->ns_name);

                init_server_client_response(&response, scp, hbm_init_ack);
                strncpy(response.body.init_ack_body.instance_id, scp->instance_id, sizeof(response.body.init_ack_body.instance_id));
                response.body.init_ack_body.heartbeat_algorithm = htons(scp->heartbeat_algorithm);
                response.body.init_ack_body.heartbeat_secret = htonl(scp->heartbeat_secret);
                response.body.init_ack_body.heartbeat_challenge = htonl(scp->heartbeat_challenge_stored);
                response.body.init_ack_body.role = htons(hb_role);

                PRINT_MESSAGE("send hbm_init_ack to '%s'\n", scp->name);
                hb_sc_write(scp, &response, sizeof(response));

                set_timeouts_from_init(&message);
                }
            break;

        case hbm_init_ack:
            PRINT_ERR("hbm_init_ack message recieved by server\n");
            break;

        case hbm_init_fail:
            PRINT_ERR("hbm_init_fail message recieved by server\n");
            break;

        case hbm_exit:
            rc = validate_response(scp, &message, hbm_exit);
            if (rc == 0)
                {
                /* valid exit */
                PRINT_INFO("exit: FD=%d;  Slot=%d  log=%s\n", HB_GET_SCP_FD(scp), idx, message.body.exit_body.log_msg);
                end_server_client_session(ns, scp, true);
                }
            break;

        case hbm_challenge:
            PRINT_ERR("TODO hbm_challenge message recieved by server\n");
            break;

        case hbm_response:
            PRINT_MESSAGE("recv: hbm_response %d from '%s'\n", ntohl(message.body.response_body.heartbeat_response), scp->name);
            if (scp->state != hbs_server_waiting_response)
                {
                PRINT_ERR("hbm_response message recieved when not in hb_server_waiting_response state %d (%s)\n", scp->state, hb_get_state_name(scp->state));
                break;
                }
            rc = validate_response(scp, &message, hbm_response);
            if (rc == 0)
                {
                /* valid response */
                rc = ntohl(message.body.response_body.health_rc);
                if (rc == hbh_healthy)
                    {
                    hb_set_expire_func_scp(scp, expired_waiting_challenge);
                    scp->state = hbs_server_waiting_challenge;
                    if (scp->health_state != hbh_healthy)
                        {
                        scp->health_state = hbh_healthy;
                        memset(scp->health_err_msg, 0, sizeof(scp->health_err_msg));
                        PRINT_ERR("health restored to: name=%s; instance_id=%s; health_rc=%d; FD=%d; Slot=%d\n",
                                  scp->name, scp->instance_id, rc, HB_GET_SCP_FD(scp), scp->heartbeat_id);
                        }
                    hb_requeue_ns_scp(ns, scp);
                    PRINT_DEBUG("enqueue alarm %p (%s) on clock %p (%s)\n", &(scp->alarm), scp->name, &(ns->alarm_clock), ns->ns_name);
                    }
                else
                    {
                    int disconnect;

                    if (scp->health_state != hbh_unhealthy)
                        PRINT_ERR("Ill health reported by: name=%s; instance_id=%s; health_rc=%d; FD=%d; Slot=%d; Msg=%s\n",
                                  scp->name, scp->instance_id, rc, HB_GET_SCP_FD(scp), scp->heartbeat_id, message.body.response_body.err_msg);

                    disconnect = take_corrective_action(scp, message.body.response_body.err_msg, false);
                    if (disconnect)
                        end_server_client_session(ns, scp, true);
                    else
                        {
                        hb_set_expire_func_scp(scp, expired_waiting_challenge);
                        hb_requeue_ns_scp(ns, scp);
                        PRINT_DEBUG("enqueue alarm %p (%s) on clock %p (%s)\n", &(scp->alarm), scp->name, &(ns->alarm_clock), ns->ns_name);
                        }
                    }
                }
            break;

        case hbm_pause:
            if ((scp->state != hbs_server_waiting_challenge) &&
                (scp->state != hbs_server_waiting_response))
                {
                PRINT_ERR("TODO hbm_pause message recieved when not in challenge/response state %d (%s)\n", scp->state, hb_get_state_name(scp->state));
                }
            rc = validate_response(scp, &message, hbm_pause);
            if (rc == 0)
                {
                /* valid response */
                scp->state = hbs_server_paused;
                hb_set_expire_func_scp(scp, expired_waiting_resume);
                scp->pause_delay.tv_sec = ntohl(message.body.pause_body.pause_secs);
                scp->pause_delay.tv_nsec = ntohl(message.body.pause_body.pause_nsecs);
                hb_set_first_timeout_scp(scp, scp->pause_delay.tv_sec, scp->pause_delay.tv_nsec);
                hb_requeue_first_ns_scp(ns, scp);
                PRINT_DEBUG("enqueue alarm %p (%s) on clock %p (%s)\n", &(scp->alarm), scp->name, &(ns->alarm_clock), ns->ns_name);

                init_server_client_response(&response, scp, hbm_pause_ack);
                scp->heartbeat_challenge_stored = rand();
                response.body.pause_ack_body.heartbeat_challenge = htonl(scp->heartbeat_challenge_stored);

                PRINT_MESSAGE("send hbm_pause_ack to '%s'\n", scp->name);
                hb_sc_write(scp, &response, sizeof(response));
                }
            break;

        case hbm_pause_ack:
            PRINT_ERR("hbm_pause_ack message recieved by server\n");
            break;

        case hbm_resume:
            if (scp->state != hbs_server_paused)
                {
                PRINT_ERR("TODO hbm_resume message recieved when not in hb_server_paused state %d (%s)\n", scp->state, hb_get_state_name(scp->state));
                }
            rc = validate_response(scp, &message, hbm_resume);
            if (rc == 0)
                {
                /* valid response */
                scp->state = hbs_server_waiting_challenge;
                hb_set_expire_func_scp(scp, expired_waiting_challenge);
                hb_set_interval_scp(scp, scp->interval.tv_sec, scp->interval.tv_nsec);
                hb_requeue_ns_scp(ns, scp);

                init_server_client_response(&response, scp, hbm_resume_ack);
                scp->heartbeat_challenge_stored = rand();
                response.body.resume_ack_body.heartbeat_challenge = htonl(scp->heartbeat_challenge_stored);

                PRINT_MESSAGE("send hbm_resume_ack to '%s'\n", scp->name);
                hb_sc_write(scp, &response, sizeof(response));
                }
            break;

        case hbm_resume_ack:
            PRINT_ERR("hbm_pause_ack message recieved by server\n");
            break;

        case hbm_child_error:
            PRINT_ERR("TODO hbm_child_error message\n");
            break;

        case hbm_shutdown_request:
            PRINT_INFO("hbm_shutdown_request");
            rc = validate_response(scp, &message, hbm_shutdown_request);
            if (rc == 0)
                {
                /* valid response */
                handle_shutdown_request(ns, &message, scp, NULL, HB_GET_SCP_FD(scp));
                }
            break;

        case hbm_shutdown_response:
            rc = validate_response(scp, &message, hbm_shutdown_response);
            if (rc == 0)
                {
                /* valid response */
                PRINT_INFO("name=%s; instance_id=%s; vote=%d; msg='%s', FD=%d; Slot=%d\n",
                           scp->name, scp->instance_id, ntohs(message.body.shutdown_response_body.event_vote),
                           message.body.shutdown_response_body.err_msg, HB_GET_SCP_FD(scp), scp->heartbeat_id);
                handle_shutdown_response(ns, &message, scp);

                }
            break;
        case hbm_network_namespace:
            handle_network_namespace_event(ns, &message);
            break;
        case hbm_nova_cmd:
            hb_handle_hbm_nova_cmd(ns, &message, hbft_server_client);
            break;

        case hbm_server_exit:
            PRINT_ERR("TODO hbm_server_exit message recieved by server\n");
            break;

        case hbm_ping:
            PRINT_INFO("hbm_ping message recieved by server\n");
            switch (scp->state)
                {
                case hbs_server_nova_paused:
                case hbs_server_migrating:
                case hbs_server_paused:
                    scp->state = hbs_server_waiting_challenge;
                    PRINT_DEBUG("setting state hbs_server_waiting_challenge and program alarm %p\n", &(scp->alarm));
                    hb_set_expire_func_scp(scp, expired_waiting_challenge);
                    hb_set_first_timeout_scp(scp, scp->interval.tv_sec, scp->interval.tv_nsec);
                    break;
                case hbs_server_waiting_init:
                case hbs_server_waiting_challenge:
                case hbs_server_waiting_response:
                case hbs_server_corrective_action:
                default:
                    // no action
                    break;

                }
            break;

        case hbm_timeouts:
            hb_handle_hbm_timeouts(ns, &message);
            break;

        default:
            PRINT_ERR("Bad message: %d\n", mtype);
            break;
        }
    }

#ifdef HB_USE_POLL
void read_ready_sockets(ns_data_t *ns) 
    {
    int i;   
    struct pollfd *pp;
    hb_fd_data_t  *fp;
    hb_server_client_t* scp = NULL;
    hb_server_t *server = NULL;
    vio_record_t  *vio = NULL;

    for(i=0; i < ns->pollfd_data.array_high; i++)
        {
        pp = &(ns->pollfd_data.pollfd_array[i]);
        fp = &(ns->pollfd_data.fd_array[i]);

        if ((pp->revents & POLLIN) == POLLIN)
            {
            PRINT_DEBUG("POLLIN on i=%d, fd=%d, type=%s\n", i, pp->fd, hb_get_fd_type_name(fp->fd_type));
            pp->revents = (pp->revents & ~POLLIN);

            switch(fp->fd_type)
                {
                case hbft_client:
                case hbft_client_vio:
                    handle_client_connection(ns->client);
                    break;
                case hbft_server:
                    handle_new_connection(ns);
                    break;
                case hbft_server_vio:
                    if ((pp->revents & POLLERRORS) == 0)
                        handle_new_vio_connection(ns, pp->fd);
                    break;
                case hbft_server_client:
                case hbft_server_client_vio:
                    scp = fp->ptr;
                    handle_server_connection(ns, scp);
                    if (fp->fd_type != hbft_server_client_vio)
                        pp->revents = 0;
                    break;
                case hbft_ns_pipe:
                    handle_pipe_connection(ns);
                    break;
                case hbft_inotify:
                    vio_inotify_event(ns);
                    break;
                case hbft_unknown:
                default:
                    PRINT_ERR("Unknown fd type %d\n", fp->fd_type);
                    break;
                }

            PRINT_DEBUG("out POLLIN on i=%d, fd=%d, type=%s\n", i, pp->fd, hb_get_fd_type_name(fp->fd_type));
            }

        if ((pp->revents & POLLERRORS) != 0)
            {
            PRINT_INFO("revents = %x on fd=%d, type=%s\n", pp->revents, pp->fd, hb_get_fd_type_name(fp->fd_type));
            pp->revents = 0;

            // This slot on poolfd_array may become vacant as a result of corrective action.
            // Vacant slots backfilled from a higher slot, so we must revisit this index.
	    i--;   

            switch(fp->fd_type)
                {
                case hbft_client:
                case hbft_client_vio:
                    handle_client_disconnect(ns->client, 0);
                    break;
                case hbft_server:
                    server = &(ns->server);
                    close(server->sock);
                    server->sock = -1;
                    heartbeat_exit(EXIT_FAILURE, __FUNCTION__);
                    break;
                case hbft_server_vio:
                    vio = vio_ptr_find_by_fd(pp->fd);
                    if (vio)
                        vio_reconnect(vio, ns);
                    break;
                case hbft_server_client:
                case hbft_server_client_vio:
                    scp = fp->ptr;
                    take_corrective_action(scp, "Connection Error", true);
                    end_server_client_session(ns, scp, 1);
                    break;
                case hbft_ns_pipe:
                    heartbeat_exit(EXIT_FAILURE, __FUNCTION__);
                    break;
                case hbft_inotify:
                    heartbeat_exit(EXIT_FAILURE, __FUNCTION__);
                    break;
                case hbft_unknown:
                default:
                    PRINT_ERR("Unknown fd type %d\n", fp->fd_type);
                    heartbeat_exit(EXIT_FAILURE, __FUNCTION__);
                    break;
                }
            }
        }
    }
#endif /* HB_USE_POLL */

#ifdef HB_USE_SELECT
void read_ready_sockets(ns_data_t *ns) 
    {
    int i;   
    hb_server_client_t* scp = NULL;

    /* Handle new connections */
    if (FD_ISSET(ns->server.sock, &(ns->ready_read_socks)))
        {
        handle_new_connection(ns);
        }
    
    for(i=0; i<=vio_data.highsock; i++)
        {
        if (FD_ISSET(i, &(vio_data.waiting_socks)) && FD_ISSET(i, &(ns->ready_read_socks)))
            {
            handle_new_vio_connection(ns, i);
            }
        }

    if (ns->client)
        {
        if (((ns->client->sock >= 0) && FD_ISSET(ns->client->sock, &(ns->ready_read_socks))) ||
            ((ns->client->vio_fd >= 0) && FD_ISSET(ns->client->vio_fd, &(ns->ready_read_socks))))
            {
            handle_client_connection(ns->client);
            }
        }
    
    if (ns->pipe_fd[READ_PIPE] >= 0)
        {
        if (FD_ISSET(ns->pipe_fd[READ_PIPE], &(ns->ready_read_socks)))
            {
            handle_pipe_connection(ns);
            }
        }
    
    /* Handle messages on existing connections */
    for (i = 0; i < HB_MAX_CLIENTS; i++)
        {
        scp = ns->server.connections[i];
        if (scp)
            {
            PRINT_DEBUG("i=%d, scp=%s, vio=%p (%s), sock=%d, vio_fd=%d\n", i, scp->name, scp->vio, scp->vio->instance_name, scp->sock, scp->vio->fd);
            if (((scp->sock >= 0) && FD_ISSET(scp->sock, &(ns->ready_read_socks))) ||
                (scp->vio && (scp->vio->fd >= 0) && FD_ISSET(scp->vio->fd, &(ns->ready_read_socks))))
                {
                handle_server_connection(ns, scp);
                }
            }
        } 

    /* Handle new/deleted vio sockets */
    if (FD_ISSET(vio_data.inotify_fd, &(ns->ready_read_socks)))
        {
        vio_inotify_event(ns);
        }

    }
#endif /* HB_USE_SELECT */


#ifdef HB_USE_POLL
void server_loop_body(ns_data_t *ns)
    {
    int num_socks;  /* Number of sockets ready for reading */
        
  retry:
    num_socks = ac_ppoll(&(ns->alarm_clock),
                         ns->pollfd_data.pollfd_array,
                         ns->pollfd_data.array_high,
                         NULL,
                         NULL);

    if (num_socks < 0)
        {
        if (errno == EINTR)
            goto retry;

        PRINT_ERR("poll: %s\n", strerror(errno));
        heartbeat_exit(EXIT_FAILURE, __FUNCTION__);
        }

    if (num_socks != 0)
        {
        read_ready_sockets(ns);
        }
    }
#endif /* HB_USE_POLL */

#ifdef HB_USE_SELECT
void server_loop_body(ns_data_t *ns)
    {
    int high;
    int num_socks;  /* Number of sockets ready for reading */
        
  retry:
    ns->ready_read_socks = ns->read_socks;
    high = ns->highsock + 1;
    num_socks = ac_select(&(ns->alarm_clock),
                             high,
                             &(ns->ready_read_socks),
                             (fd_set *) 0, 
                             (fd_set *) 0,
                             NULL); 

    if (num_socks < 0)
        {
        if (errno == EINTR)
            goto retry;

        PRINT_ERR("select: %s\n", strerror(errno));
        heartbeat_exit(EXIT_FAILURE, __FUNCTION__);
        }

    if (num_socks != 0)
        {
        read_ready_sockets(ns);
        }
    }
#endif /* HB_USE_SELECT */

void server_loop(ns_data_t *ns)
    {
    while (!exit_loop) 
        { 
        server_loop_body(ns);
        }
    }



FILE* hb_popen(char  *program, 
               char  *type,
               pid_t *pid_ptr)
    {
    FILE *iop;
    int pipe_fds[2];
    int rc;

    if ((*type != 'r' && *type != 'w') || type[1] || !pid_ptr)
        return (NULL);

    rc = pipe(pipe_fds);
    if (rc < 0)
        return (NULL);

    *pid_ptr = fork();
    if (*pid_ptr <= -1) 
        {
        /* error */
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        return NULL;
        }

    if (*pid_ptr == 0)
        {
        /* child */
        if (*type == 'r') 
            {
            if (pipe_fds[1] != fileno(stdout))
                {
                dup2(pipe_fds[1], fileno(stdout));
                close(pipe_fds[1]);
                }
            close(pipe_fds[0]);
            }
        else
            {
            if (pipe_fds[0] != fileno(stdin))
                {
                dup2(pipe_fds[0], fileno(stdin));
                close(pipe_fds[0]);
                }
            close(pipe_fds[1]);
            }
        execl("/bin/sh", "sh", "-c", program, NULL);
        _exit(127);
        }

    /* parent; assume fdopen can't fail...  */
    if (*type == 'r') 
        {
        iop = fdopen(pipe_fds[0], type);
        close(pipe_fds[1]);
        }
    else
        {
        iop = fdopen(pipe_fds[1], type);
        close(pipe_fds[0]);
        }

    return (iop);
    }

int hb_pclose(FILE  *iop,
              pid_t *pid_ptr)
    {
    sigset_t omask;
    sigset_t nmask;
    union wait pstat;
    int wpid;

    /*
     * pclose returns -1 if stream is not associated with a
     * `popened' command, if already `pclosed', or waitpid
     * returns an error.
     */
    if (!pid_ptr || !iop)
        return (-1);

    fclose(iop);
    sigemptyset(&nmask);
    sigaddset(&nmask, SIGINT);
    sigaddset(&nmask, SIGQUIT);
    sigaddset(&nmask, SIGHUP);
    sigprocmask(SIG_BLOCK, &nmask, &omask);

    do  {
        wpid = waitpid(*pid_ptr, (int *) &pstat, 0);
        } while (wpid == -1 && errno == EINTR);

    sigprocmask(SIG_SETMASK, &omask, NULL);
    *pid_ptr = 0;
    return (wpid == -1 ? -1 : pstat.w_status);
    }


heartbeat_event_vote_t hb_event_handling_script_wrapper(heartbeat_event_t         event_type,
                                                        heartbeat_notification_t  notification_type, 
                                                        void                     *arg,
                                                        char                     *err_msg_buff,
                                                        int                       err_msg_buff_size,
                                                        pid_t                    *pid_ptr)
    {
    char* script = arg;
    int rc;
    int exit_rc = 0;
    heartbeat_event_vote_t vote = (notification_type == hbnt_revocable) ? hbev_accept : hbev_complete;
    char cmd[1024];
    int save_errno;
    char buffer[HB_LOG_MSG_SIZE];
    char msg[HB_LOG_MSG_SIZE];
    FILE *fp;
    char *s;
    pid_t pid=0;

    memset(buffer, 0, sizeof(buffer));
    memset(msg, 0, sizeof(msg));
    sprintf(cmd, "%s %s %s", script, hb_get_notification_name(notification_type), hb_get_event_name(event_type));
    PRINT_INFO("cmd=%s\n", cmd);

    if (!pid_ptr)
        pid_ptr = &pid;

    fp = hb_popen(cmd, "r", pid_ptr);
    save_errno = errno;
    if (fp)
        {
        s = fgets(buffer, sizeof(buffer), fp);
        if (s)
            snprintf(msg, sizeof(msg), "%s", s);
        else
            snprintf(msg, sizeof(msg), "No Error text provided by script");

        rc = hb_pclose(fp, pid_ptr);
        save_errno = errno;
        if (rc == -1)
            {
            PRINT_ERR("popen(%s) failed: %s\n", cmd, strerror(save_errno));
            snprintf(err_msg_buff, err_msg_buff_size,
                     "pclose() failed: %s: on cmd: %s", strerror(save_errno), cmd);
            exit_rc = -1;
            }
        if (WIFEXITED(rc))
            {
            exit_rc = WEXITSTATUS(rc);
            if (exit_rc == 127)
               {
               PRINT_ERR("popen() failed: bad path or permissions for '%s'\n", cmd);
               snprintf(err_msg_buff, err_msg_buff_size,
                        "popen()  failed: bad path or permissions for '%s'\n", cmd);
               exit_rc = -1;
               }
            else if (exit_rc && (notification_type == hbnt_revocable))
               {
               vote = hbev_reject;
               snprintf(err_msg_buff, err_msg_buff_size, "%s rejected: %s", 
                        hb_get_event_name(event_type), msg);
               }

            PRINT_INFO("popen(%s) exit rc: %d, msg '%s'\n", cmd, exit_rc, err_msg_buff);
            }
        else if (WIFSIGNALED(rc))
            {
            exit_rc = WTERMSIG(rc);
            PRINT_ERR("popen(%s) killed by signal: %d\n", s, exit_rc);
            snprintf(err_msg_buff, err_msg_buff_size, "popen(%s) killed by signal: %d", 
                     cmd, exit_rc);
            exit_rc = -1;
            }
        }
    else
        {
        PRINT_ERR("popen(%s) failed: %s\n", cmd, strerror(errno));
        snprintf(err_msg_buff, err_msg_buff_size, "popen(%s) failed: %s", 
                 cmd, strerror(save_errno));
        exit_rc = -1;
        }

    return vote;
    }


void daemonize(void)
    {
    pid_t pid;
    pid_t sid;
    int fd;

    /* Test if already a daemon */
    if ( getppid() == 1 )
        return;

    /* Not yet, daemonize now */

    /* Fork off the parent process */
    pid = fork();
    if (pid < 0)
        {
        exit(EXIT_FAILURE);
        }

    if (pid > 0)
        {
        exit(EXIT_SUCCESS); /*Killing the Parent Process*/
        }

    /* At this point we are executing as the child process */

    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0)
        {
        exit(EXIT_FAILURE);
        }

    /* Change the current working directory. */
    if ((chdir("/")) < 0)
        {
        exit(EXIT_FAILURE);
        }


    fd = open("/dev/null",O_RDWR, 0);

    if (fd != -1)
        {
        dup2 (fd, STDIN_FILENO);
        dup2 (fd, STDOUT_FILENO);
        dup2 (fd, STDERR_FILENO);

        if (fd > 2)
            {
            close (fd);
            }
        }

    /* reset file creation mask */
    umask(027);
    }

void hb_ping(int sock)
    {
    heartbeat_message_t message;
    PRINT_MESSAGE("send hbm_ping %d\n", sock);
    init_pipe_message(&message, hbm_ping);
    hb_write(sock, &message, sizeof(message));
    }

void sigusr1_handler(int sig)
    {
    sig = sig;
    if (hb_debug_message)
       hb_debug_message = 0;
    else
       hb_debug_message = 1;
    }

void sigusr2_handler(int sig)
    {
    sig = sig;
    if (hb_debug_debug)
       hb_debug_debug = 0;
    else
       hb_debug_debug = 1;
    }

void sigterm_handler(int sig)
    {
    int status;

    sig = sig;
    PRINT_INFO("Recieved sig=%d, exiting\n", sig);
    if (child_pid)
        {
        kill(child_pid, SIGTERM);
        status = 0;
        waitpid(-1, &status, 0);
        exit(0);
        }
    else
        {
        exit_loop = 1;

        if (server_flag && (server_ns.pipe_fd[WRITE_PIPE] >= 0))
            hb_ping(server_ns.pipe_fd[WRITE_PIPE]);
        if (client_flag && (client.sock >= 0))
            hb_ping(client.sock);
        }
    }

void signal_handler_setup()
    {
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigterm_handler;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sa.sa_handler = sigusr1_handler;
    sigaction(SIGUSR1, &sa, NULL);
    sa.sa_handler = sigusr2_handler;
    sigaction(SIGUSR2, &sa, NULL);
    }

void self_restart()
    {
    int status;
    /* parent will monitor child, restart child if it exits ablormally */
    child_pid = fork();
    PRINT_INFO("fork: pid = %d\n", child_pid);

    if (child_pid == 0)
       return;

    if (child_pid < 0)
        {
        PRINT_ERR("fork: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
        }

    while(1)
        {
        status = 0;

        waitpid(-1, &status, 0);

        if (WIFEXITED(status) && (WEXITSTATUS(status)==0))
            exit(0);

        child_pid = fork();
        PRINT_INFO("fork: pid = %d\n", child_pid);

        if (child_pid == 0)
            return;

        if (child_pid < 0)
            {
            PRINT_ERR("fork: crashed and cannot restart: %s\n", strerror(errno));
            exit(1);
            }

        sleep(1);
        }
    }


char* trim(char* s, char* discard)
    {
    int l;

    if (!s)
        return NULL;

    while(*s && (isspace(*s) || (discard && strchr(discard, *s))))
       s++;
    for(l = strlen(s)-1; l>=0 && (isspace(s[l]) || s[l]=='\n' || (discard && strchr(discard, s[l]))); l--)
        s[l]='\0';
    return s;
    }

hb_conf_t hb_conf = 
    {
    HB_DEFAULT_FIRST_MS,     // first
    HB_DEFAULT_INTERVAL_MS,  // interval
    HB_DEFAULT_VOTE_MS,      // vote
    HB_DEFAULT_SHUTDOWN_MS,  // shutdown_notice
    HB_DEFAULT_SUSPEND_MS,   // suspend_notice
    HB_DEFAULT_RESUME_MS,    // resume_notice
    HB_DEFAULT_DOWNSCALE_MS, // downscale_notice
    HB_DEFAULT_RESTART_MS,   // restart

    hbca_instance_reboot,    // corrective_action;
    0,                       // corrective_var;
    "",                      // corrective_script;

    ""                       // event_handling_script;
    };


int read_conf_file(char *conf_fn)
    {
    FILE *fp;
    char buf[1024];
    char *s;
    char *key;
    char *value;
    char *delim = "=";
    char *discard = "\'\"";

    fp = fopen(conf_fn, "r");
    if (!fp)
        return -1;

    while ((s = fgets(buf, sizeof(buf), fp)))
        {
        s = trim(s, NULL);

        if ((*s == '\0') || (*s == '#'))
            continue;

        key = strtok(s, delim);
        value = strtok(NULL, delim);

        key = trim(key, discard);
        value = trim(value, discard);

        if (key && value)
            {
            if (0==strcmp("FIRST_HB", key))
                hb_conf.first = atoi(value);
            else if (0==strcmp("HB_INTERVAL", key))
                hb_conf.interval = atoi(value);
            else if (0==strcmp("VOTE", key))
                hb_conf.vote = atoi(value);
            else if (0==strcmp("SHUTDOWN_NOTICE", key))
                hb_conf.shutdown_notice = atoi(value);
            else if (0==strcmp("SUSPEND_NOTICE", key))
                hb_conf.suspend_notice = atoi(value);
            else if (0==strcmp("RESUME_NOTICE", key))
                hb_conf.resume_notice = atoi(value);
            else if (0==strcmp("DOWNSCALE_NOTICE", key))
                hb_conf.downscale_notice = atoi(value);
            else if (0==strcmp("RESTART", key))
                {
                hb_conf.restart = atoi(value);
                }
            else if (0==strcmp("CORRECTIVE_ACTION", key))
                {
                hb_conf.corrective_action = corrective_action_str_to_idx(value);
                }
            else if (0==strcmp("CORRECTIVE_VAR", key))
                {
                hb_conf.corrective_var = atoi(value);
                }
            else if (0==strcmp("CORRECTIVE_SCRIPT", key))
                {
                strncpy(hb_conf.corrective_script, value, sizeof(hb_conf.corrective_script));
                }
            else if (0==strcmp("EVENT_NOTIFICATION_SCRIPT", key))
                {
                strncpy(hb_conf.event_handling_script, value, sizeof(hb_conf.event_handling_script));
                }
            else if (0==strcmp("HEARTBEAT_ENABLED", key))
                {
                }
            else
                PRINT_ERR("unknown key = '%s' in conf file '%s'\n", key, conf_fn);

            }
        }

    fclose(fp);
    return 0;
    }

int main(int argc, char *argv[])
    {
    int i;
    int rc;
    int host_idx = 0;
    int name_idx = 0;
    int daemonize_flag = 0;
    int pmon_flag = 0;
    int ca_idx = 0;
    int instance_idx = 0;
    int instance_name_idx = 0;
    int corrective_idx = 0;
    int ca_script_idx = 0;
    int vote_script_idx = 0;

    hb_early_init();

    syslog_fd = open("/proc/self/ns/net", O_RDONLY);

    bind_heartbeat_exit_fptr(heartbeat_exit);
    ac_bind_exit_fptr(heartbeat_exit);
    
    bind_handle_shutdown_request_fptr(handle_shutdown_request);
    bind_handle_shutdown_response_fptr(handle_shutdown_response);
    bind_handle_network_namespace_event_fptr(handle_network_namespace_event);

    read_conf_file(HEARTBEAT_CONF);

    for(i=1;i<argc;i++)
        {
        if (0==strcmp(argv[i], "--control"))
            hb_role = hbr_control;
        else if (0==strcmp(argv[i], "--compute"))
            hb_role = hbr_compute;
        else if (0==strcmp(argv[i], "--vm"))
            hb_role = hbr_vm;
        else if (0==strcmp(argv[i], "--server_port"))
            {
            i++;
            if (i<argc)
               s_port = atoi(argv[i]);
            else
               usage();
            }
        else if (0==strcmp(argv[i], "--client_port"))
            {
            i++;
            if (i<argc)
               c_port = atoi(argv[i]);
            else
               usage();
            }
        else if (0==strcmp(argv[i], "--client_addr"))
            {
            i++;
            if (i<argc)
                ca_idx = i;
            else
               usage();
            }
        else if (0==strcmp(argv[i], "--client_host"))
            {
            i++;
            if (i<argc)
                host_idx = i;
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
        else if (0==strcmp(argv[i], "--first"))
            {
            i++;
            if (i<argc)
               hb_conf.first = atoi(argv[i]);
            else
               usage();
            }
        else if (0==strcmp(argv[i], "--interval"))
            {
            i++;
            if (i<argc)
               hb_conf.interval = atoi(argv[i]);
            else
               usage();
            }
        else if ((0==strcmp(argv[i], "--instance_id")) ||
                 (0==strcmp(argv[i], "--instance")))
            {
            i++;
            if (i<argc)
                instance_idx = i;
            else
               usage();
            }
        else if (0==strcmp(argv[i], "--instance_name"))
            {
            i++;
            if (i<argc)
                instance_name_idx = i;
            else
               usage();
            }
        else if (0==strcmp(argv[i], "--corrective"))
            {
            i++;
            if (i<argc)
                corrective_idx = i;
            else
               usage();
            }
        else if (0==strcmp(argv[i], "--corrective_var"))
            {
            i++;
            if (i<argc)
                hb_conf.corrective_var = atoi(argv[i]);
            else
               usage();
            }
        else if (0==strcmp(argv[i], "--corrective_script"))
            {
            i++;
            if (i<argc)
                ca_script_idx = i;
            else
               usage();
            }
        else if (0==strcmp(argv[i], "--event_handling_script"))
            {
            i++;
            if (i<argc)
                vote_script_idx = i;
            else
               usage();
            }
        else if (0==strcmp(argv[i], "--daemon"))
            daemonize_flag = 1;
        else if (0==strcmp(argv[i], "--pmon"))
            pmon_flag = 1;
        else if (0==strcmp(argv[i], "--help"))
           usage();
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
           usage();
        }

    switch (hb_role)
        {
        case hbr_control:
            server_flag=1; 
            client_flag=0; 
            break;
        case hbr_compute:
            server_flag=1; 
            client_flag=1; 
            break;
        case hbr_vm:
            server_flag=1; 
            client_flag=1; 
            break;
        default:
            usage();
            break;
        }

    if (!client_flag && !server_flag)
        usage();

    if ((hb_role == hbr_control) || (hb_role == hbr_compute))
        {
        if (!getenv("OS_USERNAME") || !getenv("OS_PASSWORD"))
            {
            PRINT_ERR("OS_USERNAME and OS_PASSWORD environment variables must be set\n");
            }
        }

    if (server_flag)
        {
        memset(&server_ns, 0, sizeof(server_ns));
        server_ns.ns_fd = -1;
        server_ns.pipe_fd[0] = -1;
        server_ns.pipe_fd[1] = -1;
        server_ns.server.sock = -1;
        }

    if (client_flag)
        {
        int stat_rc;
        struct stat stat_data;

        stat_rc = stat(HEARTBEAT_VIRTIO_FILE, &stat_data);

        memset(&client, 0, sizeof(client));
        client.port = c_port;

        if (stat_rc && ((!host_idx && !ca_idx) || (host_idx && ca_idx)))
            {
            PRINT_ERR("In absence of '%s', you must provide one of --client_host or --client_addr\n", HEARTBEAT_VIRTIO_FILE);
            usage();
            }

        if (host_idx)
            {
            struct hostent *my_hostent;
            struct in_addr *my_in_addr;
            char *my_addr_str;

            strncpy(client.remote_hostname, argv[host_idx], sizeof(client.remote_hostname));
            my_hostent = gethostbyname( client.remote_hostname );
            if (!my_hostent)
                {
                PRINT_ERR("Could not resolve hostname %s\n", client.remote_hostname);
                usage();
                }    

            my_in_addr = (struct in_addr*) my_hostent->h_addr_list[0];
            my_addr_str = inet_ntoa( *my_in_addr );
            strncpy(client.remote_addr, my_addr_str, sizeof(client.remote_addr));
            }

        if (ca_idx)
            {
            struct hostent *my_hostent;
            struct in_addr my_in_addr;

            strncpy(client.remote_addr, argv[ca_idx], sizeof(client.remote_addr));
            inet_aton(client.remote_addr, &my_in_addr);
            my_hostent = gethostbyaddr(&my_in_addr, sizeof(in_addr_t), AF_INET); 
            if (!my_hostent)
                {
                PRINT_INFO("Could not resolve host address %s: %s\n", client.remote_addr, strerror(errno));
                strncpy(client.remote_hostname, client.remote_addr, sizeof(client.remote_hostname));
                }    
            else
                {
                strncpy(client.remote_hostname, my_hostent->h_name, sizeof(client.remote_hostname));
                }
            }
        }

    /* turn this process into an independent daemon */
    if ( daemonize_flag )
       {
       daemonize();
       }

    signal_handler_setup();

    if ( !pmon_flag )
       {
       self_restart();
       }

    server_ns.next = NULL;
    server_ns.ns_name = HB_NS_DEFAULT_NAME;
    server_ns.thread = 0;
    server_ns.ns_fd = syslog_fd;
    ns_insert(&server_ns);
    init_ns(&server_ns, (client_flag ? &client : NULL));

    if (client_flag)
        {

        strncpy(client.instance_name, instance_name_idx ? argv[instance_name_idx] : "???", sizeof(client.instance_name));
        strncpy(client.instance_id, instance_idx ? argv[instance_idx] : "???", sizeof(client.instance_id));
        PRINT_INFO("Set client instance_id to %s, instance_idx = %d\n", client.instance_id, instance_idx);
        PRINT_INFO("Set client instance_name to %s, instance_name_idx = %d\n", client.instance_name, instance_name_idx);

        strncpy(client.name, 
                name_idx ? argv[name_idx] 
                         : (hb_role == hbr_vm ? client.instance_id 
                                              : hb_hostname), 
                sizeof(client.name));
        PRINT_DEBUG("Set client name to %s, name_idx = %d, hb_role = %d (%s)\n", client.name, name_idx, hb_role, hb_get_role_name(hb_role));

        client.corrective_action = corrective_idx ? corrective_action_str_to_idx(argv[corrective_idx]) : hb_conf.corrective_action;
        client.corrective_action_var = hb_conf.corrective_var;
        strncpy(client.corrective_action_script, ca_script_idx ? argv[ca_script_idx] : hb_conf.corrective_script, sizeof(client.corrective_action_script));
        client.first_hb.tv_sec = hb_conf.first / 1000;
        client.first_hb.tv_nsec = (hb_conf.first % 1000) * 1000000;
        client.hb_interval.tv_sec = hb_conf.interval / 1000;
        client.hb_interval.tv_nsec = (hb_conf.interval % 1000) * 1000000;
        client.vote_to.tv_sec = hb_conf.vote / 1000;
        client.vote_to.tv_nsec = (hb_conf.vote % 1000) * 1000000;
        client.shutdown_notice_to.tv_sec = hb_conf.shutdown_notice / 1000;
        client.shutdown_notice_to.tv_nsec = (hb_conf.shutdown_notice % 1000) * 1000000;
        client.suspend_notice_to.tv_sec = hb_conf.suspend_notice / 1000;
        client.suspend_notice_to.tv_nsec = (hb_conf.suspend_notice % 1000) * 1000000;
        client.resume_notice_to.tv_sec = hb_conf.resume_notice / 1000;
        client.resume_notice_to.tv_nsec = (hb_conf.resume_notice % 1000) * 1000000;
        client.downscale_notice_to.tv_sec = hb_conf.downscale_notice / 1000;
        client.downscale_notice_to.tv_nsec = (hb_conf.downscale_notice % 1000) * 1000000;
        client.restart_to.tv_sec = hb_conf.restart / 1000;
        client.restart_to.tv_nsec = (hb_conf.restart % 1000) * 1000000;

        if (vote_script_idx || (hb_conf.event_handling_script && hb_conf.event_handling_script[0]))
            {
            client.proxied_event_handler_func = hb_event_handling_script_wrapper;
            client.event_handler_func = NULL;
            client.event_handler_arg = strdup(vote_script_idx ? argv[vote_script_idx] : hb_conf.event_handling_script);
            }
        else
            {
            client.proxied_event_handler_func = NULL;
            client.event_handler_func = NULL;
            client.event_handler_arg = NULL;
            }

        client.ns = &server_ns;
        rc = init_client(&client, true);
        if (rc < 0)
            heartbeat_exit(1, "init_client failed");
        }

    if (server_flag)
        {
        init_server(&(server_ns.server), &server_ns);
        if (hb_role == hbr_compute)
            vio_server_init(&server_ns);
        }

    if (hb_role == hbr_compute)
        {
        discover_namespaces();

        /* Would be better to get name space creation events out of open stack. 
         * Launch a thread to poll for new namespaces from time to time. 
         */
        discover_namespaces_thread_start();

        /* Sometime we can get inotify events before qemu has the back end
         * of the socket ready for connections.  The connection fails.
         * This gives us a retry on those failed connection attempts.
         */
        discover_vio_thread_start();
        }

    server_loop(&server_ns);

    heartbeat_exit(0, "Recieved SIGTERM");

    return 0;
    }



int expired_waiting_shutdown_response(alarm_t* p)
    {
    int i;
    hb_server_client_t *scp;
    ns_data_t          *ns;
    heartbeat_delayed_message_t *delayed = NULL;
    int rc = ALARM_CLOCK_STOP;

    i = alarm_get_id(p);
    ns = alarm_get_util_ptr(p);
    scp = ns->server.connections[i];
    PRINT_DEBUG("p = %p, i=%d, ns=%p (%s), scp=%p (%s)\n", p, i, ns, ns->ns_name, scp, scp ? scp->name : "???");

    if (scp->state != hbs_client_waiting_shutdown_response)
        {
        PRINT_ERR("unexpected state %d (%s) vs %d (%s)\n", scp->state, hb_get_state_name(scp->state), 
                  hbs_client_waiting_shutdown_response, hb_get_state_name(hbs_client_waiting_shutdown_response));
        }

    if (scp->delayed_response)
        delayed = scp->delayed_response;
    else if (ns->delayed_response)
        delayed = ns->delayed_response;

    if (delayed)
        {
        delayed->vote = hbev_timeout_error;
        delayed->response.body.shutdown_response_body.event_vote = htons((uint16_t)delayed->vote);
        snprintf(delayed->response.body.shutdown_response_body.err_msg,
                 sizeof(delayed->response.body.shutdown_response_body.err_msg),
                 "Heartbeat server timed out waiting for response to '%s'",
                 hb_get_event_name(ntohl(delayed->response.body.shutdown_response_body.event_type)));

        rc = decrement_outstanding_votes(delayed, NULL, scp, true, false);
        }
    else
        {
        PRINT_ERR("delayed_response not set\n");
        rc = delayed_action_cleanup(ns, scp, NULL, hbet_unknown, hbnt_unknown, scp, true, false);
        }

    return rc;
    }


int decrement_outstanding_votes(heartbeat_delayed_message_t *delayed, 
                                hb_server_client_t          *voting_scp,
                                hb_server_client_t          *expired_scp,
                                int                          timeout,
                                int                          need_queue)
    {   
    atomic_type old_outstanding;
    atomic_type new_outstanding;
    heartbeat_event_vote_t new_vote;
    int rc;

retry:
    if (voting_scp || expired_scp || (delayed && delayed->outstanding < 10))
        PRINT_DEBUG("voting_scp = %s, expired_scp = %s, delayed = %p, timeout = %d, need_queue = %d\n", 
                   voting_scp ? voting_scp->name : "???",
                   expired_scp ? expired_scp->name : "???",
                   delayed, timeout, need_queue);

    old_outstanding = delayed->outstanding;
    new_outstanding = old_outstanding - 1;
    rc = atomic_test_and_set_if_eq(&(delayed->outstanding), old_outstanding, new_outstanding);
    if (!rc)
        goto retry;

    if ((delayed->vote != hbev_waiting) || (new_outstanding < 3))
       PRINT_DEBUG("notification_type %d (%s), outstanding %d -> %d, vote %d (%s)\n", delayed->notification_type, hb_get_notification_name(delayed->notification_type), (int)old_outstanding, (int)new_outstanding, (int)delayed->vote, hb_get_vote_name(delayed->vote));
    if (new_outstanding > 0)
        {
        if (voting_scp || expired_scp || (delayed && delayed->outstanding < 10))
            PRINT_DEBUG("new_outstanding = %d\n", (int)new_outstanding);
        return delayed_action_cleanup(delayed->ns, voting_scp ? voting_scp : (expired_scp ? expired_scp : delayed->scp),
                                      delayed, delayed->event_type, delayed->notification_type, expired_scp, timeout, need_queue);
        }

    /* I'm the last vote */
    /* Make sure a vote result has been transmitted */
    new_vote = delayed->vote;
    PRINT_INFO("Final vote: %d (%s) before cleanup\n", new_vote, hb_get_vote_name(new_vote)); 
    if (new_vote == hbev_waiting)
        {
        switch(delayed->notification_type)
            {
            case hbnt_revocable:
                new_vote = hbev_accept;
                break;
            case hbnt_irrevocable:
                new_vote = hbev_complete;
                break;
            case hbnt_unknown:
            default:
                /* No change */
                break;
            }

        }
    
    delayed->response.body.shutdown_response_body.event_vote = htons(new_vote);

    PRINT_INFO("Final vote: event_type %d (%s), notification_type %d (%s), vote %d (%s), msg '%s'\n", 
               delayed->event_type, hb_get_event_name(delayed->event_type),
               delayed->notification_type, hb_get_notification_name(delayed->notification_type),
               new_vote, hb_get_vote_name(new_vote),
               delayed->response.body.shutdown_response_body.err_msg);

    if (delayed->reply_scp && (delayed->sock == HB_GET_SCP_FD(delayed->reply_scp)))
        hb_sc_write(delayed->reply_scp, &(delayed->response), sizeof(delayed->response));
    else if (delayed->scp && (delayed->sock == HB_GET_SCP_FD(delayed->scp)))
        hb_sc_write(delayed->scp, &(delayed->response), sizeof(delayed->response));
    else if (delayed->ns && delayed->ns->client && (delayed->sock == HB_GET_CLIENT_FD(delayed->ns->client)))
        hb_client_write(delayed->ns->client, &delayed->response, sizeof(delayed->response));
    else
        hb_write(delayed->sock, &(delayed->response), sizeof(delayed->response));

    return delayed_action_cleanup(delayed->ns, voting_scp ? voting_scp : (expired_scp ? expired_scp : delayed->scp),
                                  delayed, delayed->event_type, delayed->notification_type, expired_scp, timeout, need_queue);
    }

void handle_vote(heartbeat_delayed_message_t *delayed, 
                 hb_server_client_t          *voting_scp,
                 heartbeat_event_vote_t       vote,
                 char                        *err_msg)
    {
    heartbeat_event_vote_t old_vote;
    heartbeat_event_vote_t new_vote;
    int old_outstanding;
    int rc;

retry:
    old_vote = delayed->vote;
    new_vote = old_vote;
    old_outstanding = delayed->outstanding;

    PRINT_INFO("vote %d (%s), msg '%s'\n", vote, hb_get_vote_name(vote), err_msg);

    switch(delayed->notification_type)
        {
        case hbnt_revocable:
            switch(vote)
                {
                case hbev_accept:
                    if ((new_vote == hbev_waiting) && (old_outstanding <= 1))
                        new_vote = hbev_accept;
                    break;
                case hbev_reject:
                    new_vote = hbev_reject;
                    break;
                case hbev_proxy_error:
                case hbev_not_found_error:
                case hbev_busy_error:
                case hbev_timeout_error:
                case hbev_script_error:
                    PRINT_ERR("shutdown voting error, vote %d (%s), promoting to (accept)\n", vote, hb_get_vote_name(vote));
                    if ((new_vote == hbev_waiting) && (old_outstanding <= 1))
                        new_vote = hbev_accept;
                    break;
                case hbev_complete:
                case hbev_waiting:
                default:
                    PRINT_ERR("unexpected shutdown vote %d (%s), prompting to (accept)\n", vote, hb_get_vote_name(vote));
                    if ((new_vote == hbev_waiting) && (old_outstanding <= 1))
                        new_vote = hbev_accept;
                    break;
                }
            break;

        case hbnt_irrevocable:
            switch(vote)
                {
                case hbev_complete:
                    if ((new_vote == hbev_waiting) && (old_outstanding <= 1))
                        new_vote = hbev_complete;
                    break;
                case hbev_proxy_error:
                case hbev_not_found_error:
                case hbev_busy_error:
                case hbev_timeout_error:
                case hbev_script_error:
                    PRINT_INFO("recieved shutdown vote %d (%s), promoting to (complete)\n", vote, hb_get_vote_name(vote));
                    if ((new_vote == hbev_waiting) && (old_outstanding <= 1))
                        new_vote = hbev_complete;
                    break;
                case hbev_waiting:
                case hbev_accept:
                case hbev_reject:
                default:
                    PRINT_ERR("unexpected shutdown vote %d (%s), promoting to (complete)\n", vote, hb_get_vote_name(vote));
                    if ((new_vote == hbev_waiting) && (old_outstanding <= 1))
                        new_vote = hbev_complete;
                    break;
                }
            break;

        case hbnt_unknown:
        default:
            PRINT_ERR("unexpected shutdown type %d (%s)\n", delayed->notification_type, hb_get_notification_name(delayed->notification_type));
            break;
        }


    rc = atomic_test_and_set_if_eq(&(delayed->vote), old_vote, new_vote);
    if (rc == 0)
        goto retry;

    if (((old_vote == hbev_waiting) || (old_vote == hbev_complete) || (old_vote == hbev_accept)) &&
        ((new_vote != hbev_waiting) && (new_vote != hbev_complete) && (new_vote != hbev_accept)) &&
        (delayed->response.body.shutdown_response_body.err_msg[0] == '\0'))
        {
        strncpy(delayed->response.body.shutdown_response_body.err_msg,
                err_msg,
                sizeof(delayed->response.body.shutdown_response_body.err_msg));
        }

    PRINT_INFO("Vote recieved from %s: notification_type %d (%s), outstanding %d, vote %d (%s), old vote %d (%s) -> aggregate vote %d (%s): msg '%s'\n",
               voting_scp ? voting_scp->name : "???",
               delayed->notification_type, hb_get_notification_name(delayed->notification_type), (int)delayed->outstanding,
               vote, hb_get_vote_name(vote), 
               old_vote, hb_get_vote_name(old_vote),
               new_vote, hb_get_vote_name(new_vote),
               delayed->response.body.shutdown_response_body.err_msg);

    /* Might be tempting to send a reject early here, but a new vote request might come in while there are still outstanding votes on the previous request and things get blocked or confused */

    decrement_outstanding_votes(delayed, voting_scp, NULL, false, true);
    }

void handle_shutdown_response(ns_data_t           *ns,
                              heartbeat_message_t *message,
                              hb_server_client_t  *scp)
    {
    heartbeat_event_vote_t vote;
    heartbeat_event_vote_t old_vote;
    heartbeat_delayed_message_t *delayed = NULL;

    PRINT_DEBUG("handle_shutdown_response server_client=%p, ns=%p\n", scp, ns); 
    if (scp && scp->delayed_response)
        {
        delayed = scp->delayed_response;
        PRINT_DEBUG("from server_client=%p (%s), delayed=%p\n", scp, scp->name, delayed); 
        }

    if (!delayed && ns && ns->delayed_response)
        {
        delayed = ns->delayed_response;
        PRINT_DEBUG("from ns=%p (%s), delayed=%p\n", ns, ns->ns_name, delayed); 
        }

    if (!delayed)
        {
        PRINT_ERR("Don't know how to route shutdown_response\n");
        return;
        }

    vote = ntohs(message->body.shutdown_response_body.event_vote);

    if (!delayed->for_me)
        {
        old_vote = delayed->vote;
        PRINT_INFO("not for me: vote=%d (%s), old_vote=%d (%s); msg='%s'\n",
                   vote, hb_get_vote_name(vote),
                   old_vote, hb_get_vote_name(old_vote),
                   message->body.shutdown_response_body.err_msg);
        delayed->vote = vote;
        delayed->response.body.shutdown_response_body.event_vote = htons(vote);
        if (((old_vote == hbev_waiting) || (old_vote == hbev_complete) || (old_vote == hbev_accept)) &&
            ((vote != hbev_waiting) && (vote != hbev_complete) && (vote != hbev_accept)) &&
            (delayed->response.body.shutdown_response_body.err_msg[0] == '\0'))
            {
            strncpy(delayed->response.body.shutdown_response_body.err_msg, 
                    message->body.shutdown_response_body.err_msg,
                    sizeof(delayed->response.body.shutdown_response_body.err_msg));
            }
        decrement_outstanding_votes(delayed, scp, NULL, false, true);
        }
    else
        {
        handle_vote(delayed, scp, vote, message->body.shutdown_response_body.err_msg);
        }

    if (scp && scp->delayed_response == delayed)
        {
        scp->delayed_response = NULL;
        PRINT_DEBUG("set delayed NULL for server_client=%p\n", scp); 
        }
    }


typedef struct
    {
    heartbeat_delayed_message_t *delayed;
    hb_server_client_t          *scp;
    } event_handler_func_data_t;

void* event_handler_func_wrapper(void *arg)
    {
    event_handler_func_data_t   *data = (event_handler_func_data_t*)arg;
    heartbeat_delayed_message_t *delayed = data->delayed;
    hb_server_client_t          *scp = data->scp;
    heartbeat_event_vote_t       vote = hbev_waiting;
    char err_msg[HB_LOG_MSG_SIZE];

    free(data);
    memset(err_msg, 0, sizeof(err_msg));
    delayed->pid = 0;
    vote = delayed->vote_func(delayed->event_type, delayed->notification_type, delayed->arg, err_msg, sizeof(err_msg), &(delayed->pid));
    delayed->pid = 0;
    handle_vote(delayed, scp, vote, err_msg);
    return NULL;
    }



void handle_shutdown_request_proxied(ns_data_t           *ns,
                                     heartbeat_message_t *message,
                                     hb_server_client_t  *scp,
                                     hb_client_t         *client,
                                     int                  reply_sock)
    {
    int                          id_match = 0;
    int                          response_ready = 0;
    heartbeat_event_vote_t       vote;
    heartbeat_message_t          message2;
    heartbeat_message_t          response;
    heartbeat_delayed_message_t *delayed;
    hb_server_t                 *server;
    hb_server_client_t          *voting_scp;
    long secs;
    long nsecs;

    int                          i;
    heartbeat_event_t            event_type;
    heartbeat_notification_t     notification_type;

    PRINT_INFO("ns = %p (%s), scp = %p (%s), client = %p (%s)\n",
               ns, ns ? ns->ns_name : "",
               scp, scp ? scp->name : "",
               client, client ? client->name : "");

    server = &(ns->server);
    if (!client)
        client = ns->client;

    event_type = ntohs(message->body.shutdown_request_body.event_type);
    notification_type = ntohs(message->body.shutdown_request_body.notification_type);
    PRINT_INFO("Recieved event_type %d (%s), notification_type %d (%s) for '%s'\n", 
               event_type, hb_get_event_name(event_type),
               notification_type, hb_get_notification_name(notification_type),
               message->body.shutdown_request_body.instance_id);

    vote = hbev_accept;
    if (scp && (HB_GET_SCP_FD(scp) == reply_sock))
        init_server_client_response(&response, scp, hbm_shutdown_response);
    else
        init_response_header(&response, message, ns->client, hbm_shutdown_response);
    response.body.shutdown_response_body.event_vote = htons((uint16_t)vote);
    response.body.shutdown_response_body.heartbeat_response  = htonl(0);
    response.body.shutdown_response_body.proxy_heartbeat_response = message->body.shutdown_request_body.proxy_heartbeat_response;
    response.body.shutdown_response_body.event_type = message->body.shutdown_request_body.event_type;
    response.body.shutdown_response_body.notification_type = message->body.shutdown_request_body.notification_type;
    memset(&(response.body.shutdown_response_body.err_msg[0]), 0, sizeof(response.body.shutdown_response_body.err_msg));

    if (client)
        {
        PRINT_INFO("setting id_match msg for %d '%s', instance_id='%s' instance_name='%s' name='%s'\n", 
                   ntohs(message->body.shutdown_request_body.inst_id_type),
                   message->body.shutdown_request_body.instance_id,
                   client->instance_id, client->instance_name, client->name);
        switch(ntohs(message->body.shutdown_request_body.inst_id_type))
            {
            case hii_inst_id:
                id_match = (0 == strcmp(message->body.shutdown_request_body.instance_id, client->instance_id));
                break;
            case hii_inst_name:
                id_match = (0 == strcmp(message->body.shutdown_request_body.instance_id, client->instance_name));
                break;
            case hii_name:
                id_match = (0 == strcmp(message->body.shutdown_request_body.instance_id, client->name));
                break;
            default:
                PRINT_ERR("Unknown inst_id_type %d", ntohs(message->body.shutdown_request_body.inst_id_type));
                break;
            }
        }
    else
        id_match = 0;

    PRINT_INFO("for instance_id '%s', vm_hostname '%s', network_hostname '%s'\n", 
               message->body.shutdown_request_body.instance_id,
               message->body.shutdown_request_body.vm_hostname,
               message->body.shutdown_request_body.network_hostname);
    PRINT_INFO("at hb_hostname=%s, ns_name=%s, client_name=%s, client_id=%s\n",
               hb_hostname,
               ns->ns_name, 
               client ? client->name : "n/a", client ? client->instance_id : "n/a");


    PRINT_INFO("id_match=%d\n", id_match);
    if (id_match)
        {
        /* For me */
        PRINT_INFO("for me!\n");

        int count = 0;

        delayed = (heartbeat_delayed_message_t*)malloc(sizeof(heartbeat_delayed_message_t));
        PRINT_DEBUG("malloc delayed %p\n", delayed);
        memset(delayed, 0, sizeof(*delayed));
        delayed->sock = reply_sock;
        delayed->outstanding = HB_MAX_CLIENTS+1;
        delayed->vote = hbev_waiting;
        delayed->notification_type = ntohs(message->body.shutdown_request_body.notification_type);
        delayed->event_type = ntohs(message->body.shutdown_request_body.event_type);
        delayed->ns = ns;
        delayed->scp = scp;
        delayed->reply_scp = scp;
        delayed->for_me = 1;
        delayed->for_my_client = 0;
        delayed->need_client_state_cleanup = 0;
        memcpy(&(delayed->response), &response, sizeof(delayed->response));
        client->delayed_response = delayed;
        PRINT_DEBUG("set delayed=%p for client=%p (%s)\n", delayed, client, client->name); 

        PRINT_INFO("run script %p,%p, client = %p (%s), vote = %d\n", 
                   client ? client->event_handler_func : NULL,
                   client ? client->proxied_event_handler_func : NULL,
                   client, client ? client->name : "???", vote);
        if (client->proxied_event_handler_func)
            {
            pthread_attr_t attr;
            event_handler_func_data_t *data;

            data = (event_handler_func_data_t*)malloc(sizeof(event_handler_func_data_t));
            data->delayed = delayed;
            data->scp = scp;
            PRINT_DEBUG("data = %p, delayed = %p, scp = %p\n", data, delayed, scp);

            pthread_attr_init(&attr);
            pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
            delayed->vote_func = client->proxied_event_handler_func;
            delayed->arg = client->event_handler_arg;
            delayed->need_client_state_cleanup = 1;
            pthread_create(&(delayed->thread), &attr, event_handler_func_wrapper, data);
            pthread_attr_destroy(&attr);
            /* TODO  pthread_cleanup_push()? */
            count++;

            hb_set_expire_func_client(client, expired_waiting_shutdown_script);
            secs = ntohl(message->body.shutdown_request_body.timeout_secs);
            nsecs = ntohl(message->body.shutdown_request_body.timeout_nsecs);
            hb_fix_shutdown_to(NULL, client, 
                               ntohs(message->body.shutdown_request_body.event_type), 
                               ntohs(message->body.shutdown_request_body.notification_type), 
                               &secs, &nsecs);
            hb_set_first_timeout_client(client, secs, nsecs);
            hb_requeue_first_ns_client(client->ns, client);
            }
        else
            {
            decrement_outstanding_votes(delayed, NULL, NULL, false, true);
            }

        for(i=0; i<HB_MAX_CLIENTS; i++)
            {
            voting_scp = server->connections[i];
            if (voting_scp && (voting_scp->client_role == hbr_vm_interface) && (delayed->vote = hbev_waiting))
                {
                if (voting_scp->delayed_response)
                    {
                    PRINT_ERR("'%s' is Busy, can't handle shutdown_request at this time\n", voting_scp->name);
                    switch(delayed->notification_type)
                        {
                        case hbnt_revocable:
                            delayed->vote = hbev_reject;
                            snprintf(delayed->response.body.shutdown_response_body.err_msg, 
                                     sizeof(delayed->response.body.shutdown_response_body.err_msg),
                                     "Heartbeat server is busy and can't handle a '%s' request at this time", 
                                     hb_get_event_name(event_type));
                            response_ready = 1;
                            break;
                        default:
                            break;
                        }

                    decrement_outstanding_votes(delayed, NULL, NULL, false, true);
                    continue;
                    }

                voting_scp->delayed_response = delayed;
                PRINT_DEBUG("set delayed=%p for server_client=%p (%s)\n", delayed, voting_scp, voting_scp->name); 

                memcpy(&message2, message, sizeof(message2));
                init_server_client_message(&message2, voting_scp, hbm_shutdown_request);

                message2.body.shutdown_request_body.inst_id_type = htons(hii_inst_id);
                strncpy(message2.body.shutdown_request_body.instance_id, voting_scp->instance_id, sizeof(message2.body.shutdown_request_body.instance_id));
                PRINT_DEBUG("set mesg instance_id %d %s", ntohs(message2.body.shutdown_request_body.inst_id_type), message2.body.shutdown_request_body.instance_id);
                PRINT_DEBUG("set mesg heartbeat_id %d", ntohl(message2.header.heartbeat_id));

                secs = ntohl(message2.body.shutdown_request_body.timeout_secs);
                nsecs = ntohl(message2.body.shutdown_request_body.timeout_nsecs);
                hb_fix_shutdown_to(voting_scp, NULL, 
                                   ntohs(message2.body.shutdown_request_body.event_type), 
                                   ntohs(message2.body.shutdown_request_body.notification_type), 
                                   &secs, &nsecs);
                hb_set_first_timeout_scp(voting_scp, secs, nsecs);
                PRINT_DEBUG("alarm_set_first_timeout %p, %ld.%09ld", &(voting_scp->alarm), secs, nsecs);

                if ((voting_scp->state != hbs_server_nova_paused) && (voting_scp->state != hbs_server_migrating))
                    {
                    voting_scp->save_state = voting_scp->state;
                    PRINT_DEBUG("saving state %d (%s)\n", voting_scp->state, hb_get_state_name(voting_scp->state));
                    }

                voting_scp->state = hbs_client_waiting_shutdown_response;
                hb_set_expire_func_scp(voting_scp, expired_waiting_shutdown_response);
                hb_requeue_first_ns_scp(ns, voting_scp);

                hb_sc_write(voting_scp, &message2, sizeof(message2));
                count++;
                }
            else
                {
                decrement_outstanding_votes(delayed, NULL, NULL, false, true);
                }
            }

        if (count == 0)
            {
            PRINT_INFO("No voters!\n");
            }
        }
    else
        {
        PRINT_INFO("for unknown, hb_role=%s\n", hb_get_role_name(hb_role));
        switch(hb_role)
            {
            case hbr_control:
                response_ready = handle_shutdown_request_proxied_control(ns, message, scp, reply_sock, &response);
                if (response_ready)
                    vote = ntohs(response.body.shutdown_response_body.event_vote);
                break;

            case hbr_compute:
                response_ready = handle_shutdown_request_proxied_compute(ns, message, scp, reply_sock, &response);
                if (response_ready)
                    vote = ntohs(response.body.shutdown_response_body.event_vote);
                break;

            default:
                PRINT_ERR("unsure how to route message for '%s' from '%s'\n", message->body.shutdown_request_body.instance_id, hb_get_role_name(hb_role));
                vote = hbev_not_found_error;
                snprintf(response.body.shutdown_response_body.err_msg, 
                         sizeof(response.body.shutdown_response_body.err_msg),
                         "Heartbeat server couldn't locate recipient '%s'", 
                         message->body.shutdown_request_body.instance_id);
                response_ready = 1;
                break;

            }
        }

    if (response_ready)
        {
        PRINT_INFO("voting response ready: vote = %d (%s)\n", vote, hb_get_vote_name(vote));
        response.body.shutdown_response_body.event_vote = htons((uint16_t)vote);

        if (scp && (reply_sock == HB_GET_SCP_FD(scp)))
            hb_sc_write(scp, &response, sizeof(response));
        if (client && (reply_sock == HB_GET_CLIENT_FD(client)))
            hb_client_write(client, &response, sizeof(response));
        else
            hb_write(reply_sock, &response, sizeof(response));
        }
    }


typedef struct
    {
    ns_data_t           *ns;
    heartbeat_message_t  message;
    hb_server_client_t  *scp;
    hb_client_t         *client;
    int                  reply_sock;
    } handle_shutdown_request_data_t;

void* handle_shutdown_request_helper(void *arg)
    {
    handle_shutdown_request_data_t *data = arg;
    
    handle_shutdown_request_proxied(data->ns,
                                    &(data->message),
                                    data->scp,
                                    data->client,
                                    data->reply_sock);
    PRINT_DEBUG("free %p\n", data);
    free(data);
    return NULL;
    }

void handle_shutdown_request(ns_data_t           *ns,
                             heartbeat_message_t *message,
                             hb_server_client_t  *scp,
                             hb_client_t         *client,
                             int                  reply_sock)
    {
    handle_shutdown_request_data_t *data;
    pthread_attr_t attr;
    pthread_t thread;
    int rc;

    PRINT_INFO("ns = %s, server_client = %s\n", ns ? ns->ns_name : "???", scp ? scp->name : "???");

    data = (handle_shutdown_request_data_t*)malloc(sizeof(handle_shutdown_request_data_t));
    PRINT_DEBUG("malloc %p\n", data);

    if (!data)
        {
        PRINT_ERR("Failed to shutdown %s, malloc: %s\n", message->body.shutdown_request_body.instance_id, strerror(errno));
        }

    // Buy time to perform nova lookups to route the shutdown request
    // hb_set_expire_func_scp(scp, expired_waiting_resume);
    if (scp)
        {
        hb_set_first_timeout_scp(scp, HB_LOOKUP_DELAY, 0);
        hb_requeue_first_ns_scp(ns, scp);
        }

    data->ns = ns;
    data->scp = scp;
    data->client = client;
    memcpy(&(data->message), message, sizeof(heartbeat_message_t));
    data->reply_sock = reply_sock;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    rc = pthread_create(&thread, &attr, handle_shutdown_request_helper, data);
    if (rc < 0)
        {
        PRINT_ERR("Failed to shutdown %s: pthread_create: %s\n", message->body.shutdown_request_body.instance_id, strerror(errno));
        PRINT_DEBUG("free %p\n", data);
        free(data);
        }

    pthread_attr_destroy(&attr);
    }

