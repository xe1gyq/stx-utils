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
#include "heartbeat.h"
#include "network_namespace.h"
#include "heartbeat_virtio_common.h"
#include "heartbeat_poll.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <resolv.h>
#include <time.h>
#include <stdarg.h>
#include <stdbool.h>
#include <signal.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <netinet/tcp.h>
#include <sys/stat.h>


/* #define HEALTH_FILE_ONLY 1 */

int hb_debug_message = 0;
int hb_debug_debug = 0;
int hb_debug_info = 1;

int                 allow_reconnect=1;

char hb_hostname[HB_INSTANCE_ID_SIZE];

const char* corrective_action_names[] =
    {
    "log",
    "script",
    "reboot",
    "stop",
    "delete",
    "restart",
    "signal",
    "set_vm_health"
    };

const char* event_names[] =
    {
    "unknown",
    "stop",
    "reboot",
    "suspend",
    "pause",
    "unpause",
    "resume",
    "live_migrate_begin",
    "live_migrate_end",
    "cold_migrate_begin",
    "cold_migrate_end",
    "downscale",
    };

const char* notification_names[] =
    {
    "unknown",
    "revocable",
    "irrevocable",
    };

const char* role_names[] =
    {
    "unknown",
    "control_interface",
    "control",
    "compute",
    "vm",
    "vm_interface",
    };

const char* state_names[] =
    {
    "invalid",
    "server_waiting_init",
    "server_waiting_challenge",
    "server_waiting_response",
    "server_paused",
    "server_nova_paused",
    "server_migrating",
    "server_corrective_action",
    "client_waiting_init_ack",
    "client_waiting_challenge",
    "client_waiting_pause_ack",
    "client_waiting_resume_ack",
    "client_paused",
    "client_waiting_shutdown_ack",
    "client_waiting_shutdown_response",
    "client_shutdown_response_recieved",
    "client_exiting",
    };

const char* message_type_names[] =
    {
    "init",
    "init_ack",
    "init_fail",
    "exit",
    "challenge",
    "response",
    "pause",
    "pause_ack",
    "resume",
    "resume_ack",
    "child_error",
    "shutdown_request", 
    "shutdown_response",
    "network_namespace",
    "nova_cmd",
    "hbm_server_exit", 
    "hbm_ping",
    "hbm_timeouts",
    };

const char* vote_names[] =
    {
    "accept",
    "reject",
    "complete",
    "proxy_error",
    "not_found_error",
    "busy_error",
    "timeout_error",
    "script_error",
    "waiting",
    };


hb_role_t hb_role = hbr_unknown;

void (*libheartbeat_exit_fptr)(int         status, 
                               const char* log) = NULL;

void (*handle_network_namespace_event_fptr)(ns_data_t           *ns,      
                                            heartbeat_message_t *message) = NULL;

void (*handle_shutdown_response_fptr)(ns_data_t           *ns,
                                      heartbeat_message_t *message,
                                      hb_server_client_t  *p) = NULL;

void (*handle_shutdown_request_fptr)(ns_data_t           *ns,
                                     heartbeat_message_t *message,
                                     hb_server_client_t  *scp,
                                     hb_client_t         *client,
                                     int                  reply_sock) = NULL;



void bind_handle_network_namespace_event_fptr(void (*f)(ns_data_t           *ns,
                                                        heartbeat_message_t *message));

void bind_handle_shutdown_response_fptr(void (*f)(ns_data_t           *ns,
                                                  heartbeat_message_t *message,
                                                  hb_server_client_t  *p));

void bind_handle_shutdown_request_fptr(void (*f)(ns_data_t           *ns,
                                                 heartbeat_message_t *message,
                                                 hb_server_client_t  *scp,
                                                 hb_client_t         *client,
                                                 int                  reply_sock));

void default_handle_shutdown_request(ns_data_t           *ns,
                                     heartbeat_message_t *message,
                                     hb_server_client_t  *scp,
                                     hb_client_t         *client,
                                     int                  reply_sock);

void default_handle_shutdown_response(ns_data_t           *ns,
                                      heartbeat_message_t *message,
                                      hb_server_client_t  *p);

void default_handle_network_namespace_event(ns_data_t           *ns,
                                            heartbeat_message_t *message);


heartbeat_corrective_action_t corrective_action_str_to_idx(const char* name);

const char* hb_get_corrective_action_name(heartbeat_corrective_action_t a);
const char* hb_get_message_type_name(heartbeat_message_type_t m);
const char* hb_get_role_name(hb_role_t r);
const char* hb_get_state_name(hb_state_t s);

heartbeat_notification_t notification_str_to_idx(const char* name);

const char* hb_get_notification_name(heartbeat_notification_t notification_type);

heartbeat_event_t shutdown_str_to_idx(const char* name);

const char* hb_get_event_name(heartbeat_event_t event_type);

uint32_t compute_response(heartbeat_algorithm_t algorithm, 
                          uint32_t              secret,
                          uint32_t              challenge);

void init_response_header(heartbeat_message_t      *response,
                          heartbeat_message_t      *respond_to,
                          hb_client_t              *p,
                          heartbeat_message_type_t  mtype);

void init_message_header(heartbeat_message_t      *message,
                         hb_client_t              *p,
                         heartbeat_message_type_t  mtype);


int init_client(hb_client_t *client, int background_connect);

int validate_client_response(hb_client_t              *client,
                             heartbeat_message_t      *m,
                             heartbeat_message_type_t  mtype);

int client_reconnect(hb_client_t *client, int timeout);

void client_disconnect(hb_client_t *client, int send_exit_msg, const char* log);

int client_connect(hb_client_t *client);

void default_handle_shutdown_request(ns_data_t           *ns,
                                     heartbeat_message_t *message,
                                     hb_server_client_t  *scp,
                                     hb_client_t         *client,
                                     int                  reply_sock);

int client_connect_retry(hb_client_t *client, int timeout);

int expired_waiting_client_activity(alarm_t* p);



__attribute__((constructor))
static
void hb_common_init()
    {
    int rc;

    bind_handle_shutdown_request_fptr(default_handle_shutdown_request);
    bind_handle_shutdown_response_fptr(default_handle_shutdown_response);
    bind_handle_network_namespace_event_fptr(default_handle_network_namespace_event);

    rc = gethostname(hb_hostname, sizeof(hb_hostname));
    if (rc < 0)
        {
        PRINT_ERR("gethostname: %s\n", strerror(errno));
        hb_hostname[0] = '\0';
        }
    }


void hb_ac_enqueue_alarm(alarm_clock_t *alarm_clock_p,
                         alarm_t       *p,
                         const char    *ac_name,
                         const char    *a_name)
    {
    PRINT_DEBUG("ALARM: enqueue %p (%s) on %p (%s)\n", p, a_name, alarm_clock_p, ac_name);
    ac_enqueue_alarm(alarm_clock_p, p);
    }

void hb_ac_enqueue_first_alarm(alarm_clock_t *alarm_clock_p,
                               alarm_t       *p,
                               const char    *ac_name,
                               const char    *a_name)
    {
    PRINT_DEBUG("ALARM: enqueue %p (%s) on %p (%s)\n", p, a_name, alarm_clock_p, ac_name);
    ac_enqueue_first_alarm(alarm_clock_p, p);
    }

void hb_ac_requeue_alarm(alarm_clock_t *alarm_clock_p,
                         alarm_t       *p,
                         const char    *ac_name,
                         const char    *a_name)
    {
    PRINT_DEBUG("ALARM: enqueue %p (%s) on %p (%s)\n", p, a_name, alarm_clock_p, ac_name);
    ac_requeue_alarm(alarm_clock_p, p);
    }

void hb_ac_requeue_first_alarm(alarm_clock_t *alarm_clock_p,
                               alarm_t       *p,
                               const char    *ac_name,
                               const char    *a_name)
    {
    PRINT_DEBUG("ALARM: enqueue %p (%s) on %p (%s)\n", p, a_name, alarm_clock_p, ac_name);
    ac_requeue_first_alarm(alarm_clock_p, p);
    }

alarm_t* hb_ac_dequeue_alarm(alarm_t    *target,
                             const char *a_name)
    {
    PRINT_DEBUG("ALARM: dequeue %p (%s) \n", target, a_name);
    return(ac_dequeue_alarm(target));
    }

void hb_alarm_set_expire_func(alarm_t    *p,
                              int       (*expire_func)(alarm_t*),
                              const char *a_name,
                              const char *f_name)
    {
    PRINT_DEBUG("ALARM: set_expire_func %p (%s) for alarm %p (%s)\n", expire_func, f_name, p, a_name);
    alarm_set_expire_func(p, expire_func);
    }

void hb_alarm_set_first_timeout(alarm_t    *p,
                                long        secs,
                                long        nsecs,
                                const char *a_name)
    {
    PRINT_DEBUG("ALARM: set_first_timeout %p (%s) %ld.%09ld\n", p, a_name, secs, nsecs);
    alarm_set_first_timeout(p, secs, nsecs);
    }

void hb_alarm_set_interval(alarm_t    *p,
                           long        secs,
                           long        nsecs,
                           const char *a_name)
    {
    PRINT_DEBUG("ALARM: set_interval %p (%s) %ld.%09ld\n", p, a_name, secs, nsecs);
    alarm_set_interval(p, secs, nsecs);
    }

void hb_requeue_first_ns_client(ns_data_t   *ns,
                                hb_client_t *client)
    {
    hb_ac_requeue_first_alarm(&(ns->alarm_clock), &(client->alarm), ns->ns_name, client->name);
    }

void hb_requeue_first_ns_scp(ns_data_t          *ns,
                             hb_server_client_t *scp)
    {
    hb_ac_requeue_first_alarm(&(ns->alarm_clock), &(scp->alarm), ns->ns_name, scp->name);
    }

void hb_enqueue_first_ns_client(ns_data_t   *ns,
                                hb_client_t *client)
    {
    hb_ac_enqueue_first_alarm(&(ns->alarm_clock), &(client->alarm), ns->ns_name, client->name);
    }

void hb_enqueue_first_ns_scp(ns_data_t          *ns,
                             hb_server_client_t *scp)
    {
    hb_ac_enqueue_first_alarm(&(ns->alarm_clock), &(scp->alarm), ns->ns_name, scp->name);
    }

void hb_requeue_ns_client(ns_data_t   *ns,
                          hb_client_t *client)
    {
    hb_ac_requeue_alarm(&(ns->alarm_clock), &(client->alarm), ns->ns_name, client->name);
    }

void hb_requeue_ns_scp(ns_data_t          *ns,
                       hb_server_client_t *scp)
    {
    hb_ac_requeue_alarm(&(ns->alarm_clock), &(scp->alarm), ns->ns_name, scp->name);
    }

void hb_enqueue_ns_client(ns_data_t   *ns,
                          hb_client_t *client)
    {
    hb_ac_enqueue_alarm(&(ns->alarm_clock), &(client->alarm), ns->ns_name, client->name);
    }

void hb_enqueue_ns_scp(ns_data_t          *ns,
                       hb_server_client_t *scp)
    {
    hb_ac_enqueue_alarm(&(ns->alarm_clock), &(scp->alarm), ns->ns_name, scp->name);
    }

void hb_dequeue_client(hb_client_t *client)
    {
    hb_ac_dequeue_alarm(&(client->alarm), client->name);
    }

void hb_dequeue_scp(hb_server_client_t *scp)
    {
    hb_ac_dequeue_alarm(&(scp->alarm), scp->name);
    }

void hb_set_first_timeout_client(hb_client_t *client,
                                 long         secs,
                                 long         nsecs)
    {
    hb_alarm_set_first_timeout(&(client->alarm), secs, nsecs, client->name);
    }

void hb_set_first_timeout_scp(hb_server_client_t *scp,
                              long                secs,
                              long                nsecs)
    {
    hb_alarm_set_first_timeout(&(scp->alarm), secs, nsecs, scp->name);
    }

void hb_set_interval_scp(hb_server_client_t *scp,
                         long                secs,
                         long                nsecs)
    {
    hb_alarm_set_interval(&(scp->alarm), secs, nsecs, scp->name);
    }

void hb_set_expire_func_scp2(hb_server_client_t *scp,
                             int               (*expire_func)(alarm_t*),
                             const char         *f_name)
    {
    hb_alarm_set_expire_func(&(scp->alarm), expire_func, scp->name, f_name);
    }

void hb_set_expire_func_client2(hb_client_t *client,
                                int        (*expire_func)(alarm_t*),
                                const char  *f_name)
    {
    hb_alarm_set_expire_func(&(client->alarm), expire_func, client->name, f_name);
    }

bool hb_is_closed(int sock)
    {
    fd_set rfd;
    fd_set efd;
    int n = 0;
    struct timeval tv;
    int rc;
    char c;

    FD_ZERO(&rfd);
    FD_ZERO(&efd);
    FD_SET(sock, &rfd);
    FD_SET(sock, &efd);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    select(sock+1, &rfd, 0, &efd, &tv);
    if (FD_ISSET(sock, &efd))
       {
       rc = recv(sock, &c, 1, MSG_OOB);
       return (rc < 1);
       }
    if (!FD_ISSET(sock, &rfd))
       return false;
    ioctl(sock, FIONREAD, &n);
    return n == 0;
    }


void bind_heartbeat_exit_fptr(void (*f)(int, const char*))
    {
    libheartbeat_exit_fptr = f;
    }

void libheartbeat_exit(int status, const char* log)
    {
    if (libheartbeat_exit_fptr)
        libheartbeat_exit_fptr(status, log);
    else
        {
        PRINT_ERR("exiting, status %d, log '%s'\n", status, log);
        exit(status);
        }
    }

void hb_setnonblocking(int sock)
    {
    int opts;

    opts = fcntl(sock, F_GETFL);
    if (opts < 0)
        {
        PRINT_ERR("fcntl(%d, F_GETFL): %s\n", sock, strerror(errno));
        libheartbeat_exit(EXIT_FAILURE, __FUNCTION__);
        }

    opts = (opts | O_NONBLOCK);
    if (fcntl(sock, F_SETFL, opts) < 0)
        {
        PRINT_ERR("fcntl(%d, F_SETFL): %s\n", sock, strerror(errno));
        libheartbeat_exit(EXIT_FAILURE, __FUNCTION__);
        }

    return;
    }

int pipe_connect(ns_data_t *ns)
    {
    int rc;

    rc = pipe2(ns->pipe_fd, O_NONBLOCK | O_CLOEXEC);
    if (rc < 0)
        {
        PRINT_ERR("pipe2: %s\n", strerror(errno));
        return -1;
        }

    #ifdef HB_USE_SELECT
        if (ns->highsock < ns->pipe_fd[READ_PIPE])
            ns->highsock = ns->pipe_fd[READ_PIPE];

        FD_SET(ns->pipe_fd[READ_PIPE], &(ns->read_socks));
    #endif /* HB_USE_SELECT */
    #ifdef HB_USE_POLL
        hb_pollfd_add(&(ns->pollfd_data), ns->pipe_fd[READ_PIPE], hbft_ns_pipe, -1, ns);
    #endif /* HB_USE_POLL */

    PRINT_DEBUG("ns=%p (%s), read fd = %d, write fd = %d\n", ns, ns->ns_name, ns->pipe_fd[READ_PIPE], ns->pipe_fd[WRITE_PIPE]);
    return 0;
    }


void init_ns(ns_data_t *ns, hb_client_t *client)
    {
    int rc;
    struct timespec precision;

    #ifdef HB_USE_SELECT
        ns->highsock = 0;
        FD_ZERO(&(ns->read_socks));
        FD_ZERO(&(ns->ready_read_socks));
    #endif /* HB_USE_SELECT */
    #ifdef HB_USE_POLL
        hb_init_pollfd_data(&(ns->pollfd_data));
    #endif /* HB_USE_POLL */

    ns->client = client;

    precision.tv_sec = 0;
    precision.tv_nsec = 10000000;   /* 10 millisec */

    ac_init(&(ns->alarm_clock), NULL, precision);
    PRINT_DEBUG("init clock %p (%s)\n", &(ns->alarm_clock), ns->ns_name);

    rc = pipe_connect(ns);
    if (rc < 0)
        {
        PRINT_ERR("pipe_connect failed: rc = %d\n", rc);
        }
    }

ssize_t hb_read(int fd, heartbeat_message_t *message, size_t size)
    {
    ssize_t rc;

  retry:
    errno=0;
    rc = read(fd, message, size);
    if (rc < 0)
        {
        if (errno == EINTR)
            goto retry;
        PRINT_ERR("fd=%d, rc=%d, error=%s\n", fd, (int)rc, strerror(errno));
        return rc;
        }

    PRINT_MESSAGE("read: fd=%d, type=%s, seq=%d, rc=%d\n",
                  fd, hb_get_message_type_name(ntohs(message->header.mtype)),
                  ntohl(message->header.sequence), (int)rc);

    return rc;
    }



ssize_t hb_write(int fd, heartbeat_message_t *message, size_t size)
    {
    PRINT_MESSAGE("fd=%d, type=%s, seq=%d\n",
                  fd,
                  hb_get_message_type_name(ntohs(message->header.mtype)),
                  ntohl(message->header.sequence));
    return write(fd, message, size);
    }


ssize_t hb_client_read(hb_client_t *client, heartbeat_message_t *message, size_t size)
    {
    return hb_read(HB_GET_CLIENT_FD(client), message, size);
    }

ssize_t hb_client_write(hb_client_t *client, heartbeat_message_t *message, size_t size)
    {
    client->sequence++;
    message->header.sequence = htonl(client->sequence);
    return hb_write(HB_GET_CLIENT_FD(client), message, size);
    }

void bind_handle_network_namespace_event_fptr(void (*f)(ns_data_t           *ns,
                                                        heartbeat_message_t *message))
    {
    handle_network_namespace_event_fptr = f;
    }

void bind_handle_shutdown_response_fptr(void (*f)(ns_data_t           *ns,
                                                  heartbeat_message_t *message,
                                                  hb_server_client_t  *p))
    {
    handle_shutdown_response_fptr = f;
    }

void bind_handle_shutdown_request_fptr(void (*f)(ns_data_t           *ns,
                                                 heartbeat_message_t *message,
                                                 hb_server_client_t  *scp,
                                                 hb_client_t         *client,
                                                 int                  reply_sock))
    {
    handle_shutdown_request_fptr = f;
    }

heartbeat_corrective_action_t corrective_action_str_to_idx(const char* name)
    {
    int i;

    for(i=0; i<hbca_corrective_action_max; i++)
        {
        if (0==strcmp(corrective_action_names[i], name))
            return (heartbeat_corrective_action_t)i;
        }

    return HB_CORRECTIVE_ACTION_DEFAULT;
    }

const char* hb_get_corrective_action_name(heartbeat_corrective_action_t a)
    {
    if (a >= hbca_corrective_action_max)
        return "???";

    return corrective_action_names[a];
    }

const char* hb_get_message_type_name(heartbeat_message_type_t m)
    {
    if (m >= hbm_message_type_max)
        return "???";

    return message_type_names[m];
    }

const char* hb_get_role_name(hb_role_t r)
    {
    if (r >= hbr_role_max)
        return "???";

    return role_names[r];
    }

const char* hb_get_state_name(hb_state_t s)
    {
    if (s >= hbs_state_max)
        return "???";

    return state_names[s];
    }

const char* hb_get_vote_name(heartbeat_event_vote_t v)
    {
    if (v >=hbev_vote_max)
        return "???";

    return vote_names[v];
    }


heartbeat_notification_t notification_str_to_idx(const char* name)
    {
    int i;

    for(i=0; i<hbnt_max; i++)
        {
        if (0==strcmp(notification_names[i], name))
            return (heartbeat_notification_t)i;
        }

    return HBNT_DEFAULT;
    }

const char* hb_get_notification_name(heartbeat_notification_t notification_type)
    {
    if (notification_type >= hbnt_max)
        return "???";

    return notification_names[notification_type];
    }

heartbeat_event_t shutdown_str_to_idx(const char* name)
    {
    int i;

    for(i=0; i<hbet_max; i++)
        {
        if (0==strcmp(event_names[i], name))
            return (heartbeat_event_t)i;
        }

    return HBET_DEFAULT;
    }

const char* hb_get_event_name(heartbeat_event_t event_type)
    {
    if (event_type >= hbet_max)
        return "???";

    return event_names[event_type];
    }

uint32_t compute_response(heartbeat_algorithm_t algorithm, 
                          uint32_t              secret,
                          uint32_t              challenge)
    {
    uint32_t response = 0;

    switch(algorithm)
        {
        case hb_algorithm_xor:
            response = secret ^ challenge;
            break;
        default:
            PRINT_ERR("unsupported algorithm: %d\n", algorithm);
            break;
        }

    return response;
    }


void init_response_header(heartbeat_message_t      *response,
                          heartbeat_message_t      *respond_to,
                          hb_client_t              *client,
                          heartbeat_message_type_t  mtype)
    {
    heartbeat_message_header_t *h   = &(response->header);
    heartbeat_message_header_t *rth = &(respond_to->header);

    strncpy(h->magic, HB_MAGIC, sizeof(h->magic));
    h->version = (client ? htons(client->version) : rth->version);
    h->mtype = htons(mtype);
    h->sequence = htonl(client ? client->sequence : ntohl(rth->sequence)+1);
    h->heartbeat_id = htonl(client ? client->heartbeat_id : 0);
    h->size = htonl((uint32_t)sizeof(*response));
    }


void init_message_header(heartbeat_message_t      *message,
                         hb_client_t              *client,
                         heartbeat_message_type_t  mtype)
    {
    heartbeat_message_header_t *h = &(message->header);

    strncpy(h->magic, HB_MAGIC, sizeof(h->magic));
    h->version = htons(client->version);
    h->mtype = htons(mtype);
    h->sequence = htonl(client->sequence);
    h->heartbeat_id = htonl(client->heartbeat_id);
    h->size = htonl((uint32_t)sizeof(*message));
    }

/* 
 * init_client
 *
 *    client:             Structure to populate with connection data.
 *    background_connect: Attempt background connection if immediate
 *                        connection is not possible. 
 *
 *    Returns:  0 = connected now
 *              1 = thread will attempt connection in background.
 *                  SIGIO when ready.
 *             -1 = connection failed
 */
int init_client(hb_client_t *client, int background_connect)
    {
    int rc;

    ac_init_alarm(&(client->alarm),
                  client->first_hb.tv_sec + client->hb_interval.tv_sec + 1 + (client->first_hb.tv_nsec + client->hb_interval.tv_nsec)/1000000000,
                  2*client->hb_interval.tv_sec + 1 + (2*client->hb_interval.tv_nsec)/1000000000,
                  ALARM_CLOCK_FOREVER, expired_waiting_client_activity, AC_IS_CLIENT, client->ns);

    client->server_role = hbr_unknown;
    client->state = hbs_client_waiting_init_ack;
    client->version = HB_CURRENT_VERSION;
    client->sequence = rand();
    client->sock = -1;
    client->vio_fd = -1;
    client->delayed_response = NULL;

    rc = client_connect(client);
    if (rc == 0)
       return 0;

    if (background_connect)
        {
        rc = client_connect_retry(client, 1);
        if (rc == 0)
           return 1;
        }

    return -1;
    }

int validate_client_response(hb_client_t              *client,
                             heartbeat_message_t      *m,
                             heartbeat_message_type_t  mtype)
    {
    heartbeat_id_t heartbeat_id;
    char  instance_id[HB_INSTANCE_ID_SIZE];
    const char* who;
    uint32_t expected_sequence = 0;
    uint32_t sequence = 0;

    strncpy(instance_id, client->instance_id, sizeof(instance_id));
    who = hb_get_message_type_name(mtype);
    heartbeat_id = ntohl(m->header.heartbeat_id);

    expected_sequence = client->sequence+1;
    sequence = ntohl(m->header.sequence);


    switch (mtype)
        {
        case hbm_init_ack:
            strncpy(instance_id, m->body.init_ack_body.instance_id, sizeof(instance_id));
            heartbeat_id = client->heartbeat_id;
            break;
        case hbm_challenge:
        case hbm_pause_ack:
        case hbm_resume_ack:
        case hbm_shutdown_request:
        case hbm_shutdown_response:
        case hbm_network_namespace:
        case hbm_nova_cmd:
        case hbm_response:
        case hbm_pause:
        case hbm_resume:
            /* fall through */
            break;
        case hbm_init:
        case hbm_exit:
        case hbm_child_error:
        case hbm_server_exit:
        case hbm_ping:
        case hbm_timeouts:
        case hbm_init_fail:
            if (client)
                {
                client->sequence = sequence;
                PRINT_INFO("sequence = %d for '%s'\n", sequence, client->name);
                }
            return 0;
        default:
            PRINT_ERR("Unhandled message type %d\n", mtype);
            return -4;
        }

    if (strncmp(instance_id, client->instance_id, sizeof(client->instance_id)))
        {
        PRINT_ERR("TODO %s had invalid instance_id: %s\n", who, instance_id);
        return -1;
        }

    if (heartbeat_id != client->heartbeat_id)
        {
        PRINT_ERR("TODO %s had invalid heartbeat_id: %d vs %d\n", who, heartbeat_id, client->heartbeat_id);
        return -1;
        }

    if (expected_sequence != sequence)
        {
        if ((expected_sequence != (sequence+1)) && (expected_sequence != (sequence-1)))
            {
            PRINT_ERR("%s invalid sequence: %d vs expected %d\n", who, sequence, expected_sequence);
            return -2;
            }
        else
            {
            PRINT_INFO("%s: async message, allowing unexpected sequence: %d vs expected %d\n", who, sequence, expected_sequence);
            }
        }

    if (client)
        {
        client->sequence = sequence;
        PRINT_DEBUG("sequence = %d for '%s'\n", sequence, client->name);
        }

    return 0;
    }

#define CLIENT_CONNECT_MAX_TYRIES 100000
#define CLIENT_CONNECT_SLOW_DOWN 60

pid_t client_connect_signal_tid = 0;
pid_t client_connect_signal_sent = 0;
int client_connect_sig = SIGIO;
struct sigaction client_connect_oldsa;

int hb_get_signum()
    {
    return client_connect_sig;
    }

void* client_connect_retry_thread(void* arg)
    {
    hb_client_t *client = arg;
    int rc;
    int i;
    int interval = 1;
    int max_try = CLIENT_CONNECT_MAX_TYRIES;

    if (client->connect_timeout)
        sleep(client->connect_timeout);

    for(i=0; i<max_try; i++)
       {
       rc = client_connect(client);
       if (rc == 0)
           {
           if (client_connect_signal_tid)
               {
               /* Send signal to break main thread out of select().
                * The old select is using an old fd_set that doesn't include our new socket.
                * We would ignore the new socket, potentially for seconds, without this.
                *
                * TODO: what if signal interupts something other than our signal aware select?
                * Probably better to have a file descriptor to write to that is part of the select.
                */
               PRINT_DEBUG("send signal to %d\n", client_connect_signal_tid);
               client_connect_signal_sent = 1;
               rc = tkill(client_connect_signal_tid, client_connect_sig);
               }
           pthread_exit(NULL);
           return NULL;
           }

       /* Assuming CLIENT_CONNECT_SLOW_DOWN=60
        * Initially use 1 second retry interval for first 60 seconds, then slowly
        * increase interval till the retry interval is once per minute.
        */
       if ((i>CLIENT_CONNECT_SLOW_DOWN) && (interval < CLIENT_CONNECT_SLOW_DOWN))
          interval++;
       sleep(interval);
       }
    PRINT_ERR("exceeded max client connect retries %d\n", max_try);
    libheartbeat_exit(1, __FUNCTION__);
    pthread_exit(NULL);
    return NULL;
    }

void client_connect_signal_handler(int sig, siginfo_t *info, void *u)
    {
    if (client_connect_signal_sent)
        {
        client_connect_signal_sent = 0;
        client_connect_signal_tid = 0;
        sigaction(client_connect_sig, &client_connect_oldsa, NULL);
        return;
        }

    /* Not our signal, pass to previous handler */
    if ((client_connect_oldsa.sa_handler != SIG_DFL) &&
        (client_connect_oldsa.sa_handler != SIG_IGN))
        {
        if ((client_connect_oldsa.sa_flags & SA_SIGINFO) == SA_SIGINFO)
            {
            client_connect_oldsa.sa_sigaction(sig, info, u);
            }
         else
            {
            client_connect_oldsa.sa_handler(sig);
            }
        }
    }

int expired_waiting_client_activity(alarm_t* p)
    {
    hb_client_t *client;
    ns_data_t   *ns;
    int sock;
    int rc = ALARM_CLOCK_CONTINUE;
    int need_reconnect=0;
    #ifdef TRY_TO_KEEP_ALIVE
        int rc2;
        heartbeat_message_t message;
    #endif  /* TRY_TO_KEEP_ALIVE */

    ns = alarm_get_util_ptr(p);
    client = ns->client;
    PRINT_DEBUG("p = %p, client=%p, ns=%p (%s)\n", p, client, ns, ns->ns_name);

    sock = HB_GET_CLIENT_FD(client);
    if (sock >= 0)
        {
        PRINT_INFO("Possible loss of connectivity with server for '%s'\n", client->name);
        #ifdef TRY_TO_KEEP_ALIVE
            if (hb_is_closed(sock))
                {
                need_reconnect=1;
                }
            else
                {
                PRINT_INFO("send hbm_ping from '%s'\n", client->name);
                init_message_header(&message, client, hbm_ping);
                rc2 = hb_client_write(client, &message, sizeof(message));
                if (rc2 < 0)
                    {
                    PRINT_ERR("Write failed: (%s); attempting reconnect\n", strerror(errno));
                    need_reconnect=1;
                    }
                }
        #else
            need_reconnect=1;
        #endif  /* TRY_TO_KEEP_ALIVE */

        if (need_reconnect)
            {
            client_reconnect(client, 0);
            /* Don't allow alarm_clock to automatically requeue,  
             * Instead allow the async reconnection to do it. 
             */
            rc = ALARM_CLOCK_STOP;
            }
        }

    return rc;
    }

int client_connect_retry(hb_client_t *client, int timeout)
    {
    int rc;
    pthread_attr_t attr;
    pthread_t thread;
    struct sigaction sa;

    if (timeout == 0)
        {
        // Attempt immediate connection before launching thread.
        rc = client_connect(client);
        if (rc == 0)
            {
            return 0;
            }
        }

    client_connect_signal_tid = gettid();
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = client_connect_signal_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(client_connect_sig, &sa, &client_connect_oldsa);
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    client->connect_timeout = timeout;
    rc = pthread_create(&thread, &attr, client_connect_retry_thread, client);
    pthread_attr_destroy(&attr);
    if (rc < 0)
        {
        PRINT_ERR("pthread_create failed: %s\n", strerror(errno));
        libheartbeat_exit(1, __FUNCTION__);
        }
    return rc;
    }

int client_reconnect(hb_client_t *client, int timeout)
    {
    PRINT_INFO("client_reconnect allow_reconnect=%d\n", allow_reconnect);
    client_disconnect(client, false, NULL);
    if (!allow_reconnect)
        return HB_RC_MISC_ERR;
    return client_connect_retry(client, timeout);
    }

void client_disconnect(hb_client_t *client, int send_exit_msg, const char* log)
    {
    uint32_t resp;
    int sock = -1;
    heartbeat_message_t message;
    int rc;

    if (ac_alarm_on_queue(&(client->alarm)))
        hb_dequeue_client(client);

    sock = HB_GET_CLIENT_FD(client);

    if ((sock >= 0) && (send_exit_msg))
        {
        init_message_header(&message, client, hbm_exit);
        resp = compute_response(client->heartbeat_algorithm,
                                client->heartbeat_secret,
                                client->heartbeat_challenge);
        message.body.exit_body.heartbeat_response = htonl(resp);
        if (log)
            strncpy(message.body.exit_body.log_msg, log, sizeof(message.body.exit_body.log_msg));
        else
            message.body.exit_body.log_msg[0] = '\0';
        PRINT_MESSAGE("send hbm_exit '%s'\n", client->name);
        hb_client_write(client, &message, sizeof(message));
        }

    if (client->vio_fd >= 0)
        {
        PRINT_INFO("close client vio_fd=%d\n", client->vio_fd);
        #ifdef HB_USE_SELECT
            FD_CLR(client->vio_fd, &(client->ns->read_socks));
        #endif /* HB_USE_SELECT */
        #ifdef HB_USE_POLL
            hb_pollfd_remove_fd(&(client->ns->pollfd_data), client->vio_fd);
        #endif /* HB_USE_POLL */
        rc = close(client->vio_fd);
        if (rc < 0)
            PRINT_ERR("close failed, fd=%d, rc=%d: %s", client->vio_fd, rc, strerror(errno));
        client->vio_fd = -1;
        }

    if (client->sock >= 0)
        {
        PRINT_INFO("close client sock=%d\n", client->sock);
        #ifdef HB_USE_SELECT
            FD_CLR(client->sock, &(client->ns->read_socks));
        #endif /* HB_USE_SELECT */
        #ifdef HB_USE_POLL
            hb_pollfd_remove_fd(&(client->ns->pollfd_data), client->sock);
        #endif /* HB_USE_POLL */
        shutdown(client->sock, SHUT_WR);
        rc = close(client->sock);
        if (rc < 0)
            PRINT_ERR("close failed, fd=%d, rc=%d: %s", client->sock, rc, strerror(errno));
        client->sock = -1;
        }
    }


int get_dhcp_server_addr(hb_client_t *client)
    {
    char         buffer[1024];
    FILE        *file;
    char        *s;
    int          i=0;
    char         c;
    int          found = 0;

    file = popen("grep -a dhcp-server-identifier /var/lib/dhcp/dhclient.leases  | awk ' { print $3 } ' | awk -F ';' ' { print $1 }'", "r");
    if (!file)
        {
        return -1;
        }

    while ((s = fgets(buffer, sizeof(buffer), file)))
        {
        for(i=0;i<(int)sizeof(buffer);i++)
            {
            c = s[i];
            if ((c < '0' || c > '9') && (c != '.'))
                {
                s[i] = '\0';
                if (i < (int)sizeof(client->alt_remote_addr))
                    {
                    strncpy(client->alt_remote_addr, s, sizeof(client->alt_remote_addr));
                    found = 1;
                    }
                }
            }
        }

    if (found)
        return 0;
    return -1;
    }

int client_connect(hb_client_t *client)
    {
    int *p_int;
    int rc;
    heartbeat_message_t message;
    int save_errno;
    int use_alt = 0;
    int use_vio = (hb_role == hbr_vm);
    int sock = -1;
    hb_fd_type_t fd_type = hbft_unknown;

    client->sequence = rand();
    client->vio_fd = -1;
    client->sock = -1;

    if (use_vio)
        {
        rc = vio_client_init(client);
        PRINT_INFO("vio_client_init: rc = %d, fd = %d\n", rc, client->vio_fd);

        if ((rc < 0) || (client->vio_fd < 0))
           {
           // TODO: Uncomment this to allow fallback to a network socket
           //       When vio fails.  Network connection is not as well
           //       tested, and vio can be transient.
           // use_vio = 0;
           return -1;
           }
        else
           {
           sock = client->vio_fd;
           fd_type = hbft_client_vio;
           }
        }

    if (!use_vio)
        {
        client->sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (client->sock == -1)
            {
            PRINT_ERR("client socket: %s", strerror(errno));
            return -1;
            }

        sock = client->sock;
        fd_type = hbft_client;

        p_int = (int*)malloc(sizeof(int));
        *p_int = 1;

        if ((setsockopt(client->sock, SOL_SOCKET, SO_REUSEADDR, (char*)p_int, sizeof(int)) == -1 ) ||
            (setsockopt(client->sock, SOL_SOCKET, SO_KEEPALIVE, (char*)p_int, sizeof(int)) == -1 ))
            {
            PRINT_ERR("Error setting client options: %s", strerror(errno));
            free(p_int);
            close(client->sock);
            client->sock = -1;
            return -1;
            }


        client->address.sin_family = AF_INET ;
        client->address.sin_port = htons(client->port);
        memset(&(client->address.sin_zero), 0, 8);
        client->address.sin_addr.s_addr = inet_addr(client->remote_addr);
        PRINT_INFO("try connect: host = %s, addr = %s,%x, sock = %d, port = %d\n", client->remote_hostname, client->remote_addr, client->address.sin_addr.s_addr, client->sock, client->port);
        rc = connect(client->sock, (struct sockaddr*)&client->address, sizeof(client->address));
        if (rc == -1 )
            {
            if (errno != EINPROGRESS)
                {
                save_errno = errno;
                if (0==get_dhcp_server_addr(client))
                    {
                    use_alt = 1;
                    client->address.sin_addr.s_addr = inet_addr(client->alt_remote_addr);
                    PRINT_INFO("try connect: alt addr = %s,%x, sock = %d, port = %d\n", client->alt_remote_addr, client->address.sin_addr.s_addr, client->sock, client->port);
                    rc = connect(client->sock, (struct sockaddr*)&client->address, sizeof(client->address));
                    if (rc == -1 )
                        {
                        if (errno != EINPROGRESS)
                            {
                            PRINT_ERR("primary: %s; alternate: %s\n", strerror(save_errno), strerror(errno));
                            close(client->sock);
                            client->sock = -1;
                            free(p_int);
                            return -1;
                            }
                        }
                    }
                }
            }

        int idle = 3;
        int cnt = 2;
        int intvl = 2;

        if ((setsockopt(client->sock, IPPROTO_TCP, TCP_KEEPIDLE, (char*)&idle, sizeof(int)) == -1 ) ||
            (setsockopt(client->sock, IPPROTO_TCP, TCP_KEEPCNT, (char*)&cnt, sizeof(int)) == -1 ) ||
            (setsockopt(client->sock, IPPROTO_TCP, TCP_KEEPINTVL, (char*)&intvl, sizeof(int)) == -1 ))
            {
            PRINT_ERR("Error setting client options for keepalive times: %s", strerror(errno));
            free(p_int);
            close(client->sock);
            client->sock = -1;
            return -1;
            }
    
        free(p_int);
        }

    #ifdef HB_USE_SELECT
        if (client->ns->highsock < sock)
            client->ns->highsock = sock;

        FD_SET(sock, &(client->ns->read_socks));
    #endif /* HB_USE_SELECT */
    #ifdef HB_USE_POLL
        hb_pollfd_add(&(client->ns->pollfd_data),
                      sock,
                      fd_type,
                      -1,
                      client);

    #endif /* HB_USE_POLL */

    PRINT_INFO("Connected to HB server at %s from: client = %p (%s), ns = %p (%s), sock = %d, vio_fd = %d\n", 
               (client->sock>=0 ? (use_alt ? client->alt_remote_addr : client->remote_addr)
                                : (client->vio_fd>=0 ? "virt_io" : "???")),
               client, client->name,
               client->ns, (client->ns ? client->ns->ns_name : "???"),
               client->sock, client->vio_fd);

    init_message_header(&message, client, hbm_init);
    client->pid = getpid();
    message.body.init_body.pid = htons(client->pid);
    message.body.init_body.role = htons(hb_role);

    message.body.init_body.first_hb_secs = htonl((uint32_t)client->first_hb.tv_sec);
    message.body.init_body.first_hb_nsecs = htonl((uint32_t)client->first_hb.tv_nsec);
    message.body.init_body.hb_interval_secs = htonl((uint32_t)client->hb_interval.tv_sec);
    message.body.init_body.hb_interval_nsecs = htonl((uint32_t)client->hb_interval.tv_nsec);
    message.body.init_body.vote_secs = htonl((uint32_t)client->vote_to.tv_sec);
    message.body.init_body.vote_nsecs = htonl((uint32_t)client->vote_to.tv_nsec);
    message.body.init_body.shutdown_notice_secs = htonl((uint32_t)client->shutdown_notice_to.tv_sec);
    message.body.init_body.shutdown_notice_nsecs = htonl((uint32_t)client->shutdown_notice_to.tv_nsec);
    message.body.init_body.suspend_notice_secs = htonl((uint32_t)client->suspend_notice_to.tv_sec);
    message.body.init_body.suspend_notice_nsecs = htonl((uint32_t)client->suspend_notice_to.tv_nsec);
    message.body.init_body.resume_notice_secs = htonl((uint32_t)client->resume_notice_to.tv_sec);
    message.body.init_body.resume_notice_nsecs = htonl((uint32_t)client->resume_notice_to.tv_nsec);
    message.body.init_body.downscale_notice_secs = htonl((uint32_t)client->downscale_notice_to.tv_sec);
    message.body.init_body.downscale_notice_nsecs = htonl((uint32_t)client->downscale_notice_to.tv_nsec);
    message.body.init_body.restart_secs = htonl((uint32_t)client->restart_to.tv_sec);
    message.body.init_body.restart_nsecs = htonl((uint32_t)client->restart_to.tv_nsec);

    strncpy(message.body.init_body.instance_id, client->instance_id, sizeof(message.body.init_body.instance_id));
    strncpy(message.body.init_body.name, client->name, sizeof(message.body.init_body.name));
    strncpy(message.body.init_body.instance_name, client->instance_name, sizeof(message.body.init_body.instance_name));

    message.body.init_body.corrective_action = htons(client->corrective_action);
    message.body.init_body.corrective_action_var = htons(client->corrective_action_var);
    strncpy(message.body.init_body.corrective_action_script, client->corrective_action_script, sizeof(message.body.init_body.corrective_action_script));
    message.body.init_body.child_corrective_action = htons(hbca_log);
    message.body.init_body.child_corrective_action_var = 0;
    strncpy(message.body.init_body.child_corrective_action_script, "", sizeof(message.body.init_body.child_corrective_action_script));

    PRINT_MESSAGE("send hbm_init from '%s'\n", client->name);
    client->state = hbs_client_waiting_init_ack;
    rc = hb_client_write(client, &message, sizeof(message));
    if (rc < 0)
        {
        PRINT_ERR("client write: %s", strerror(errno));
        close(sock);
        #ifdef HB_USE_SELECT
            FD_CLR(sock, &(client->ns->read_socks));
        #endif /* HB_USE_SELECT */
        #ifdef HB_USE_POLL
            hb_pollfd_remove_fd(&(client->ns->pollfd_data), sock);
        #endif /* HB_USE_POLL */
        client->sock = -1;
        client->vio_fd = -1;
        return -1;
        }

    hb_set_first_timeout_client(client, 2*client->hb_interval.tv_sec, 2*client->hb_interval.tv_nsec);
    PRINT_INFO("client_connect ac_enqueue_alarm\n");
    hb_enqueue_first_ns_client(client->ns, client);
    return 0;
    }

void handle_client_disconnect(hb_client_t *client, int timeout)
    {
    PRINT_INFO("handle_client_disconnect\n");
    client_reconnect(client, timeout);
    }

/**************************************************************************************
 *
 * Name   : handle_client_connection
 *
 * Purpose: Manage the client connection to the guestServer daemon on the host
 *
 * Description: This handler
 *
 *  1. Handles  'init_ack' messages
 *  2. handles 'challenge' messages 
 *
 *  ... comming into the VM from the host.
 *
 * Note: From within the VM the guestServer running on the host is seen as the client
 *
 */
int handle_client_connection(hb_client_t *client)
    {
    heartbeat_message_t message;
    heartbeat_message_t response;
    int rc = -1;
    uint16_t version;
    uint16_t mtype;
    uint32_t sequence;
    uint32_t size;
    uint32_t challenge;
    uint32_t resp;
    int      sock = -1;
    long secs;
    long nsecs;

    PRINT_DEBUG("handle_client_connection\n");

    rc = hb_client_read(client, &message, sizeof(message));

    sock = HB_GET_CLIENT_FD(client);
        
    if (rc <= 0)
        {
        /* Connection closed, close this end
           and free up entry in server.connections */
        PRINT_ERR("Client Connection lost: '%s', FD=%d, rc=%d: %s\n", client->name, sock, rc, strerror(errno));

        handle_client_disconnect(client, 0);
        return HB_RC_IO_ERR;
        }

    if (rc < (int)sizeof(message))
        {
        /* Connection closed, close this end
           and free up entry in server.connections */
        PRINT_ERR("Short message: '%s', FD=%d\n", client->name, sock);

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
    PRINT_MESSAGE("recv by '%s', fd=%d, type=%s, for=%s, ns=%s\n", client->name, sock, hb_get_message_type_name(mtype), client->name, client->ns->ns_name);

    if (version > HB_CURRENT_VERSION)
        {
        PRINT_ERR("Bad version: %d, size = %d, sequence = %d\n", version, size, sequence);
        /* TODO corrective action? close socket? ignore for now */
        return 0;
        }

    hb_set_first_timeout_client(client, 2*client->hb_interval.tv_sec, 2*client->hb_interval.tv_nsec);
    if (ac_alarm_on_queue(&(client->alarm)))
        {
        hb_requeue_first_ns_client(client->ns, client);
        }
    else
        {
        PRINT_INFO("Not on queue\n");
        hb_enqueue_first_ns_client(client->ns, client);
        }

    switch(mtype)
        {
        case hbm_init:
            PRINT_ERR("unexpected 'hbm_init' message recieved\n");
            break;
        case hbm_init_fail:
            handle_client_disconnect(client, 5);
            return HB_RC_IO_ERR;
        case hbm_init_ack:
            /* We got an init ACK from the guestServer on the compute */
            if (client->state != hbs_client_waiting_init_ack)
            {
                PRINT_ERR("unexpected 'hbm_init_ack' message recieved while in '%s' state %d\n", 
                           hb_get_state_name(client->state), client->state );

                /**
                 * TODO: Need to handle this error case
                 *       - should set back to sending init aftr some TBD criteria
                 **/
            }
            else
            {
                PRINT_MESSAGE("recv: hbm_init_ack for '%s'\n", client->name);
                rc = validate_client_response(client, &message, hbm_init_ack);
                if (rc == 0)
                {
                    /* valid */
                    PRINT_DEBUG("hbm_init_ack: '%s' FD=%d\n", client->name, sock);
                    client->server_role = ntohs(message.body.init_ack_body.role);
                    client->heartbeat_id = ntohl(message.header.heartbeat_id);
                    client->heartbeat_algorithm = ntohl(message.body.init_ack_body.heartbeat_algorithm);
                    client->heartbeat_secret = ntohl(message.body.init_ack_body.heartbeat_secret);
                    client->heartbeat_challenge = ntohl(message.body.init_ack_body.heartbeat_challenge);
                    client->state = hbs_client_waiting_challenge;
                    client->server_role = ntohs(message.body.init_ack_body.role);
                    PRINT_DEBUG("waiting challenge %d\n", client->heartbeat_challenge);
                    PRINT_INFO("Connection Accepted by %s, connection id %d\n", hb_get_role_name(client->server_role), client->heartbeat_id);
                }
            }
            break;
        case hbm_exit:
            PRINT_ERR("hbm_exit message recieved by client\n");
            break;
        case hbm_challenge: /* ERIC IS HERE - Handle the challenge request from the guestServer */
            if ((client->state != hbs_client_waiting_challenge) &&
                (client->state != hbs_client_paused))
                {
                PRINT_ERR("hbm_challenge message recieved when in state %d (%s)\n", client->state, hb_get_state_name(client->state));
                }
            else
                {
                PRINT_DEBUG("recv: hbm_challenge %d for '%s'\n", ntohl(message.body.challenge_body.heartbeat_challenge), client->name);
                rc = validate_client_response(client, &message, hbm_challenge);
                if (rc == 0)
                    {
                    /* valid */
                    int health_rc;
                    char err_msg[HB_LOG_MSG_SIZE];

                    memset(err_msg, 0, sizeof(err_msg));
                    memset(response.body.response_body.err_msg, 0, sizeof(response.body.response_body.err_msg));

                    #ifdef HEALTH_FILE_ONLY
                        int stat_rc;
                        struct stat stat_buf;
                        stat_rc = stat(HEARTBEAT_UNHEALTHY_FILE, &stat_buf);
                        if (stat_rc == 0)
                            {
                            health_rc = hbh_unhealthy;
                            snprintf(response.body.response_body.err_msg, sizeof(response.body.response_body.err_msg),
                                     "Voting unhealthy due to presence of file '%s'", HEARTBEAT_UNHEALTHY_FILE);
                            PRINT_INFO("Voting unhealthy due to presence of file '%s'", HEARTBEAT_UNHEALTHY_FILE);
                            } 
                        else
                            {
                            health_rc = hbh_healthy;
                            }
                    #else
                        /* Run my health check function/script */
                        if (client->health_check_func)
                            {
                            health_rc = client->health_check_func(client->health_check_arg, err_msg, sizeof(err_msg));
                            if (health_rc != hbh_healthy)
                                {
                                strncpy(response.body.response_body.err_msg, err_msg, sizeof(response.body.response_body.err_msg));
                                response.body.response_body.corrective_action = htons(client->corrective_action);
                                allow_reconnect = 0;
                                }
                            }
                        else
                            health_rc = hbh_healthy;
    
                        PRINT_DEBUG("local health=%d, msg='%s'\n", health_rc, response.body.response_body.err_msg);
    
                        /* Check to see if we have our own clients that wish to vote unhealthy */
                        if ((health_rc == hbh_healthy) && client->ns)
                            {
                            int i;
                            hb_server_client_t *scp;
    
                            for(i=0; (i<HB_MAX_CLIENTS) && (health_rc == hbh_healthy); i++)
                                {
                                scp = client->ns->server.connections[i];
                                if (scp)
                                   PRINT_DEBUG("client %s health=%d, msg='%s'\n", scp->name, scp->health_state, scp->health_err_msg);
                                if (scp && (scp->health_state != hbh_healthy))
                                    {
                                    health_rc = scp->health_state;
                                    response.body.response_body.corrective_action = htons(scp->corrective_action);
                                    strncpy(response.body.response_body.err_msg, scp->health_err_msg, sizeof(response.body.response_body.err_msg));
                                    } 
                                } 
                            }
                    #endif

                    PRINT_DEBUG("clients health=%d, msg='%s'\n", health_rc, response.body.response_body.err_msg);

                    challenge = ntohl(message.body.challenge_body.heartbeat_challenge);
    
                    PRINT_DEBUG("challenge %d\n", challenge);
                    init_response_header(&response, &message, client, hbm_response);
                    response.header.heartbeat_id = htonl(client->heartbeat_id);
                    response.body.response_body.health_rc = htonl((uint32_t)health_rc);
                    resp = compute_response(client->heartbeat_algorithm,
                                            client->heartbeat_secret,
                                            challenge);
                    response.body.response_body.heartbeat_response = htonl(resp);
                    client->state = hbs_client_waiting_challenge;
                    PRINT_MESSAGE("send hbm_response %d from '%s'\n", resp, client->name);
                    hb_client_write(client, &response, sizeof(response));
                    }
                }
            break;
        case hbm_response:
            PRINT_ERR("hbm_response message recieved by client\n");
            break;
        case hbm_pause:
            PRINT_ERR("hbm_pause message recieved by client\n");
            break;
        case hbm_pause_ack:
            if (client->state != hbs_client_waiting_pause_ack)
                {
                PRINT_ERR("hbm_pause_ack message recieved when not in hb_client_waiting_pause_ack, state %d\n", client->state);
                }
            else
                {
                PRINT_MESSAGE("recv: hbm_pause_ack for '%s'\n", client->name);
                rc = validate_client_response(client, &message, hbm_challenge);
                if (rc == 0)
                    {
                    /* valid, TODO nothing to do? */
                    client->state = hbs_client_paused;
                    client->heartbeat_challenge = ntohl(message.body.pause_ack_body.heartbeat_challenge);
                    PRINT_DEBUG("hbm_pause_ack: '%s'\n", client->name);
                    }
                }
            break;
        case hbm_resume:
            PRINT_ERR("hbm_resume message recieved by client\n");
            break;
        case hbm_resume_ack:
            if (client->state != hbs_client_waiting_resume_ack)
                {
                PRINT_ERR("hbm_resume_ack message recieved when not in hb_client_waiting_resume_ack, state %d\n", client->state);
                }
            else
                {
                PRINT_MESSAGE("recv: hbm_resume_ack for '%s'\n", client->name);
                rc = validate_client_response(client, &message, hbm_challenge);
                if (rc == 0)
                    {
                    /* valid, TODO nothing to do? */
                    client->state = hbs_client_waiting_challenge;
                    client->heartbeat_challenge = ntohl(message.body.resume_ack_body.heartbeat_challenge);
                    PRINT_DEBUG("hbm_resume_ack: '%s'\n", client->name);
                    }
                }
            break;
        case hbm_child_error:
            PRINT_ERR("TODO hbm_child_error message recieved by client\n");
            break;
        case hbm_shutdown_request:
            secs = ntohl(message.body.shutdown_request_body.timeout_secs);
            nsecs = ntohl(message.body.shutdown_request_body.timeout_nsecs);
            hb_fix_shutdown_to(NULL, client, 
                               ntohs(message.body.shutdown_request_body.event_type), 
                               ntohs(message.body.shutdown_request_body.notification_type), 
                               &secs, &nsecs);
            PRINT_MESSAGE("recv: hbm_shutdown_request %u for '%s', timeout=%ld\n", ntohl(message.body.shutdown_request_body.heartbeat_challenge), client->name, secs);
            rc = validate_client_response(client, &message, hbm_shutdown_request);
            if (rc == 0)
                {
                /* We may not be seeing a challenge for a while ... till shutdown_response or timeout of shutdown_response */
                hb_set_first_timeout_client(client,
                                            secs + 2*client->hb_interval.tv_sec,
                                            nsecs + 2*client->hb_interval.tv_nsec);
                hb_requeue_first_ns_client(client->ns, client);
                handle_shutdown_request_fptr(client->ns, &message, NULL, client, sock);
                }
            break;
        case hbm_shutdown_response:
            PRINT_MESSAGE("recv: hbm_shutdown_response %d for '%s'\n", ntohl(message.body.shutdown_request_body.heartbeat_challenge), client->name);
            rc = validate_client_response(client, &message, hbm_shutdown_response);
            if (rc == 0)
                {
                /* valid */
                handle_shutdown_response_fptr(client->ns, &message, NULL);
                }
            break;
        case hbm_network_namespace:
            PRINT_MESSAGE("recv: hbm_network_namespace %d for '%s'\n", ntohl(message.body.shutdown_request_body.heartbeat_challenge), client->name);
            rc = validate_client_response(client, &message, hbm_network_namespace);
            if (rc == 0)
                {
                /* valid */
                handle_network_namespace_event_fptr(client->ns, &message);
                }
            break;
        case hbm_nova_cmd:
            PRINT_ERR("hbm_nova_cmd message recieved by client\n");
            break;
        case hbm_server_exit:
            /* This will disconnect us, then launch a thread to try and reconnect */
            client_reconnect(client, 2);
            break;
        case hbm_ping:
            PRINT_INFO("hbm_ping message recieved by client\n");
            break;
        case hbm_timeouts:
            PRINT_ERR("hbm_timeouts message recieved by client\n");
            break;
        default:
            PRINT_ERR("Bad message: %d\n", mtype);
            break;
        }

    return 0;
    }



void default_handle_network_namespace_event(ns_data_t           *ns,
                                            heartbeat_message_t *message)
    {
    ns=ns;
    message=message;
    PRINT_ERR("Unexpected call to default_handle_network_namespace_event!\n");
    }

void default_handle_shutdown_response(ns_data_t           *ns,
                                      heartbeat_message_t *message,
                                      hb_server_client_t  *scp)
    {
    ns=ns;
    message=message;
    scp=scp;
    PRINT_ERR("Unexpected call to default_handle_shutdown_response!\n");
    }

void default_handle_shutdown_request(ns_data_t           *ns,
                                     heartbeat_message_t *message,
                                     hb_server_client_t  *scp,
                                     hb_client_t         *client,
                                     int                  reply_sock)
    {
    heartbeat_event_t event_type;
    heartbeat_notification_t notification_type;
    heartbeat_event_vote_t vote = hbev_accept;
    heartbeat_message_t response;
    char err_msg[HB_LOG_MSG_SIZE];

    ns=ns;
    scp=scp;

    event_type = ntohs(message->body.shutdown_request_body.event_type);
    notification_type = ntohs(message->body.shutdown_request_body.notification_type);

    PRINT_INFO("event_type = %d (%s), notification_type = %d (%s)\n", event_type, hb_get_event_name(event_type), notification_type, hb_get_notification_name(notification_type));
    switch(notification_type)
        {
        case hbnt_revocable:
            vote = hbev_accept;
            break;
        case hbnt_irrevocable:
            vote = hbev_complete;
            break;
        default:
            vote = hbev_accept;
            break;
        }

    init_response_header(&response, message, client, hbm_shutdown_response);
    response.body.shutdown_response_body.event_vote = htons((uint16_t)vote);
    response.body.shutdown_response_body.heartbeat_response  = htonl(0);
    response.body.shutdown_response_body.proxy_heartbeat_response = message->body.shutdown_request_body.proxy_heartbeat_response;
    response.body.shutdown_response_body.event_type = message->body.shutdown_request_body.event_type;
    response.body.shutdown_response_body.notification_type = message->body.shutdown_request_body.notification_type;
    memset(response.body.response_body.err_msg, 0, sizeof(response.body.response_body.err_msg));

    PRINT_INFO("call to default_handle_shutdown_request!\n");

    if (client->event_handler_func)
        {
        PRINT_INFO("client event script called for event=%s, msg_type='%s'\n", hb_get_event_name(event_type), hb_get_notification_name(notification_type));
        memset(err_msg, 0, sizeof(err_msg));
        vote = client->event_handler_func(event_type, notification_type, client->event_handler_arg, err_msg, sizeof(err_msg));
        PRINT_INFO("vote= %d (%s), err_msg='%s'\n", vote, hb_get_vote_name(vote), err_msg);
        if (vote != hbev_accept)
            {
            response.body.shutdown_response_body.event_vote = htons((uint16_t)vote);
            strncpy(response.body.shutdown_response_body.err_msg, err_msg, sizeof(response.body.shutdown_response_body.err_msg));
            }
        }

    if (HB_GET_CLIENT_FD(client) == reply_sock)
        hb_client_write(client, &response, sizeof(response));
    else
        hb_write(reply_sock, &response, sizeof(response));
    }

void hb_fix_shutdown_to(hb_server_client_t       *scp,
                        hb_client_t              *client,
                        heartbeat_event_t         event_type,
                        heartbeat_notification_t  notification_type,
                        long                     *secs,
                        long                     *nsecs)
    {
    long default_secs=0;
    long default_nsecs=0;

    if (!secs || !nsecs || (!client && !scp))
        return;

    default_secs = HB_DEFAULT_VM_TIMEOUT_MS / 1000;
    default_nsecs = (HB_DEFAULT_VM_TIMEOUT_MS % 1000) * 1000000;

    if ((*secs != default_secs) || (*nsecs != default_nsecs))
        return;

    switch(notification_type)
        {
        case hbnt_revocable:
            if (scp)
                {
                *secs = scp->vote_to.tv_sec;
                *nsecs = scp->vote_to.tv_nsec;
                }
            else
                {
                *secs = client->vote_to.tv_sec;
                *nsecs = client->vote_to.tv_nsec;
                }
            break;

        case hbnt_irrevocable:
            switch(event_type)
                {
                case hbet_stop:
                case hbet_reboot:
                    if (scp)
                        {
                        *secs = scp->shutdown_notice_to.tv_sec;
                        *nsecs = scp->shutdown_notice_to.tv_nsec;
                        }
                    else
                        {
                        *secs = client->shutdown_notice_to.tv_sec;
                        *nsecs = client->shutdown_notice_to.tv_nsec;
                        }
                    break;

                case hbet_live_migrate_begin:
                case hbet_cold_migrate_begin:
                case hbet_suspend:
                case hbet_pause:
                    if (scp)
                        {
                        *secs = scp->suspend_notice_to.tv_sec;
                        *nsecs = scp->suspend_notice_to.tv_nsec;
                        }
                    else
                        {
                        *secs = client->suspend_notice_to.tv_sec;
                        *nsecs = client->suspend_notice_to.tv_nsec;
                        }
                    break;

                case hbet_live_migrate_end:
                case hbet_cold_migrate_end:
                case hbet_unpause:
                case hbet_resume:
                    if (scp)
                        {
                        *secs = scp->resume_notice_to.tv_sec;
                        *nsecs = scp->resume_notice_to.tv_nsec;
                        }
                    else
                        {
                        *secs = client->resume_notice_to.tv_sec;
                        *nsecs = client->resume_notice_to.tv_nsec;
                        }
                    break;
                case hbet_downscale:
                    if (scp)
                        {
                        *secs = scp->downscale_notice_to.tv_sec;
                        *nsecs = scp->downscale_notice_to.tv_nsec;
                        }
                    else
                        {
                        *secs = client->downscale_notice_to.tv_sec;
                        *nsecs = client->downscale_notice_to.tv_nsec;
                        }
                    break;
                default:
                    break;
                }

            break;
        default:
            break;
        }
    }

