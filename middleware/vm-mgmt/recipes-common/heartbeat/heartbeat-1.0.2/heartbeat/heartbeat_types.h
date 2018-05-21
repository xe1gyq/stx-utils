/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

#ifndef __HEARTBEAT_TYPES_H__
#define __HEARTBEAT_TYPES_H__

/**
*/

// #define HB_USE_SELECT 1
#define HB_USE_POLL 1

#include <sys/types.h>
#include <unistd.h>
#include <poll.h>
#include <netinet/in.h>

#include <cgcs/alarm_clock_types.h>
#include <cgcs/atomic_types.h>
#include "heartbeat_message.h"

#define HEARTBEAT_VIRTIO_FILE "/dev/virtio-ports/cgcs.heartbeat"

#define HEARTBEAT_CONF "/etc/heartbeat/heartbeat.conf"

#define HEARTBEAT_UNHEALTHY_FILE "/tmp/heartbeat_unhealthy"

#define HB_NS_DEFAULT_NAME "default"

#define HB_RC_OK                  0
#define HB_RC_INVALID_ARG        -1
#define HB_RC_ALREADY_CONNECTED  -2
#define HB_RC_OVERFLOW           -3
#define HB_RC_IO_ERR             -4
#define HB_RC_OS_ERR             -5
#define HB_RC_TIMEOUT_ERR        -6
#define HB_RC_STATE_ERR          -7
#define HB_RC_MESSAGING_ERR      -8
#define HB_RC_MISC_ERR           -9

#define HB_LISTEN_QUEUE_BACKLOG 5
#define HB_DEFAULT_SERVER_PORT 1037
#define HB_DEFAULT_CLIENT_PORT 1037
#define HB_MAX_CLIENTS 1024 
#define HB_HOST_NAME "127.0.0.1"

/* Use context appropriate timeout selected by the VM itself */
#define HB_DEFAULT_VM_TIMEOUT_MS    0

#define HB_DEFAULT_FIRST_MS      2000
#define HB_DEFAULT_INTERVAL_MS   1000
#define HB_DEFAULT_REBOOT_MS    10000
#define HB_DEFAULT_VOTE_MS      10000
#define HB_DEFAULT_SHUTDOWN_MS  10000
#define HB_DEFAULT_SUSPEND_MS   10000
#define HB_DEFAULT_RESUME_MS    10000
#define HB_DEFAULT_DOWNSCALE_MS 10000
#define HB_DEFAULT_RESTART_MS  120000
#define SERVER_SUSPEND_TIMEOUT_SECS  (365*24*3600)


// secs
#define HB_LOOKUP_DELAY          5  

#define HB_SHUTDOWN_RC_ACCEPT   0
#define HB_SHUTDOWN_RC_REJECT   1
#define HB_SHUTDOWN_RC_TIMEOUT  2
#define HB_SHUTDOWN_RC_ERROR    255

#define AC_IS_CLIENT -1
#define AC_IS_NS     -2

#define HB_GET_SCP_FD(scp) (((scp)->vio && ((scp)->vio->fd >= 0)) ? (scp)->vio->fd : (scp)->sock)
#define HB_GET_CLIENT_FD(client) (((client)->vio_fd >= 0) ? (client)->vio_fd : (client)->sock)

typedef enum 
    {
    hbr_unknown,
    hbr_control_interface,
    hbr_control,
    hbr_compute,
    hbr_vm,
    hbr_vm_interface,
    hbr_role_max,
    } hb_role_t;

typedef enum 
    {
    hbs_invalid,
    hbs_server_waiting_init,
    hbs_server_waiting_challenge,
    hbs_server_waiting_response,
    hbs_server_paused,       // heartbeat paused at request of vm
    hbs_server_nova_paused,  // heartbeat paused at request of nova
    hbs_server_migrating,    // heartbeat paused while migrate in progress
    hbs_server_corrective_action,
    hbs_client_waiting_init_ack,
    hbs_client_waiting_challenge,
    hbs_client_waiting_pause_ack,
    hbs_client_waiting_resume_ack,
    hbs_client_paused,
    hbs_client_waiting_shutdown_ack,
    hbs_client_waiting_shutdown_response,
    hbs_client_shutdown_response_recieved,
    hbs_client_exiting,
    hbs_state_max
    } hb_state_t;

typedef struct ns_data_s ns_data_t;
typedef struct hb_server_client_s hb_server_client_t;
typedef struct hb_client_s hb_client_t;

typedef struct
    {
    int                        sock;
    int                        for_me;
    int                        for_my_client;
    atomic_type                outstanding;
    heartbeat_event_t          event_type;
    heartbeat_notification_t   notification_type;
    atomic_type                vote;   // heartbeat_event_vote_t
    heartbeat_event_vote_t   (*vote_func)(heartbeat_event_t         event_type,
                                          heartbeat_notification_t  notification_type,
                                          void                     *event_handler_arg,
                                          char                     *err_msg_buff,
                                          int                       err_msg_buff_size,
                                          pid_t                    *pid_ptr);
    void                      *arg;
    ns_data_t                 *ns;
    hb_server_client_t        *scp;
    hb_server_client_t        *reply_scp;
    pthread_t                  thread;
    heartbeat_message_t        response;
    pid_t                      pid;
    int                        need_client_state_cleanup;
    } heartbeat_delayed_message_t;

typedef struct
    {
    int                 fd;
    int                 vio_idx;
    hb_server_client_t *scp;
    char               *file_name;
    char               *instance_name;
    } vio_record_t;

typedef struct
    {
    int                   inotify_fd;
    int                   inotify_watch_id;
    struct inotify_event *event_ptr;
    int                   event_size;
    vio_record_t          records[HB_MAX_CLIENTS];
#ifdef HB_USE_SELECT
    int                   highsock;
    fd_set                waiting_socks;
    fd_set                all_socks;
#endif /* HB_USE_SELECT */
    hb_client_t          *client;
    } vio_data_t;

struct hb_client_s
    {
    alarm_t             alarm;

    ns_data_t          *ns;

    hb_state_t          state;

    heartbeat_id_t      heartbeat_id;
    hb_role_t           server_role;
    pid_t               pid;
    char                instance_id[HB_INSTANCE_ID_SIZE];  // 5b433e4b-abe0-4fcc-bee5-34c05dd6a79d
    char                name[HB_NAME_SIZE];                // my_instance
    char                instance_name[HB_INSTANCE_NAME_SIZE];       // instance-00000009

    char                remote_hostname[HB_NAME_SIZE];
    char                remote_addr[16];
    char                alt_remote_addr[16];

    int                 connect_timeout;
    int                 port;
    uint16_t            version;
    uint32_t            sequence;
    int                 sock;
    struct sockaddr_in  address; 
    int                 vio_fd;

    struct timespec     first_hb;
    struct timespec     hb_interval;
    struct timespec     vote_to;
    struct timespec     shutdown_notice_to;
    struct timespec     suspend_notice_to;
    struct timespec     resume_notice_to;
    struct timespec     downscale_notice_to;
    struct timespec     restart_to;

    uint32_t            heartbeat_algorithm;
    uint32_t            heartbeat_secret;
    uint32_t            heartbeat_challenge;  // Stored challenge for future

    void               *health_check_arg;
    heartbeat_health_t (*health_check_func)(void *health_check_arg,
                                            char *err_msg_buff,
                                            int   err_msg_buff_size);

    void                     *event_handler_arg;
    heartbeat_event_vote_t  (*event_handler_func)(heartbeat_event_t         event_type,
                                                  heartbeat_notification_t  notification_type,
                                                  void                     *event_handler_arg,
                                                  char                     *err_msg_buff,
                                                  int                       err_msg_buff_size);
    heartbeat_event_vote_t  (*proxied_event_handler_func)(
                                                  heartbeat_event_t         event_type,
                                                  heartbeat_notification_t  notification_type,
                                                  void                     *event_handler_arg,
                                                  char                     *err_msg_buff,
                                                  int                       err_msg_buff_size,
                                                  pid_t                    *pid_ptr);

    heartbeat_delayed_message_t *delayed_response;

    /* passed to server */
    uint16_t            corrective_action;
    uint16_t            corrective_action_var;
    char                corrective_action_script[HB_SCRIPT_SIZE];
    };

struct hb_server_client_s
    {
    alarm_t            alarm;

    ns_data_t         *ns;
    vio_record_t      *vio;

    hb_state_t         state;
    hb_state_t         save_state;
    heartbeat_health_t health_state;
    char               health_err_msg[HB_LOG_MSG_SIZE];

    heartbeat_id_t     heartbeat_id;
    hb_role_t          client_role;
    pid_t              pid;
    char               instance_id[HB_INSTANCE_ID_SIZE];     // 5b433e4b-abe0-4fcc-bee5-34c05dd6a79d
    char               name[HB_NAME_SIZE];                   // my_instance
    char               instance_name[HB_INSTANCE_NAME_SIZE]; // instance-00000009

    uint16_t           version;
    uint32_t           sequence;
    int                sock;
    struct sockaddr_in remote_addr;

    struct timespec    interval;
    struct timespec    first_delay;
    struct timespec    pause_delay;

    struct timespec    vote_to;
    struct timespec    shutdown_notice_to;
    struct timespec    suspend_notice_to;
    struct timespec    resume_notice_to;
    struct timespec    downscale_notice_to;
    struct timespec    restart_to;

    uint32_t           heartbeat_algorithm;
    uint32_t           heartbeat_secret;
    uint32_t           heartbeat_challenge;  // Stored challenge for future
    uint32_t           heartbeat_challenge_stored;  // Stored challenge for future

    uint16_t           corrective_action;       // heartbeat_corrective_action_t
    uint16_t           corrective_action_var;
    char               corrective_action_script[HB_SCRIPT_SIZE];
                                
    uint16_t           child_corrective_action; // heartbeat_corrective_action_t
    uint16_t           child_corrective_action_var;
    char               child_corrective_action_script[HB_SCRIPT_SIZE];

    heartbeat_delayed_message_t *delayed_response;
    };

typedef hb_server_client_t* hb_server_client_p;

typedef struct
    {
    ns_data_t          *ns;

    heartbeat_id_t      heartbeat_id;

    int                 port;
    struct sockaddr_in  address; 
    int                 sock;
    hb_server_client_p  connections[HB_MAX_CLIENTS];  

    uint16_t            version;
    uint32_t            sequence;

    uint32_t            heartbeat_algorithm;
    uint32_t            heartbeat_secret;
    uint32_t            heartbeat_challenge;  // Stored challenge for future
    } hb_server_t;

#define WRITE_PIPE 1
#define READ_PIPE 0

typedef enum
    {
    hbft_unknown,
    hbft_client,
    hbft_client_vio,
    hbft_server,        // listening
    hbft_server_vio,    // unconnected
    hbft_server_client,
    hbft_server_client_vio,
    hbft_ns_pipe,
    hbft_inotify,
    hbft_max,
    } hb_fd_type_t;

typedef struct 
    {
    hb_fd_type_t fd_type;
    int          idx;
    void*        ptr;
    } hb_fd_data_t;

typedef struct 
    {
    int            array_high;
    int            array_max;
    struct pollfd *pollfd_array;
    hb_fd_data_t  *fd_array;
    } hb_pollfd_data_t;

struct ns_data_s
    {
    ns_data_t       *next;
    const char      *ns_name;
    int              ns_fd;
    pthread_t        thread;
    hb_server_t      server;
    hb_client_t     *client;
    int              pipe_fd[2];
    alarm_clock_t    alarm_clock;
#ifdef HB_USE_SELECT
    int              highsock;
    fd_set           read_socks;
    fd_set           ready_read_socks;
#endif /* HB_USE_SELECT */
#ifdef HB_USE_POLL
    hb_pollfd_data_t pollfd_data;
#endif /* HB_USE_POLL */
    heartbeat_delayed_message_t *delayed_response;
    };

typedef enum
    {
    ns_traverse_stop,
    ns_traverse_continue
    } ns_traverse_func_return_t;

typedef enum
    {
    ns_traverse_complete,
    ns_traverse_stopped
    } ns_traverse_return_t;

typedef struct
    {
    int first;    // time till first heartbeat (millisec)
    int interval; // time between heartbeats (millisec)
    int vote;
    int shutdown_notice;
    int suspend_notice;
    int resume_notice;
    int downscale_notice;
    int restart;

    heartbeat_corrective_action_t  corrective_action; 
    uint16_t                       corrective_var;
    char                           corrective_script[HB_SCRIPT_SIZE];

    char                           event_handling_script[HB_SCRIPT_SIZE];
    } hb_conf_t;

#endif  /* __HEARTBEAT_TYPES_H__ */
