/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

#ifndef __HEARTBEAT_COMMON_H__
#define __HEARTBEAT_COMMON_H__

/**
*/

#include "heartbeat_message.h"
#include "heartbeat_types.h"
#include <cgcs/alarm_clock_types.h>

#include <stdbool.h>

extern hb_role_t hb_role;
extern int hb_debug_message;
extern int hb_debug_debug;
extern int hb_debug_info;

extern char hb_hostname[HB_INSTANCE_ID_SIZE];

extern void init_ns(ns_data_t *ns, hb_client_t *client);

extern ssize_t hb_write(int fd, heartbeat_message_t *message, size_t size);

extern ssize_t hb_read(int fd, heartbeat_message_t *message, size_t size);

extern ssize_t hb_client_write(hb_client_t *client, heartbeat_message_t *message, size_t size);

extern ssize_t hb_client_read(hb_client_t *client, heartbeat_message_t *message, size_t size);

extern heartbeat_corrective_action_t corrective_action_str_to_idx(const char* name);

extern const char* hb_get_corrective_action_name(heartbeat_corrective_action_t a);

extern const char* hb_get_message_type_name(heartbeat_message_type_t m);

extern const char* hb_get_role_name(hb_role_t r);

extern heartbeat_notification_t notification_str_to_idx(const char* name);

extern const char* hb_get_notification_name(heartbeat_notification_t notification_type);

extern heartbeat_event_t shutdown_str_to_idx(const char* name);

extern const char* hb_get_event_name(heartbeat_event_t event_type);

extern const char* hb_get_state_name(hb_state_t s);

extern const char* hb_get_vote_name(heartbeat_event_vote_t v);

extern int hb_get_signum();

extern uint32_t compute_response(heartbeat_algorithm_t algorithm, 
                                 uint32_t              secret,
                                 uint32_t              challenge);

extern void init_response_header(heartbeat_message_t      *response,
                                 heartbeat_message_t      *respond_to,
                                 hb_client_t              *p,
                                 heartbeat_message_type_t  mtype);

extern void init_message_header(heartbeat_message_t      *message,
                                hb_client_t              *p,
                                heartbeat_message_type_t  mtype);


extern int init_client(hb_client_t *client, int background_connect);

extern int validate_client_response(hb_client_t              *client,
                                    heartbeat_message_t      *m,
                                    heartbeat_message_type_t  mtype);

extern int handle_client_connection(hb_client_t *client);

extern void handle_shutdown_notice(ns_data_t           *ns,
                                   heartbeat_message_t *message,
                                   hb_server_client_t  *scp);

extern void bind_handle_shutdown_response_fptr(void (*f)(ns_data_t           *ns,
                                                         heartbeat_message_t *message,
                                                         hb_server_client_t  *scp));

extern void bind_handle_shutdown_request_fptr(void (*f)(ns_data_t           *ns,
                                                        heartbeat_message_t *message,
                                                        hb_server_client_t  *scp,
                                                        hb_client_t         *client,
                                                        int                  reply_sock));

extern void bind_handle_network_namespace_event_fptr(void (*f)(ns_data_t *ns,
                                                     heartbeat_message_t *message));

extern int pipe_connect(ns_data_t *ns);

extern void handle_client_disconnect(hb_client_t *client, int timeout);

extern void client_disconnect(hb_client_t *client, int send_exit_msg, const char* log);

extern void bind_heartbeat_exit_fptr(void (*f)(int, const char*));

extern bool hb_is_closed(int sock);

extern void hb_setnonblocking(int sock);

extern int expired_waiting_client_activity(alarm_t* p);

extern void hb_ac_enqueue_first_alarm(alarm_clock_t *alarm_clock_p,
                                      alarm_t       *p,
                                      const char    *ac_name,
                                      const char    *a_name);

extern void hb_ac_enqueue_alarm(alarm_clock_t *alarm_clock_p,
                                alarm_t       *p,
                                const char    *ac_name,
                                const char    *a_name);

extern void hb_ac_requeue_alarm(alarm_clock_t *alarm_clock_p,
                                alarm_t       *p,
                                const char    *ac_name,
                                const char    *a_name);

extern void hb_ac_requeue_first_alarm(alarm_clock_t *alarm_clock_p,
                                      alarm_t       *p,
                                      const char    *ac_name,
                                      const char    *a_name);

extern alarm_t* hb_ac_dequeue_alarm(alarm_t    *target,
                                    const char *a_name);

extern void hb_alarm_set_expire_func(alarm_t    *p,
                                     int       (*expire_func)(alarm_t*),
                                     const char *a_name,
                                     const char *f_name);

extern void hb_alarm_set_first_timeout(alarm_t    *p,
                                       long        secs,
                                       long        nsecs,
                                       const char *a_name);

extern void hb_alarm_set_interval(alarm_t    *p,
                                  long        secs,
                                  long        nsecs,
                                  const char *a_name);

extern void hb_requeue_first_ns_client(ns_data_t   *ns,
                                       hb_client_t *client);

extern void hb_requeue_first_ns_scp(ns_data_t          *ns,
                                    hb_server_client_t *scp);

extern void hb_enqueue_first_ns_client(ns_data_t   *ns,
                                       hb_client_t *client);

extern void hb_enqueue_first_ns_scp(ns_data_t          *ns,
                                    hb_server_client_t *scp);

extern void hb_requeue_ns_client(ns_data_t   *ns,
                                 hb_client_t *client);

extern void hb_requeue_ns_scp(ns_data_t          *ns,
                              hb_server_client_t *scp);

extern void hb_enqueue_ns_client(ns_data_t   *ns,
                                 hb_client_t *client);
                                       
extern void hb_enqueue_ns_scp(ns_data_t          *ns,
                              hb_server_client_t *scp);

extern void hb_dequeue_client(hb_client_t *client);

extern void hb_dequeue_scp(hb_server_client_t *scp);

extern void hb_set_first_timeout_client(hb_client_t *client,
                                        long         secs,
                                        long         nsecs);

extern void hb_set_first_timeout_scp(hb_server_client_t *scp,
                                     long                secs,
                                     long                nsecs);

extern void hb_set_interval_scp(hb_server_client_t *scp,
                                long                secs,
                                long                nsecs);

#define hb_set_expire_func_client(client, expire_func) hb_set_expire_func_client2(client, expire_func, #expire_func)
extern void hb_set_expire_func_client2(hb_client_t *client,
                                       int        (*expire_func)(alarm_t*),
                                       const char  *f_name);

#define hb_set_expire_func_scp(scp, expire_func) hb_set_expire_func_scp2(scp, expire_func, #expire_func)
extern void hb_set_expire_func_scp2(hb_server_client_t *scp,
                                    int               (*expire_func)(alarm_t*),
                                    const char         *f_name);

extern void hb_fix_shutdown_to(hb_server_client_t       *scp,
                               hb_client_t              *client,
                               heartbeat_event_t         event_type,
                               heartbeat_notification_t  notification_type,
                               long                     *secs,
                               long                     *nsecs);

#endif /* __HEARTBEAT_COMMON_H__ */
