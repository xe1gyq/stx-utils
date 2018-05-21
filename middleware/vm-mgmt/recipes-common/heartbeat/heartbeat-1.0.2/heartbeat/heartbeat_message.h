/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

#ifndef __HEARTBEAT_MESSAGE_H__
#define __HEARTBEAT_MESSAGE_H__

/**
*/

#include <stdint.h>


typedef enum
    {
    hbh_healthy,   // 0
    hbh_unhealthy, // 1
    hbh_max
    } heartbeat_health_t;


typedef enum
    {
    hbm_init,              // client registers for heartbeat service
    hbm_init_ack,          //   server accepts new client
    hbm_init_fail,         //   server rejects new client
    hbm_exit,              // client intends to exit (Unused)
    hbm_challenge,         // server chalenges client, are you healthy
    hbm_response,          //   client responce to challenge
    hbm_pause,             // client requests pause in normal heartbeating
    hbm_pause_ack,         //   server accepts pause
    hbm_resume,            // client request resumption of normal heartbeating
    hbm_resume_ack,        //   server accepts resume
    hbm_child_error,       // client encountered error (Unused)
    hbm_shutdown_request,  // server proposes/demands shutdown
    hbm_shutdown_response, //   client votes on shutdown, or indicates shutdown complete
    hbm_network_namespace, // (Unused)
    hbm_nova_cmd,          // client asks server to issue nova command
    hbm_server_exit,       // server intends to exit/restart
    hbm_ping,              // 
    hbm_timeouts,          // client informs server about its prefered timeouts.
    hbm_message_type_max,
    } heartbeat_message_type_t;


typedef enum
    {
    hbca_log = 0,
    hbca_script,
    hbca_instance_reboot,
    hbca_instance_stop,
    hbca_instance_delete,
    hbca_process_restart,
    hbca_process_signal,
    hbca_process_set_instance_health,
    hbca_corrective_action_max,
    } heartbeat_corrective_action_t;

typedef enum
    {
    hbet_unknown,
    hbet_stop,
    hbet_reboot,
    hbet_suspend,
    hbet_pause,
    hbet_unpause,
    hbet_resume,
    hbet_live_migrate_begin,
    hbet_live_migrate_end,
    hbet_cold_migrate_begin,
    hbet_cold_migrate_end,
    hbet_downscale,
    hbet_max,
    } heartbeat_event_t;

typedef enum
    {
    hbnt_unknown,
    hbnt_revocable,    // Query VM's willingness to shutdown or reboot.
                       //    e.g. nova reboot/stop --vote <instance>
    hbnt_irrevocable,  // Notify VM of impending shutdown or reboot.
                       //    This is an oportunity for VM resident applications 
                       //    to swact or cleanly shutdown ahead of ACPI shutdown.
                       //    e.g. nova reboot/stop --notify <instance>
    hbnt_max,
    } heartbeat_notification_t;

typedef enum
    {
    hbev_accept,
    hbev_reject,
    hbev_complete,
    hbev_proxy_error,
    hbev_not_found_error,
    hbev_busy_error,
    hbev_timeout_error,
    hbev_script_error,
    hbev_waiting,
    hbev_vote_max,
    } heartbeat_event_vote_t;

typedef enum
    {
    hb_ns_create,
    hb_ns_destroy,
    } hb_ns_event_t;

#define HB_MAX(x,y) ((x)>(y)?(x):(y))

#define HBNT_DEFAULT hbnt_unknown;
#define HBET_DEFAULT hbet_unknown;
#define HB_CORRECTIVE_ACTION_DEFAULT hbca_log;
#define HB_MAGIC "HRBT"
#define HB_MAGIC_SIZE 4
#define HB_NAME_SIZE 64
#define HB_INSTANCE_ID_SIZE 40
#define HB_INSTANCE_NAME_SIZE 24
#define HB_LOG_MSG_SIZE 192
#define HB_SCRIPT_SIZE 128

#define HB_MAX_ACTIONS 1
#define HB_MAX_HOP 4

#define HB_CURRENT_VERSION 1

typedef uint32_t heartbeat_id_t;

#define HB_DIRECTION_UP   1
#define HB_DIRECTION_DOWN 0


typedef struct
    {
    char magic[HB_MAGIC_SIZE];   
    uint16_t version;
    uint16_t mtype;  // heartbeat_message_type_t 
    uint32_t sequence;
    uint32_t heartbeat_id; // heartbeat_id_t
    uint32_t size;
    } heartbeat_message_header_t;

typedef enum
    {
    hb_algorithm_xor
    } heartbeat_algorithm_t;

typedef enum
    {
    hii_unknown,
    hii_inst_id,    // instance uuid
    hii_inst_name,  // instance libvirt name
    hii_name,       // instance public name
    hii_max,
    } heartbeat_inst_id_t;

typedef union
    {
    struct
       {
       uint32_t       first_hb_secs;    // time before first heartbeat
       uint32_t       first_hb_nsecs;
       uint32_t       hb_interval_secs;  // time between heartbeat messages.
       uint32_t       hb_interval_nsecs;
       uint32_t       vote_secs;    // time to vote on shutdown, reboot, suspend, pause, etc.
       uint32_t       vote_nsecs;
       uint32_t       shutdown_notice_secs;   // time to process a shutdown or reboot notice
       uint32_t       shutdown_notice_nsecs;
       uint32_t       suspend_notice_secs;   // time to process a suspend, pause or migrate_start notice
       uint32_t       suspend_notice_nsecs;
       uint32_t       resume_notice_secs;   // time to process a resume, unpause or migrate_end notice
       uint32_t       resume_notice_nsecs;
       uint32_t       downscale_notice_secs;   // time to to process a heat downscale notice
       uint32_t       downscale_notice_nsecs;
       uint32_t       restart_secs;   // time to restart image and resume heartbeating
       uint32_t       restart_nsecs;
       uint16_t       pid;
       uint16_t       role;          // hb_role_t
       char           instance_id[HB_INSTANCE_ID_SIZE];           // 5b433e4b-abe0-4fcc-bee5-34c05dd6a79d
       char           name[HB_NAME_SIZE];                         // my_instance
       char           instance_name[HB_INSTANCE_NAME_SIZE];       // instance-00000009
       uint16_t       corrective_action;       // heartbeat_corrective_action_t
       uint16_t       corrective_action_var;
       uint16_t       child_corrective_action; // heartbeat_corrective_action_t
       uint16_t       child_corrective_action_var;
       char           corrective_action_script[HB_SCRIPT_SIZE];
       char           child_corrective_action_script[HB_SCRIPT_SIZE];
       } init_body;  // hbm_init
    struct
       {
       char           instance_id[HB_INSTANCE_ID_SIZE];
       uint16_t       role;          // hb_role_t
       uint16_t       heartbeat_algorithm;
       uint32_t       heartbeat_secret;
       uint32_t       heartbeat_challenge;  // Stored challenge for future
                                            // pause/resume/exit/child_err
       } init_ack_body;  // hbm_init_ack
    struct
       {
       uint32_t       heartbeat_response;  // Response to last stored challenge
       char           log_msg[HB_LOG_MSG_SIZE];
       } exit_body;  // hbm_exit
    struct
       {
       heartbeat_id_t heartbeat_id;
       uint32_t       heartbeat_challenge;
       } challenge_body;  // hbm_challenge
    struct
       {
       uint32_t       heartbeat_response;  // Response to challenge
       uint32_t       health_rc;           // heartbeat_health_t
       uint16_t       corrective_action;       // heartbeat_corrective_action_t
       char           err_msg[HB_LOG_MSG_SIZE];
       } response_body;  // hbm_response
    struct
       {
       uint32_t       heartbeat_response;  // Response to last stored challenge
       uint32_t       pause_secs;
       uint32_t       pause_nsecs;
       } pause_body;  // hbm_pause,
    struct
       {
       uint32_t       heartbeat_challenge;  // Stored challenge for future
                                            // pause/resume/exit/child_err
       } pause_ack_body;  // hbm_pause_ack,
    struct
       {
       uint32_t       heartbeat_response;  // Response to last stored challenge
       } resume_body;  // hbm_resume,
    struct
       {
       uint32_t       heartbeat_challenge;  // Stored challenge for future
                                            // pause/resume/exit/child_err
       } resume_ack_body;  // hbm_resume_ack,
    struct
       {
       uint32_t       heartbeat_response;  // Response to last stored challenge
       char           child_instance_id_t[HB_INSTANCE_ID_SIZE];
       uint16_t       child_heartbeat_id_t; // heartbeat_id_t
       uint16_t       child_pid;
       char           child_name[HB_NAME_SIZE];
       char           err_msg[HB_LOG_MSG_SIZE];
       } child_error_body;  // hbm_child_error,
    struct
       {
       uint32_t       heartbeat_challenge;  // Stored challenge for future
                                            // pause/resume/exit/child_err
       } child_error_body_ack;  // hbm_child_error,
    struct
       {
       uint32_t       heartbeat_challenge;  
       uint16_t       event_type;                // heartbeat_event_t
       uint16_t       notification_type;         // heartbeat_notification_t
       uint32_t       timeout_secs;
       uint32_t       timeout_nsecs;
       uint32_t       proxy_heartbeat_response;  
       uint16_t       inst_id_type;              // heartbeat_inst_id_t
       char           instance_id[HB_MAX(HB_MAX(HB_INSTANCE_ID_SIZE,HB_INSTANCE_NAME_SIZE),HB_NAME_SIZE)];
       char           network_hostname[HB_NAME_SIZE];
       char           vm_hostname[HB_NAME_SIZE];
       } shutdown_request_body; // hbm_shutdown_request
    struct
       {
       uint32_t       heartbeat_response;        // Response to challenge
       uint32_t       proxy_heartbeat_response;  
       uint16_t       event_type;                // heartbeat_event_t
       uint16_t       notification_type;         // heartbeat_notification_t
       uint16_t       event_vote;                // heartbeat_event_vote_t
       uint16_t       retry_secs;                // For future. Not currently used
       char           err_msg[HB_LOG_MSG_SIZE];  // Why did someone vote no?
       } shutdown_response_body; // hbm_shutdown_response
    struct
       {
       uint16_t       ns_event;     // hb_ns_event_t
       uint16_t       unused;       // For future. Not currently used
       char           ns_name[HB_INSTANCE_ID_SIZE];
       char           network_hostname[HB_NAME_SIZE];
       } network_namespace_body; // hbm_network_namespace
    struct
       {
       char           nova_cmd[64 + HB_INSTANCE_ID_SIZE];
       } nova_cmd_body; // hbm_nova_cmd
    struct
       {
       } server_exit_body; // hbm_server_exit
    struct
       {
       uint32_t       first_hb_secs;    // time before first heartbeat
       uint32_t       first_hb_nsecs;
       uint32_t       hb_interval_secs;  // time between heartbeat messages.
       uint32_t       hb_interval_nsecs;
       uint32_t       vote_secs;    // time to vote on shutdown, reboot, suspend, pause, etc.
       uint32_t       vote_nsecs;
       uint32_t       shutdown_notice_secs;   // time to process a shutdown or reboot notice
       uint32_t       shutdown_notice_nsecs;
       uint32_t       suspend_notice_secs;   // time to process a suspend, pause or migrate_start notice
       uint32_t       suspend_notice_nsecs;
       uint32_t       resume_notice_secs;   // time to process a resume, unpause or migrate_end notice
       uint32_t       resume_notice_nsecs;
       uint32_t       downscale_notice_secs;   // time to process a resume, unpause or migrate_end notice
       uint32_t       downscale_notice_nsecs;
       uint32_t       restart_secs;   // time to restart image and resume heartbeating
       uint32_t       restart_nsecs;
       uint16_t       role;          // hb_role_t
       uint16_t       unused;          // For future
       char           instance_id[HB_INSTANCE_ID_SIZE];           // 5b433e4b-abe0-4fcc-bee5-34c05dd6a79d
       char           name[HB_NAME_SIZE];                         // my_instance
       char           instance_name[HB_INSTANCE_NAME_SIZE];       // instance-00000009
       } timeouts_body; // hbm_timeouts
    } heartbeat_message_body_t;


typedef struct
    {
    heartbeat_message_header_t header;
    heartbeat_message_body_t   body;
    } heartbeat_message_t;

#endif /* __HEARTBEAT_MESSAGE_H__ */

