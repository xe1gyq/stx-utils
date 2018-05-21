/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

#ifndef __HEARTBEAT_API_H__
#define __HEARTBEAT_API_H__

/**
*/

#include "heartbeat_message.h"
#include "heartbeat_common.h"

#include <poll.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>


/* 
 ------------------------- BASIC HEARTBEAT APIs    ---------------------
 -
 - These are the core set of APIs that the Application needs to use
 - in order to interface with the CG Comms Server Heartbeat Server.
 -
 - The following functions initialize the Heartbeat Client API:
 -
 -    hb_set_health_check(...)      // Register the Applications Health check
 -                                  // callback function with the Heartbeat API.
 -    hb_set_corrective_action(...) // Set the corrective action if this process'
 -                                  // health is bad; typically hbca_process_set_instance_health
 -                                  // to influence overall VM's health.
 -    hb_set_event_handler(...)     // Register the Applications Shutdown Request
 -                                  // callback function with the Heartbeat API.
 -    hb_init_client(...)           // Initialize registration with Heartbeat Server;
 -                                  // specifying several timeout values.
 -
 -    hb_get_socket()               // Retrieve the socket for communicating with
 -                                  // the Heartbeat Server.  This would be added to 
 -                                  // the application's main eventloop select() statement.
 -
 - The following functions would be used during steady state:
 -
 -    hb_handle_message()                  // Handle the pending message on heartbeat socket.
 -                                         // i.e. if select() returned due to heartbeat socket.
 -    <Applications_health_check>(...)     // The Application Health Check Method; implemented
 -                                         // by Application according to heartbeat-api-defined 
 -                                         // function signature.
 -    <Applications_shutdown_request>(...) // The Application Shutdown Request Method; implemented
 -                                         // by Application according to heartbeat-api-defined 
 -                                         // function signature.
 -    hb_exit(...)                         // Cleanly de-register with Heartbeat Server
 -
 - 
 - See detailed descriptions below.
 -
 */




/* 
 ************************* INITIALIZATION COMMANDS *********************
 */

/*
 * hb_set_health_check: Set the function callback for testing the health of
 *                      the process or the system as a whole.  The health_check_func()
 *                      should return hbh_unhealthy and set the err_msg if a fault is found.
 *
 *                      Use before calling hb_init_client().
 *
 *                      Callback must return in less time than the registered health check 
 *                      interval.  See 'interval_ms' of hb_init_client() below.
 *
 *                      Error messages will appear in /var/log/user.log on the
 *                      on the host compute with format...
 *
 *                      "Ill health reported by: name=%s; instance_id=%s; health_rc=%d; FD=%d; Slot=%d; Msg=%s"
 *
 *   health_check_func: function to call when a health check message is received.
 *   health_check_arg:  An arguement to pass throught to the health_check_arg
 *                      arguement of health_check_func().
 *
 *   err_msg_buff:      buffer for storage of any error messages health_check_func()
 *                      cares to provide.
 *   err_msg_buff_size: Size of err_msg_buff in bytes.
 *   returns:           heartbeat_health_t: One of ...
 *  
 *                                          hbh_healthy
 *                                          hbh_unhealthy
 */

extern void hb_set_health_check(heartbeat_health_t (*health_check_func)(void *health_check_arg,
                                                                        char *err_msg_buff,
                                                                        int   err_msg_buff_size),
                                                    void  *health_check_arg);


/*
 * hb_set_corrective_action: Set the corrective action to take if a health check
 *                           fails.  Corrective action may be local or affecting
 *                           the VM as a whole.  
 *
 *                           Use before calling hb_init_client().
 *
 *       idx:                Place holder for future revision allowing multiple or
 *                           escalating corrective actions.  Must be zero.
 *
 *       corrective_action:  One of:
 *                             hbca_log: (scope = local)
 *                                   Capture a log only.  The log will go to 
 *                                   /var/log/user.log within the current VM.
 *                                   The format is:
 *
 *                                   "Heartbeat has detected the following entity requires manual corrective action: name='%s', instance_id='%s' pid=%d, msg='%s'\n"
 *
 *                             hbca_script: (scope = local)
 *                                   Run an arbitrary script locally.
 *                                   The script will have access to the
 *                                   following environment variables.
 *                                      INSTANCE_ID, CORRECTIVE_ACTION_VAR,
 *                                      INSTANCE_PID, INSTANCE_NAME
 *
 *                             hbca_process_signal: (scope = process)
 *                                   Send a signal to this process.
 *                                   'corrective_var' is the numeric value of the signal.
 *
 *                             hbca_process_restart: (scope = local/process)
 *                                   Calls "/etc/init.d/%s restart" using the
 *                                   'instance' specified in hb_init_client().
 *
 *                             hbca_process_set_instance_health: (scope = VM)
 *                                   Set a health flag within the heartbeat server.
 *                                   This will cause the local heartbeat server
 *                                   to indicate ill health of the VM as a whole
 *                                   to the superior heartbeat server on the host
 *                                   compute. Depending on the local heartbeat
 *                                   servers configuration, any of the following
 *                                   occure.
 *
 *                             Note: Don't use these directly from an application.
 *                             hbca_instance_reboot: (scope = VM)
 *                                   issue a nove reboot against this VM.
 *
 *                             hbca_instance_stop: (scope = VM)
 *                                   issue a nove stop against this VM.
 *
 *                             hbca_instance_delete: (scope = VM)
 *                                   issue a nove delete against this VM.
 *
 *                             hbca_log: (scope = VM)
 *                                   Capture a log only.  The log will go to 
 *                                   /var/log/user.log on the host compute.
 *                                   The format is:
 *
 *                                   "Heartbeat has detected the following entity requires manual corrective action: name='%s', instance_id='%s' pid=%d, msg='%s'\n"
 *
 *                             hbca_script: (scope = VM)
 *                                   Run an arbitrary script on the compute.
 *                                   The following environment variables are defined.
 *                                      INSTANCE_ID, CORRECTIVE_ACTION_VAR,
 *                                      INSTANCE_PID, INSTANCE_NAME
 *                                   Note: May be disallowed or restricted in future.
 *                                   
 *       corrective_var:     Context dependent.  Might be a signal number
 *                           or a value placed into the envoironment of a script.
 *       script:             The script to run if corrective_action=hbca_script.
 *                           max 128 characters.
 *
 */

extern int hb_set_corrective_action(int                            idx, 
                                    heartbeat_corrective_action_t  corrective_action,
                                    int                            corrective_var,
                                    const char                    *script);


/*
 * hb_set_event_handler: Set the function callback for handling life cycle events
 *                       for the VM in which this process will be run.  Events
 *                       include reboot, stop, pause, unpause, suspend, resume,
 *                       and the begin and end of a live or cold migration.
 *
 *                       Events come in two types (notification_type):
 *
 *                         hbnt_revocable: A request by Titanium/openstack for permission
 *                                         to proceed with the event; to vote
 *                                         if you will.  The vote must be
 *                                         unanimous for the action to proceed.
 *                                         The process should take no other
 *                                         action.  If the vote passes, an
 *                                         hbnt_irrevocable version of the
 *                                         event will follow.  
 *
 *                                         Return hbev_reject to abort the 
 *                                         event, and supply a reason for the 
 *                                         rejection in err_msg_buff.
 *
 *                                         Return hbev_accept to allow the event.
 *
 *                                         This function must complete prior to
 *                                         'vote_ms' timeout given in hb_init_client().
 *                                         Failure to do so will result in a timeout error.
 *                                         and hbev_accept is assumed.
 *                                         
 *
 *                         hbnt_irrevocable: A pre-notification from Titanium/openstack 
 *                                           that the indicated event will occure
 *                                           shortly, as soon as all notifications
 *                                           have been processed.  Applies to 
 *                                           reboot, stop, pause, suspend, and
 *                                           live/cold migration begin messages.
 *
 *                                           This callback is an opportunity for
 *                                           a clean shutdown or hand off of the
 *                                           applications functions prior to the
 *                                           event.
 *
 *                                           Alternatively a post-notification from
 *                                           Titanium/openstack that the indicated event 
 *                                           has just occured.  Applies to unpause,
 *                                           resume, and live/cold migration end
 *                                           messages.
 *
 *                                           This callback is an opportunity to 
 *                                           resume normal processing after a
 *                                           pause or migration.  E.g. adjust time
 *                                           or reset notworks.
 *
 *                                           This function must complete prior to
 *                                           a timeout given in hb_init_client().
 *                                           One of shutdown_ms, suspend_ms, resume_ms
 *
 *                       Optional.  
 *
 *                       Use before calling hb_init_client().
 *
 *   event_handler_func: function to call when an event notification message is received.
 *   event_handler_arg:  An arguement to pass throught to the event_handler_arg
 *                       arguement of event_handler_func().
 *
 *   event_type:         Code indicating the event. See definition of 
 *                       heartbeat_event_t in heartbeat_message.h
 *                       One of:
 *                         reboot, stop, pause, unpause, suspend, resume,
 *                         and the begin and end of a live or cold migration. 
 *   notification_type:  Code indicating how the callback may react.
 *                         hbnt_revocable:   Vote to allow or abort the proposed event.
 *                         hbnt_irrevocable: React to an impending or recently 
 *                                           completed event with cleanup or recovery
 *                                           actions.
 *   err_msg_buff:       Buffer for storage of any error messages event_handler_func()
 *                       cares to provide.
 *   err_msg_buff_size:  Size of err_msg_buff in bytes.
 *                       
 */
extern void hb_set_event_handler(heartbeat_event_vote_t  (*event_handler_func)(heartbeat_event_t         event_type,
                                                                               heartbeat_notification_t  notification_type,
                                                                               void                     *event_handler_arg,
                                                                               char                     *err_msg_buff,
                                                                               int                       err_msg_buff_size),
                                                          void  *event_handler_arg);

/*
 * hb_init_client: Connect to the heartbeat server.
 *
 *         name:         Any identifying string:  Suggest the process name.
 *         instance:     Any identifying string:  Perhaps the name of a /etc/init.d startup script.
 *         inst_name:    Any identifying string:  Perhaps the hostname or instance name
 *         first_ms:     Time from hb_init_client to first health check callback.
 *         interval_ms:  Time between calls the health check callback, and it's max runtime.
 *         vote_ms       Time limit to process an event notification where 
 *                           notification_type=hbnt_revocable
 *         shutdown_ms:  Time limit to process an event notification where
 *                           notification_type = hbnt_irrevocable, and
 *                           event_type = hbet_stop or hbet_reboot
 *         suspend_ms:   Time limit to process an event notification where
 *                           notification_type = hbnt_irrevocable, and
 *                           event_type = hbet_suspend or hbet_pause or
 *                                        hbet_live_migrate_begin or
 *                                        hbet_cold_migrate_begin
 *         resume_ms:    Time limit to process an event notification where
 *                           notification_type = hbnt_irrevocable, and
 *                           event_type = hbet_unpause or hbet_resume or
 *                                        hbet_live_migrate_end or
 *                                        hbet_cold_migrate_end
 *         restart_ms:   Time limit for VM reboot while waiting to deliver
 *                       hbet_cold_migrate_end event.
 *
 *         Note: All time limits are given in milliseconds.
 */
extern int hb_init_client(char *name, 
                          char *instance, 
                          char *inst_name, 
                          int   first_ms,
                          int   interval_ms,
                          int   vote_ms,
                          int   shutdown_ms,
                          int   suspend_ms,
                          int   resume_ms,
                          int   downscale_ms,
                          int   restart_ms);

/* hb_get_socket:  Retrieve the file descriptor used for heartbeat messages.
 *                 This file descriptor can be used in an applications 
 *                 main select() or poll() loop.
 *
 *                 Wait till the FD is ready to read, then call hb_handle_message().
 *                 
 *                 Not Recommended: instead we recommend using one of...
 *
 *                     hb_pselect, hb_select, hb_poll, hb_ppoll
 */
extern int hb_get_socket();



/* 
 ************************* RUNTIME COMMANDS *********************
 */

/* hb_handle_message:  Process a message found on the hearbeat socket.
 *                     Call this after select() or poll() indicates 
 *                     the file descriptor returned by hb_get_socket()
 *                     is ready for reading.
 *
 *                     Not Recommended: instead we recommend using one of...
 *
 *                         hb_pselect, hb_select, hb_poll, hb_ppoll
 *
 *                     which will take care of message handling automatically.
 */

extern int hb_handle_message();


/* hb_exit: Call this prior to exit() to cleanly close heartbeat 
 *          messaging socket and avoid triggering a corrective action.
 */
extern int hb_exit(const char* log);












/* 
 ------------------------- ADVANCED HEARTBEAT APIs    ---------------------
 */





/* 
 ************************* INITIALIZATION COMMANDS *********************
 */

/*
 * hb_set_server_hostname: Set hostname of the heartbeat server you wish to 
 *                         connect to.  Use before calling hb_init_client().  
 *
 *                         Alternative interface: hb_set_server_addr()
 *
 *                         Not required for common usage.  The default
 *                         of 127.0.0.1 is usually correct.
 */

extern int hb_set_server_hostname(const char* hostname);

/*
 * hb_set_server_addr: Set ip address of the heartbeat server you wish to
 *                     connect to.  Use before calling hb_init_client().
 *                     Take a string in standard IPv4 format "128.224.140.200"
 *
 *                     Alternative interface: hb_set_server_addr()
 *
 *                     Not required for common usage.  The default
 *                     of 127.0.0.1 is usually correct.
 */

extern int hb_set_server_addr(const char* addr);

/*
 * hb_set_server_port: Set post number of the eartbeat server you wish to
 *                     connect to.  Use before calling hb_init_client().
 *
 *                     Not required for common usage.  The default
 *                     por of 1037 is usually correct.
 */   

extern int hb_set_server_port(int port);



/* 
 ************************* RUNTIME COMMANDS *********************
 */

/* hb_pselect: A wrapper around pselect() that adds the heartbeat
 *             socket to the select, and processes heartbeat messages.
 *             Substitute for pselect() within your main processing loop.
 *             See pselect manpage for details.
 */
extern int hb_pselect(int                    nfds,
                      fd_set                *readfds,
                      fd_set                *writefds,
                      fd_set                *exceptfds,
                      const struct timespec *timeout,
                      const sigset_t        *sigmask);

/* hb_select: A wrapper around select() that adds the heartbeat
 *            socket to the select, and processes heartbeat messages.
 *            Substitute for select() within your main processing loop.
 *            See select manpage for details.
 */
extern int hb_select(int             nfds, 
                     fd_set         *readfds,
                     fd_set         *writefds,
                     fd_set         *exceptfds,
                     struct timeval *timeout);

/* hb_poll: A wrapper around poll() that adds the heartbeat
 *          socket to the poll, and processes heartbeat messages.
 *          Substitute for poll() within your main processing loop.
 *          See poll manpage for details.
 */
extern int hb_poll(struct pollfd *fds,
                   nfds_t         nfds,
                   int            timeout);

/* hb_ppoll: A wrapper around ppoll() that adds the heartbeat
 *           socket to the ppoll, and processes heartbeat messages.
 *           Substitute for ppoll() within your main processing loop.
 *           See ppoll manpage for details.
 */
extern int hb_ppoll(struct pollfd         *fds,
                    nfds_t                 nfds,
                    const struct timespec *timeout_ts,
                    const sigset_t        *sigmask);

/* hb_discard_message:
 */
extern int hb_discard_message();


/* hb_freeze: Temporarily pause health check callbacks for indicated time.
 *            Allows process to deal with exceptional circumstances that
 *            may prevent servicing of health checks on the normal schedule.
 */
extern int hb_freeze(int timeout_ms);


/* hb_thaw: Clear the freeze condition of hb_freeze() immediately,
 *          and resume normal heartbeating. Don't wait for the freeze timeout.
 */
extern int hb_thaw();





/* 
 ************************* DO NOT USE THESE *********************
 */
extern int hb_shutdown_request(heartbeat_event_t         event_type,
                               heartbeat_notification_t  notification_type,
                               const char               *instance_id,
                               const char               *instance_name,
                               const char               *name,
                               int                       timeout_ms);

extern int hb_ns_notify(const char    *ns_name,
                        hb_ns_event_t  event);

extern int hb_ns_create_notify(const char *ns_name, 
                               const char *ns_host_name);

extern int hb_ns_destroy_notify(const char *ns_name, 
                                const char *ns_host_name);

#endif /* __HEARTBEAT_API_H__ */
