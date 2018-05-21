/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

/**
*/
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

    printf("heartbeat_client [--port <port>] [--addr <ip_addr> | --host <hostname>] \n");
    printf("                 [--name <name>] [--instance_id <id>] [--instance_name <name>] \n");
    printf("                 [--first <millisec>] [--interval <millisec>] [--health_script <quoted_script>]\n");
    printf("                 [--corrective <action> [--corrective_var <int>] [--corrective_script <quoted_script>]  \n");
    printf("                 [--vote_timeout <millisec>] [--shutdown_timeout <millisec>] [--restart_timeout <millisec>] \n");
    printf("                 [--suspend_timeout <millisec>] [--resume_timeout <millisec>]\n");
    printf("\n");
    printf("    where <action> is one of: ");
    for(i=0; i<hbca_corrective_action_max; i++)
        printf("%s%s", (i ? ", " : ""), hb_get_corrective_action_name(i));
    printf("\n");
    exit(-1);
    }

int unhealthy = 0;
char unhealthy_err_msg_buff[HB_LOG_MSG_SIZE] = "";

int request_pause = 0;
int pause_timeout = 60;
char* health_script = NULL;
char* event_handling_script = NULL;

void sighup_handler(int sig)
    {
    sig = sig;

    hb_exit("heartbeat_client exiting due to SIGHUP");
    exit(-1);
    }

void sigusr1_handler(int sig)
    {
    sig = sig;
    unhealthy = !unhealthy;
    if (unhealthy)
        strncpy(unhealthy_err_msg_buff, "Simulate unhealthy condition in response to SIGUSR1" ,sizeof(unhealthy_err_msg_buff));
    else
        memset(unhealthy_err_msg_buff, 0 ,sizeof(unhealthy_err_msg_buff));
    }

void sigusr2_handler(int sig)
    {
    int rc;
    int timeout = pause_timeout;

    sig = sig;
    request_pause = !request_pause;
    if (request_pause)
        {
        rc = hb_freeze(timeout * 1000);
        if (rc == HB_RC_OK)
            {
            PRINT_DEBUG("freeze heartbeat for %d secs\n", timeout);
            }
        else
            {
            PRINT_DEBUG("hb_freeze failed with rc=%d\n", rc);
            }
        }
    else
        {
        rc = hb_thaw();
        if (rc == HB_RC_OK)
            {
            PRINT_DEBUG("thaw heartbeat\n");
            }
        else
            {
            PRINT_DEBUG("hb_thaw failed with rc=%d\n", rc);
            }
        }
    }

heartbeat_health_t health_script_wrapper(void *arg, 
                                         char *err_msg_buff,
                                         int   err_msg_buff_size)
    {
    char* script = arg;
    int rc;
    int exit_rc = 0;
    int save_errno;
    char cmd[1024];
    char buffer[HB_LOG_MSG_SIZE];
    char msg[HB_LOG_MSG_SIZE];
    FILE *fp;
    char *s;

    memset(buffer, 0, sizeof(buffer));
    memset(msg, 0, sizeof(msg));
    sprintf(cmd, "%s", script);
    PRINT_INFO("cmd=%s\n", cmd);
    fp = popen(cmd, "r");
    save_errno = errno;
    if (fp)
        {
        s = fgets(buffer, sizeof(buffer), fp);
        if (s)
            snprintf(msg, sizeof(msg), "%s", s);
        else
            snprintf(msg, sizeof(msg), "No Error text provided by script");

        rc = pclose(fp);
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
            if (exit_rc)
               {
               snprintf(err_msg_buff, err_msg_buff_size, 
                        "Health script '%s' indicates unhealthy condition: %s", cmd, msg);
               }
            }
        }
    else
        {
        PRINT_ERR("popen(%s) failed: %s\n", cmd, strerror(errno));
        snprintf(err_msg_buff, err_msg_buff_size, "popen(%s) failed: %s",
                 cmd, strerror(save_errno));
        exit_rc = -1;
        }

    return exit_rc;
    }


heartbeat_event_vote_t event_handling_script_wrapper(heartbeat_event_t         event_type,
                                                     heartbeat_notification_t  notification_type,
                                                     void                     *arg,
                                                     char                     *err_msg_buff,
                                                     int                       err_msg_buff_size)
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

    PRINT_INFO("notification_type=%d, arg=%p\n", notification_type, arg);

    memset(buffer, 0, sizeof(buffer));
    memset(msg, 0, sizeof(msg));
    sprintf(cmd, "%s %s %s", script, hb_get_notification_name(notification_type), hb_get_event_name(event_type));
    PRINT_INFO("cmd=%s\n", cmd);
    fp = popen(cmd, "r");
    save_errno = errno;
    if (fp)
        {
        s = fgets(buffer, sizeof(buffer), fp);
        if (s)
            snprintf(msg, sizeof(msg), "%s", s);
        else
            snprintf(msg, sizeof(msg), "No Error text provided by script");

        rc = pclose(fp);
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
            if (exit_rc && (notification_type == hbnt_revocable))
               {
               vote = hbev_reject;
               snprintf(err_msg_buff, err_msg_buff_size, "%s rejected: %s",
                        hb_get_event_name(event_type), msg);
               PRINT_INFO("vote=reject, err_msg_buff=%s\n", err_msg_buff);
               }

            PRINT_INFO("popen(%s) exit rc: %d\n", cmd, exit_rc);
            }
        else if (WIFSIGNALED(rc))
            {
            exit_rc = WTERMSIG(rc);
            PRINT_ERR("popen(%s) killed by signal: %d\n", cmd, exit_rc);
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

heartbeat_health_t  my_health_check(void *health_check_arg,
                                    char *err_msg_buff,
                                    int   err_msg_buff_size)
    {
    health_check_arg = health_check_arg;

    if (unhealthy)
        {
        strncpy(err_msg_buff, unhealthy_err_msg_buff, err_msg_buff_size);
        return hbh_unhealthy;
        }
    return hbh_healthy;
    }

int main(int argc, char *argv[])
    {
    int i;
    int s_port = -1;
    int sa_idx = 0;
    int host_idx = 0;
    int name_idx = 0;
    int instance_idx = 0;
    int inst_name_idx = 0;
    int corrective_idx = 0;
    int corrective_var = 0;
    int corrective_script_idx = 0;
    int health_script_idx = 0;
    int event_handling_script_idx = 0;
    int first = HB_DEFAULT_FIRST_MS;
    int interval = HB_DEFAULT_INTERVAL_MS;
    int vote_ms = HB_DEFAULT_VOTE_MS;
    int shutdown_ms = HB_DEFAULT_SHUTDOWN_MS;
    int suspend_ms = HB_DEFAULT_SUSPEND_MS;
    int resume_ms = HB_DEFAULT_RESUME_MS;
    int downscale_ms = HB_DEFAULT_DOWNSCALE_MS;
    int restart_ms = HB_DEFAULT_RESTART_MS;
    int rc;
    heartbeat_corrective_action_t corrective_action;
    struct sigaction sa;


    hb_role = hbr_vm_interface;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigusr1_handler;
    sigaction(SIGUSR1, &sa, NULL);
    sa.sa_handler = sigusr2_handler;
    sigaction(SIGUSR2, &sa, NULL);
    sa.sa_handler = sighup_handler;
    sigaction(SIGHUP, &sa, NULL);

    PRINT_DEBUG("PID = %d\n", getpid());

    hb_set_health_check(my_health_check, NULL);

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
               first = atoi(argv[i]);
            else
               usage();
            }
        else if (0==strcmp(argv[i], "--interval"))
            {
            i++;
            if (i<argc)
               interval = atoi(argv[i]);
            else
               usage();
            }
        else if (0==strcmp(argv[i], "--vote_timeout"))
            {
            i++;
            if (i<argc)
                vote_ms = atoi(argv[i]);
            else
                usage();
            }
        else if (0==strcmp(argv[i], "--shutdown_timeout"))
            {
            i++;
            if (i<argc)
                shutdown_ms = atoi(argv[i]);
            else
                usage();
            }
        else if (0==strcmp(argv[i], "--suspend_timeout"))
            {
            i++;
            if (i<argc)
                suspend_ms = atoi(argv[i]);
            else
                usage();
            }
        else if (0==strcmp(argv[i], "--downscale_timeout"))
            {
            i++;
            if (i<argc)
                downscale_ms = atoi(argv[i]);
            else
                usage();
            }
        else if (0==strcmp(argv[i], "--resume_timeout"))
            {
            i++;
            if (i<argc)
                resume_ms = atoi(argv[i]);
            else
                usage();
            }
        else if (0==strcmp(argv[i], "--restart_timeout"))
            {
            i++;
            if (i<argc)
                restart_ms = atoi(argv[i]);
            else
                usage();
            }
        else if (0==strcmp(argv[i], "--pause"))
            {
            i++;
            if (i<argc)
               pause_timeout = atoi(argv[i]);
            else
               usage();
            }
        else if (0==strcmp(argv[i], "--instance_id"))
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
                inst_name_idx = i;
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
                corrective_var = atoi(argv[i]);
            else
               usage();
            }
        else if (0==strcmp(argv[i], "--corrective_script"))
            {
            i++;
            if (i<argc)
                corrective_script_idx = i;
            else
               usage();
            }
        else if (0==strcmp(argv[i], "--health_script"))
            {
            i++;
            if (i<argc)
                health_script_idx = i;
            else
               usage();
            }
        else if (0==strcmp(argv[i], "--event_handling_script"))
            {
            i++;
            if (i<argc)
                event_handling_script_idx = i;
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

    if (corrective_idx)
        {
        corrective_action = corrective_action_str_to_idx(argv[corrective_idx]);
        rc = hb_set_corrective_action(0, corrective_action, corrective_var, corrective_script_idx ? argv[corrective_script_idx] :  NULL);
        if (rc)
            PRINT_ERR("hb_set_corrective_action failed with rc %d\n", rc);
        }

    if (health_script_idx)
        {
        health_script = strdup(argv[health_script_idx]);
        hb_set_health_check(health_script_wrapper, health_script);
        }

    if (event_handling_script_idx)
        {
        event_handling_script = strdup(argv[event_handling_script_idx]);
        hb_set_event_handler(event_handling_script_wrapper, event_handling_script);
        }

    rc = hb_init_client(name_idx ? argv[name_idx] : "heartbeat_client",
                        instance_idx ? argv[instance_idx] : "heartbeat_client_id",
                        inst_name_idx ? argv[inst_name_idx] : "heartbeat_client_name",
                        first, interval, vote_ms, shutdown_ms, suspend_ms, resume_ms, downscale_ms, restart_ms);
    PRINT_DEBUG("hb_init_client rc = %d\n", rc);
    if (rc < 0)
        {
        PRINT_ERR("hb_init_client failed with rc=%d\n", rc);
        fprintf(stderr, "Failed to open a connection to the heartbeat server\n");
        usage();
        }

    while (1)
        {
        int num_socks;
        fd_set read_socks;
        struct timeval timeout;

        timeout.tv_sec = 60 + first/1000;
        timeout.tv_usec = 0;

#define HB_SELECT 1
#ifdef SELECT
        FD_ZERO(&read_socks);

        sock = hb_get_socket();
        FD_SET(sock, &read_socks);

        num_socks = select(sock+1,
                           &read_socks,
                           (fd_set *) 0,
                           (fd_set *) 0,
                           &timeout);

        PRINT_DEBUG("select rc = %d\n", num_socks);

        if (num_socks < 0)
            {
            if (errno == EINTR)
                {
                }
            else
                {
                PRINT_ERR("select: %s\n", strerror(errno));
                exit(EXIT_FAILURE);
                }
            }

        if (num_socks == 0)
            {
            /* Nothing ready to read */
            }
        else
            {
            if (FD_ISSET(sock, &read_socks))
                {
                if (unhealthy)
                    {
                    PRINT_DEBUG("pretending to be unhealthy, ignore challenge\n");
                    hb_discard_message();
                    }
                else
                    {
                    rc = hb_handle_message(); 
                    PRINT_DEBUG("hb_handle_message rc = %d\n", rc);
                    }
                }
            }
#endif /* SELECT */

#ifdef HB_SELECT
        FD_ZERO(&read_socks);

        num_socks = hb_select(1,
                              &read_socks,
                              (fd_set *) 0,
                              (fd_set *) 0,
                              &timeout);

        PRINT_DEBUG("select rc = %d\n", num_socks);

        if (num_socks < 0)
            {
            if (errno == EINTR)
                {
                }
            else
                {
                PRINT_ERR("hb_select: %s\n", strerror(errno));
                exit(EXIT_FAILURE);
                }
            }

        if (num_socks == 0)
            {
            /* Nothing ready to read */
            }
        else
            {
            /* read something here */
            }

#endif /* HB_SELECT */

        }


    }
