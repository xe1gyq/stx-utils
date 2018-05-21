/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

/**
*/
#include "heartbeat_macro.h"
#include "heartbeat_message.h"
#include "heartbeat_types.h"
#include "heartbeat_common.h"
#include "heartbeat_poll.h"
#include "network_namespace.h"
#include "heartbeat_virtio_common.h"

#include <dirent.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <resolv.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> 
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>




const char* host_virtio_dir = "/var/lib/libvirt/qemu";

// Use instance id to substitute the first %s below
const char* host_virtio_file_format_print = "cgcs.heartbeat.%s.sock";
const char* alt_host_virtio_file_format_print = "wrs.heartbeat.agent.0.%s.sock";

// Must return '2' when scaned, first buffer recieves instance id, second should get a k, and third is unused
const char* host_virtio_file_format_scan = "cgcs.heartbeat.%m[^.].soc%m[k]%ms";
const char* alt_host_virtio_file_format_scan = "wrs.heartbeat.agent.0.%m[^.].soc%m[k]%ms";



#define ARRAY_SIZE(x) ((int)(sizeof(x)/sizeof(*x)))

extern int take_corrective_action(hb_server_client_t *p,
                                  char               *err_msg, 
                                  int                 disconnect_in);
extern void end_server_client_session(ns_data_t          *ns,
                                      hb_server_client_t *p,
                                      int                 need_dequeue);


int vio_find_free_slot()
    {
    int i;

    for(i=0;i<ARRAY_SIZE(vio_data.records);i++)
        {
        if (vio_data.records[i].fd == -1)
            return i;
        }

    return -1;
    }

int vio_find_by_fd(int fd)
    {
    int i;

    for(i=0;i<ARRAY_SIZE(vio_data.records);i++)
        {
        if (vio_data.records[i].fd == fd)
            return i;
        }

    return -1;
    }

vio_record_t* vio_ptr_find_by_fd(int fd)
    {
    int i;

    i = vio_find_by_fd(fd);
    if (i < 0)
        return NULL;
    return &(vio_data.records[i]);
    }

int vio_find_by_file_name(char *fn)
    {
    int i;

    for(i=0;i<ARRAY_SIZE(vio_data.records);i++)
        {
        if ((vio_data.records[i].fd >= 0) &&
            (vio_data.records[i].file_name) &&
            (0 == strcmp(vio_data.records[i].file_name, fn)))
            {
            return i;
            }
        }

    return -1;
    }

void vio_record_init(vio_record_t *vio, int vio_idx)
    {
    vio->fd = -1;
    vio->scp = NULL;
    vio->file_name = NULL;
    vio->instance_name = NULL;

    if (vio_idx >= 0)
        vio->vio_idx = vio_idx;
    }


void vio_free_record(vio_record_t *vio, ns_data_t *ns)
    {
    vio->scp = NULL;

    PRINT_DEBUG("vio->file_name = %p\n", vio->file_name);
    if (vio->file_name)
        {
        free(vio->file_name);
        vio->file_name = NULL;
        }

    PRINT_DEBUG("vio->instance_name = %p\n", vio->instance_name);
    if (vio->instance_name)
        {
        free(vio->instance_name);
        vio->instance_name = NULL;
        }


    PRINT_DEBUG("vio->fd = %d\n", vio->fd);
    if (vio->fd >= 0)
        {
        #ifdef HB_USE_SELECT
            FD_CLR(vio->fd, &(vio_data.all_socks));
            FD_CLR(vio->fd, &(vio_data.waiting_socks));
            if (vio->scp)
                {
                FD_CLR(vio->fd, &(vio->scp->ns->read_socks));
                FD_CLR(vio->fd, &(vio->scp->ns->ready_read_socks));
                }
        #endif /* HB_USE_SELECT */
        #ifdef HB_USE_POLL
            hb_pollfd_remove_fd(&(ns->pollfd_data), vio->fd);
        #endif /* HB_USE_POLL */

        close(vio->fd);
        vio->fd = -1;
        }

    vio->scp = NULL;
    }

void vio_disconnect(vio_record_t *vio, ns_data_t *ns)
    {
    #ifdef HB_USE_SELECT
        FD_SET(vio->fd, &(vio_data.waiting_socks));
    #endif /* HB_USE_SELECT */
    #ifdef HB_USE_POLL
        hb_pollfd_modify_fd(&(ns->pollfd_data), vio->fd, hbft_server_vio, -1, NULL);
    #endif /* HB_USE_POLL */

    vio->scp = NULL;
    }

void vio_full_disconnect(vio_record_t *vio, ns_data_t *ns)
    {
    if (vio->scp)
        {
        PRINT_INFO("Deleted vio file '%s' was associated with client name=%s, instance_id=%s, instance_name=%s\n", vio->file_name, vio->scp->name, vio->scp->instance_id, vio->scp->instance_name);
        take_corrective_action(vio->scp, "vio_full_disconnect", true);
        end_server_client_session(ns, vio->scp, true);
        vio->scp = NULL;
        }

    vio_free_record(vio, ns);
    }


/* 
 * Check a filename, already striped of an directory component, against the expected
 * pattern for a cgcs heartbeat vio socket file.  
 *
 * If satisfied, returns an allocated buffer containing the qemu instance name. 
 * The buffer must be free'd. 
 *
 * Returns NULL on failure.
 */
char* vio_check_filename(char *fn)
    {
    char *s1 = NULL;
    char *s2= NULL;
    char *instance_name = NULL;
    int rc;

    rc = sscanf(fn, host_virtio_file_format_scan, &instance_name, &s1, &s2);
    if (rc != 2)
        {
        if (s1)
            {
            free(s1);
            s1 = NULL;
            }

        if (s2)
            {
            free(s2);
            s2 = NULL;
            }

        if (instance_name)
            {
            free(instance_name);
            instance_name = NULL;
            }

        rc = sscanf(fn, alt_host_virtio_file_format_scan, &instance_name, &s1, &s2);
        if (rc != 2)
            {
            PRINT_DEBUG("'%s' does not satisfy scan pattern %s\n", fn, host_virtio_file_format_scan);
            if (instance_name)
                {
                free(instance_name);
                instance_name = NULL;
                }
            }
        }

    if (s1)
        {
        free(s1);
        s1 = NULL;
        }

    if (s2)
        {
        free(s2);
        s2 = NULL;
        }

    return instance_name;
    }

void vio_delete_file(char *fn, ns_data_t *ns)
    {
    int i;
    vio_record_t *vio = NULL;
    char* instance_name;

    if (!fn || !ns)
        return;
    
    instance_name = vio_check_filename(fn);
    if (!instance_name)
        return;

    free(instance_name);
    instance_name = NULL;

    i = vio_find_by_file_name(fn);
    if (i < 0)
        {
        PRINT_ERR("Couldn't find record for file '%s'\n", fn);
        return;
        }
    
    vio = &(vio_data.records[i]);

    PRINT_INFO("Detected deletion of vio file '%s'\n", fn);
    vio_full_disconnect(vio, ns);
    }

int vio_add_file(char *fn, ns_data_t *ns)
    {
    int i;
    int rc;
    int len;
    struct sockaddr_un un;
    vio_record_t *vio;
    char* instance_name = NULL;
    char buf[PATH_MAX];

    if (!fn || !ns)
        return -1;
    
    instance_name = vio_check_filename(fn);
    if (!instance_name)
        {
        return -1;
        }

    i = vio_find_by_file_name(fn);
    if (i >= 0)
        {
        PRINT_DEBUG("'%s' is already known\n", fn);
        free(instance_name);
        return i;
        }

    i = vio_find_free_slot();
    if (i < 0)
        {
        PRINT_ERR("No free slot for %s\n", fn);
        free(instance_name);
        return -1;
        }

    vio = &(vio_data.records[i]);

    vio->file_name = strdup(fn);
    vio->instance_name = instance_name;
    instance_name = NULL;
    if (!(vio->file_name) || !(vio->instance_name))
        {
        PRINT_ERR("strpud for '%s': %s\n", fn, strerror(errno));
        vio_free_record(vio, ns);
        return -1;
        }

    snprintf(buf, sizeof(buf), "%s/%s", host_virtio_dir, fn);

    vio->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    PRINT_INFO("fn=%s, fd=%d -> idx=%d\n", fn, vio->fd, i);
    if (vio->fd < 0)
        {
        PRINT_ERR("socket failed: %s\n", strerror(errno));
        vio_free_record(vio, ns);
        return -1;
        }

    hb_setnonblocking(vio->fd);

    rc = fcntl(vio->fd, F_SETFD, FD_CLOEXEC);
    if (rc < 0)
        {
        PRINT_ERR("fcntl failed: %s\n", strerror(errno));
        vio_free_record(vio, ns);
        return -1;
        }
    
    un.sun_family = AF_UNIX;
    snprintf(buf, sizeof(buf), "%s/%s", host_virtio_dir, fn);
    strcpy(un.sun_path, buf);
    len = offsetof(struct sockaddr_un, sun_path) + strlen(buf);

    rc = connect(vio->fd, (struct sockaddr *)&un, len);
    if (rc < 0)
        {
        PRINT_ERR("connect to '%s' failed: %s\n", buf, strerror(errno));
        vio_free_record(vio, ns);
        return -1;
        }

    PRINT_INFO("Connection accepted to '%s'\n", buf);

    #ifdef HB_USE_SELECT
        if (ns->highsock < vio->fd)
            ns->highsock = vio->fd;

        FD_SET(vio->fd, &(ns->read_socks));

        if (vio_data.highsock < vio->fd)
            vio_data.highsock = vio->fd;

        FD_SET(vio->fd, &(vio_data.waiting_socks));
        FD_SET(vio->fd, &(vio_data.all_socks));
    #endif /* HB_USE_SELECT */
    #ifdef HB_USE_POLL
        hb_pollfd_add(&(ns->pollfd_data), vio->fd, hbft_server_vio, -1, NULL);
    #endif /* HB_USE_POLL */

    PRINT_INFO("registered vio sock %d\n", vio->fd);

    PRINT_INFO("Allocated slot %d for %s\n", i, fn);
    return i;
    }

void vio_reconnect(vio_record_t *vio, ns_data_t *ns)
    {
    char *fn = NULL;
    int i;

    if (vio->file_name)
        fn = strdup(vio->file_name);
    
    if (fn)
        PRINT_INFO("Attempting reconnection to '%s'\n", fn);

    // hbft_server_vio
    vio_full_disconnect(vio, ns);

    if (!fn)
        {
        PRINT_ERR("No file name\n");
        return;
        }

    i = vio_add_file(fn, ns);
    if (i < 0)
        {
        PRINT_ERR("failed to reconnect with file='%s'\n", fn);
        free(fn);
        return;
        }

    PRINT_INFO("reconnection succeeded on '%s'\n", fn);

    free(fn);
    }

void vio_inotify_event(ns_data_t *ns)
    {
    int i;
    int rc;
    struct inotify_event *in_event_p;
    int bufsize = sizeof(struct inotify_event) + PATH_MAX + 1;

    in_event_p = malloc(bufsize);

    rc = read(vio_data.inotify_fd, in_event_p, bufsize);
    if (rc < 0)
        {
        free(in_event_p);
        return;
        }

    if ((in_event_p->mask & IN_CREATE) == IN_CREATE)
        {
        PRINT_DEBUG("inotify creation event for '%s'\n", in_event_p->name);
        i = vio_add_file(in_event_p->name, ns);
        if (i >= 0)
            {
            PRINT_INFO("added '%s'\n", in_event_p->name);
            }
        }
    else if ((in_event_p->mask & IN_DELETE) == IN_DELETE)
        {
        PRINT_DEBUG("inotify deletion event for '%s'\n", in_event_p->name);
        vio_delete_file(in_event_p->name, ns);
        }

    free(in_event_p);
    }

void vio_scan(ns_data_t *ns)
    {
    DIR *dirp;
    struct dirent entry;
    struct dirent *result;
    int i;

    dirp = opendir(host_virtio_dir);

    if (!dirp)
        {
        PRINT_ERR("opendir %s failed: %s\n", host_virtio_dir, strerror(errno));
        return;
        }

    while(0 == readdir_r(dirp, &entry, &result))
        {
        if (!result)
            break;

        i = vio_add_file(result->d_name, ns);
        if (i >= 0)
            {
            PRINT_DEBUG("added '%s'\n", result->d_name);
            }
        }

    closedir(dirp);
    }


int vio_server_init(ns_data_t *ns)
    {
    int i;

    if (!ns)
        {
        PRINT_ERR("failed to provide ns_data\n");
        return -1;
        }

    vio_data.event_size = sizeof(struct inotify_event) + PATH_MAX + 1;
    vio_data.event_ptr = NULL;
    vio_data.inotify_fd = -1;
    vio_data.inotify_watch_id = -1;
    #ifdef HB_USE_SELECT
        vio_data.highsock = -1;
        FD_ZERO(&vio_data.waiting_socks);
        FD_ZERO(&vio_data.all_socks);
    #endif /* HB_USE_SELECT */

    for(i=0;i<ARRAY_SIZE(vio_data.records);i++)
        vio_record_init(&(vio_data.records[i]), i);

    vio_data.event_size = sizeof(struct inotify_event) + PATH_MAX + 1;
    vio_data.event_ptr = malloc(vio_data.event_size);
    vio_data.inotify_fd = inotify_init();
    if (vio_data.inotify_fd < 0)
        {
        PRINT_ERR("vio_init failed: %s\n", strerror(errno));
        return -1;
        }

    vio_data.inotify_watch_id = inotify_add_watch(vio_data.inotify_fd, host_virtio_dir, IN_CREATE | IN_DELETE);
    if (vio_data.inotify_watch_id < 0)
        {
        PRINT_ERR("vio_add_watch failed: %s\n", strerror(errno));
        close(vio_data.inotify_fd);
        vio_data.inotify_fd = -1;
        return -1;
        }

    #ifdef HB_USE_SELECT
        if (ns->highsock < vio_data.inotify_fd)
            ns->highsock = vio_data.inotify_fd;

        FD_SET(vio_data.inotify_fd, &(ns->read_socks));
    #endif /* HB_USE_SELECT */
    #ifdef HB_USE_POLL
        hb_pollfd_add(&(ns->pollfd_data), vio_data.inotify_fd, hbft_inotify, -1, NULL);
    #endif /* HB_USE_POLL */
    PRINT_INFO("registered vio inotify sock %d\n", vio_data.inotify_fd);

    if (hb_role == hbr_compute)
        vio_scan(ns);

    return 0;
    }
 

