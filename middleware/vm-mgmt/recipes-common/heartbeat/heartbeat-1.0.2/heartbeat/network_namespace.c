/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

/**
*/
#include "heartbeat_macro.h"
#include "heartbeat_types.h"
#include "heartbeat.h"
#include "heartbeat_poll.h"
#include <cgcs/atomic.h>

#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <pthread.h>
#include <errno.h>
#include <stdbool.h>


#define NETNS_RUN_DIR "/var/run/netns"


typedef enum
    {
    nsdf_ptr,
    nsdf_ns_name,
    nsdf_ns_fd,
    nsdf_thread,
    nsdf_instance_id,
    nsdf_instance_name,
    nsdf_name,
    } ns_data_field_t;

typedef struct 
    {
    ns_data_field_t field;
    ns_data_t      *match;
    ns_data_t     **match_prev;
    ns_data_t       ns_data;
    const char     *target;
    hb_server_client_t *scp;
    } ns_data_find_t;


ns_data_t *ns_head = NULL;



int get_namespace_fd(const char *dir_name, const char *name_space);



void ns_insert(ns_data_t *new_ns)
    {
    ns_data_t *old;
    int rc;

    do
       {
       old = ns_head;
       new_ns->next = old;
       rc = ATOMIC_TEST_AND_SET_IF_EQ(&ns_head, old, new_ns);
       } while (!rc);
    }

ns_traverse_return_t ns_traverse(
                                 ns_traverse_func_return_t (*f)(ns_data_t *ptr,
                                                                void      *arg),
                                 void                       *arg)
    {
    ns_data_t                 *p;
    ns_traverse_func_return_t  trc;

    for(p = ns_head; p; p = p->next)
        {
        trc = f(p, arg);
        if (trc == ns_traverse_stop)
           return ns_traverse_stopped;
        }

    return ns_traverse_complete;
    }

hb_server_client_t* find_server_client_from_instance_id(ns_data_t* ns, const char* instance_id)
    {
    int i;
    hb_server_client_t *scp;

    for(i=0; i<HB_MAX_CLIENTS; i++)
        {
        scp = ns->server.connections[i];
        if (scp && scp->instance_id[0])
            {
            if (0==strncmp(scp->instance_id, instance_id, sizeof(scp->instance_id)))
                return scp;
            }
        }

    return NULL;
    }


hb_server_client_t* find_server_client_from_instance_name(ns_data_t* ns, const char* instance_name)
    {
    int i;
    hb_server_client_t *scp;

    for(i=0; i<HB_MAX_CLIENTS; i++)
        {
        scp = ns->server.connections[i];
        if (scp && scp->instance_name[0])
            {
            if (0==strncmp(scp->instance_name, instance_name, sizeof(scp->instance_name)))
                return scp;
            }
        }

    return NULL;
    }


hb_server_client_t* find_server_client_from_name(ns_data_t* ns, const char* name)
    {
    int i;
    hb_server_client_t *scp;

    for(i=0; i<HB_MAX_CLIENTS; i++)
        {
        scp = ns->server.connections[i];
        if (scp && scp->name[0])
            {
            if (0==strncmp(scp->name, name, sizeof(scp->name)))
                return scp;
            }
        }

    return NULL;
    }


ns_traverse_func_return_t ns_find_helper(ns_data_t *ns, void *arg)
    {
    ns_data_find_t *target = arg;
    hb_server_client_t *scp;

    switch(target->field)
        {
        case nsdf_ptr:
            if (target->match == ns)
                {
                return ns_traverse_stop;
                }

        case nsdf_ns_name:
            if (target->ns_data.ns_name == ns->ns_name)
                {
                target->match = ns;
                return ns_traverse_stop;
                }

            if (0==strcmp(target->ns_data.ns_name, ns->ns_name))
                {
                target->match = ns;
                return ns_traverse_stop;
                }

            break;

        case nsdf_ns_fd:
            if (target->ns_data.ns_fd == ns->ns_fd)
                {
                target->match = ns;
                return ns_traverse_stop;
                }

            break;

        case nsdf_thread:
            if (target->ns_data.thread == ns->thread)
                {
                target->match = ns;
                return ns_traverse_stop;
                }

            break;

        case nsdf_instance_id:
            scp = find_server_client_from_instance_id(ns, target->target);
            if (scp)
                {
                target->match = ns;
                target->scp = scp;
                return ns_traverse_stop;
                }
            break;

        case nsdf_instance_name:
            scp = find_server_client_from_instance_name(ns, target->target);
            if (scp)
                {
                target->match = ns;
                target->scp = scp;
                return ns_traverse_stop;
                }
            break;

        case nsdf_name:
            scp = find_server_client_from_name(ns, target->target);
            if (scp)
                {
                target->match = ns;
                target->scp = scp;
                return ns_traverse_stop;
                }
            break;

        default:
            break;
        }

    target->match_prev = &(ns->next);
    return ns_traverse_continue;
    }


/* 1 = found, 0 = not found */
int ns_find(ns_data_t **head, ns_data_find_t *target)
    {
    ns_traverse_return_t trc;

    if (!target || !head)
        return 0;
    target->match_prev = head;
    trc = ns_traverse(ns_find_helper, target);
    return (trc == ns_traverse_stopped);
    }

ns_data_t** ns_find_ptr(ns_data_t *target_ptr)
    {
    ns_data_find_t target;

    if (!target_ptr)
        return NULL;
    memset(&target, 0, sizeof(target));
    target.field = nsdf_ptr;
    target.match = target_ptr;
    if (ns_find(&ns_head, &target))
        return target.match_prev;
    return NULL;
    }

ns_data_t* ns_find_ns_name(const char* ns_name)
    {
    ns_data_find_t target;

    if (!ns_name)
        return NULL;
    memset(&target, 0, sizeof(target));
    target.field = nsdf_ns_name;
    target.ns_data.ns_name = ns_name;
    if (ns_find(&ns_head, &target))
        return target.match;
    return NULL;
    }

hb_server_client_t* find_scp_from_abstract_name(heartbeat_inst_id_t id_type, const char* id)
    {
    ns_data_find_t target;

    if (!id)
        return NULL;

    memset(&target, 0, sizeof(target));

    switch(id_type)
        {       
        case hii_inst_id:
            target.field = nsdf_instance_id;
            break;
        case hii_inst_name:
            target.field = nsdf_instance_name;
            break;
        case hii_name:
            target.field = nsdf_name;
            break;
        default:
            PRINT_ERR("Unknown inst_id_type %d", id_type);
            return NULL;
        }

    target.target = id;
    if (ns_find(&ns_head, &target))
        return target.scp;
    return NULL;
    }

hb_server_client_t* find_scp_from_instance_id(const char* id)
    {
    ns_data_find_t target;

    if (!id)
        return NULL;
    memset(&target, 0, sizeof(target));
    target.field = nsdf_instance_id;
    target.target = id;
    if (ns_find(&ns_head, &target))
        return target.scp;
    return NULL;
    }

ns_data_t* ns_remove(ns_data_t* target)
    {
    ns_data_t **prev;
    ns_data_t  *old_ptr = target;
    ns_data_t  *new_ptr;
    int         rc;

    if (!target)
        return NULL;
    do
       {
       prev = ns_find_ptr(target);
       if (prev == NULL)
           return NULL;
       new_ptr = target->next;
       rc = ATOMIC_TEST_AND_SET_IF_EQ(prev, old_ptr, new_ptr);
       } while (!rc);
    
    target->next = NULL;
    return target;
    }

ns_data_t* ns_remove_ns_name(const char* ns_name)
    {
    ns_data_t* target;

    if (!ns_name)
        return NULL;
    target = ns_find_ns_name(ns_name);
    if (!target)
        return NULL;

    return ns_remove(target);
    }

int ns_delete(const char* ns_name)
    {
    ns_data_t* ns;

    ns = ns_remove_ns_name(ns_name);
    if (!ns)
        {
        return -1;
        }

    server_shutdown(&(ns->server));

    #ifdef HB_USE_SELECT
        FD_CLR(ns->pipe_fd[WRITE_PIPE], &(ns->read_socks));
        FD_CLR(ns->pipe_fd[READ_PIPE], &(ns->read_socks));
    #endif /* HB_USE_SELECT */
    #ifdef HB_USE_POLL
        hb_pollfd_remove_fd(&(ns->pollfd_data), ns->pipe_fd[READ_PIPE]);
    #endif /* HB_USE_POLL */

    // TODO can we call pipe_disconnect(ns) instead?
    close(ns->pipe_fd[WRITE_PIPE]);
    close(ns->pipe_fd[READ_PIPE]);
    ns->pipe_fd[WRITE_PIPE] = -1;
    ns->pipe_fd[READ_PIPE] = -1;

    if (ns->ns_fd >= 0)
        {
        close(ns->ns_fd);
        }

    pthread_exit(NULL);
    return 0;
    }

void* ns_start(void *arg)
    {
#if HB_SETNS > 0
    ns_data_t *ns = arg;
    int        rc;

    while(!ns->thread)
        usleep(10);

    pthread_detach(ns->thread);
    PRINT_INFO("ns_start '%s'\n", ns->ns_name);
    ns_insert(ns);
    rc = setns(ns->ns_fd, CLONE_NEWNET);
    if (rc < 0)
        {
        PRINT_ERR("setns: %s\n", strerror(errno));
        pthread_exit(NULL);
        }

    init_ns(ns, NULL);
    init_server(&(ns->server), ns);
    server_loop(ns);
    return NULL;
#else
    PRINT_INFO("ns thread not needed: exiting\n");
    pthread_exit(NULL);
    return arg;
#endif
    }

ns_data_t* ns_add(const char *ns_name)
    {
    ns_data_t *ns;
    int        rc;

    PRINT_INFO("ns_add '%s'\n", ns_name);
    ns = malloc(sizeof(ns_data_t));
    if (ns)
        {
        ns->ns_fd = get_namespace_fd(NETNS_RUN_DIR, ns_name);
        if (ns->ns_fd >= 0)
            {
            ns->ns_name = strdup(ns_name);
            if (ns->ns_name)
                {
                rc = pthread_create(&(ns->thread), NULL, ns_start, ns);
                if (rc == 0)
                    {
                    /* success */
                    return ns;
                    }
                else
                    PRINT_ERR("pthread_create failed: %s\n", strerror(errno));
                free((void*)ns->ns_name);
                }
            else
                PRINT_ERR("strdup failed: %s\n", strerror(errno));
            close(ns->ns_fd);
            }
        else
            PRINT_ERR("get_namespace_fd failed\n");
        free(ns);
        }
    else
        PRINT_ERR("malloc failed: %s\n", strerror(errno));
    return NULL;
    }

int get_namespace_fd(const char *dir_name, const char *name_space)
    {
    int fd;
    char path[128];

    snprintf(path, sizeof(path), "%s/%s", dir_name, name_space);
    fd = open(path, O_RDONLY);   /* Get descriptor my namespace */
    if (fd >= 0)
        {
        fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
        }
    return fd;
    }

int ns_check(const char *name_space)
    {
    DIR *dirp;
    struct dirent entry;
    struct dirent *result;
    int found = 0;

    dirp = opendir(NETNS_RUN_DIR);

    if (!dirp)
        {
        PRINT_ERR("opendir %s failed: %s\n", NETNS_RUN_DIR, strerror(errno));
        return found;
        }

    while(0 == readdir_r(dirp, &entry, &result))
        {
        if (!result)
            break;

        if (0 == strcmp(result->d_name, name_space))
            {
            found = 1;
            break;
            }
        }

    closedir(dirp);
    return found;
    }

void discover_namespaces()
    {
    DIR *dirp;
    struct dirent entry;
    struct dirent *result;
    ns_data_t *ns;
    ns_data_t* found;

    dirp = opendir(NETNS_RUN_DIR);

    if (!dirp)
        {
        PRINT_DEBUG("opendir %s failed: %s\n", NETNS_RUN_DIR, strerror(errno));
        return;
        }

    while(0 == readdir_r(dirp, &entry, &result))
        {
        if (!result)
            break;

        /* Only interested in namespaces created by quantum, which are prefixed by 'q' */
        PRINT_DEBUG("Considering namespace '%s'\n", result->d_name);
        if (strncmp("qdhcp", result->d_name, 5) == 0)
            {
            PRINT_DEBUG("Found namespace '%s'\n", result->d_name);
            found = ns_find_ns_name(result->d_name);
            if (found)
                {
                PRINT_DEBUG("namespace '%s' previously known\n", result->d_name);
                continue;
                }

            PRINT_INFO("Found new namespace '%s'\n", result->d_name);
            ns = ns_add(result->d_name);
            if (!ns)
                {
                PRINT_ERR("discover_namespaces: ns_add failed for '%s'\n",
                          result->d_name);
                }
            else
                {
                PRINT_INFO("discover_namespaces: added '%s'\n",
                           result->d_name);
                }
            }
        }

    closedir(dirp);
    }

char* ns_find_ns_name_from_quantum_network_id(const char* network_id)
    {
    char buffer[256];
    char buffer2[256];
    FILE* file;
    char *s;

    snprintf(buffer, sizeof(buffer), "ip netns | grep %s", network_id);
    file = popen(buffer, "r");
    if (!file)
        return NULL;
    s = fgets(buffer, sizeof(buffer), file);
    pclose(file);
    if (s)
        {
        sscanf(s, "%s", buffer2);
        return strdup(buffer2);
        }
    return NULL;
    }
