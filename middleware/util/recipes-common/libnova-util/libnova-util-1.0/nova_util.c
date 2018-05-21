/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

/**
*/
#define _GNU_SOURCE
#include <errno.h>
#include <time.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <sys/types.h>
#include <sys/syscall.h>

#include "nova_util_types.h"
#include <cgcs/quantum_util.h>



/*
 * parse_nova_list_line: parse one line of content from 'nova list' command.
 *
 *                   nl: place to store parsed output.  Will contain malloc'd strings, use nova_list_free() to dispose
 *                    s: string input containing one line of 'nova list' output
 *              returns: 0 = success, non-zero = error
 *
 *  assumes format like this ... less the header...

nova list --fields name,OS-EXT-SRV-ATTR:instance_name,status,OS-EXT-SRV-ATTR:host,Networks --all-tenants 1
+--------------------------------------+------------+--------------------------------+-----------------------+--------+---------------------------------------------------------------+
| ID                                   | Name       | OS-EXT-SRV-ATTR: Instance Name | OS-EXT-SRV-ATTR: Host | Status | Networks                                                      |
+--------------------------------------+------------+--------------------------------+-----------------------+--------+---------------------------------------------------------------+
| 5b433e4b-abe0-4fcc-bee5-34c05dd6a79d | cloud-test | instance-00000009              | compute-0             | ACTIVE | internal-net0=10.10.0.2, 10.10.1.2; public-net0=192.168.101.3 |
+--------------------------------------+------------+--------------------------------+-----------------------+--------+---------------------------------------------------------------+


 */

int parse_nova_list_line(nova_list_t *nl, char* s)
    {
    int i=0;
    int j=0;
    int rc=0;
    char *buffer;
    char *buffer2;

    char id[128];
    char name[128];
    char inst_name[128];
    char status[128];
    char ip[128];
    char network_name[128];
    char vm_host[128];

    char remainder[1024];
    char networks[1024];

    nl->id = NULL;
    nl->name = NULL;
    nl->vm_host = NULL;
    nl->status = NULL;
    nl->num_networks = 0;
    
    id[0]='\0';
    name[0]='\0';
    inst_name[0]='\0';
    status[0]='\0';
    vm_host[0]='\0';
    remainder[0]='\0';
    rc = sscanf(s, "| %[^ |] | %[^ |] | %[^ |] | %[^ |] | %[^ |] | %[^|] |", id, name, inst_name, status, vm_host, remainder);
    if (rc < 5)
        return -1;

    nl->id = strdup(id);
    nl->name = strdup(name);
    nl->vm_host = strdup(vm_host);
    nl->inst_name = strdup(inst_name);
    nl->status = strdup(status);

    if (rc >= 6)
        {
        buffer = strdup(remainder);
        for(i=0; buffer && (i<NOVA_MAX_NETWORKS); i++)
            {
            nl->networks[i].network_name = NULL;
            nl->networks[i].num_ips = 0;
            for(j=0; j<NOVA_MAX_IPS; j++)
                nl->networks[i].ip[j] = NULL;

            rc = sscanf(buffer, "%[^;]; %[^@]", networks, remainder);
            free(buffer);
            if (rc >=2)
                buffer = strdup(remainder);
            else
                buffer = NULL;

            if (rc >= 1)
                {
                rc = sscanf(networks, "%[^ =]=%[^@]", network_name, remainder);
                if (rc >= 1)
                    nl->networks[i].network_name = strdup(network_name);

                if (rc >= 2)
                    {
                    buffer2 = strdup(remainder);
                    for(j=0; buffer2 && (j<NOVA_MAX_IPS); j++)
                        {
                        rc = sscanf(buffer2, "%[^ ,], %[^ ,]", ip, remainder);
                        free(buffer2);
                        if (rc >= 2)
                            buffer2 = strdup(remainder);
                        else
                            buffer2 = NULL;

                        if (rc >= 1)
                            {
                            nl->networks[i].ip[j] = strdup(ip);
                            nl->networks[i].num_ips = j+1;
                            }
                        }
                    nl->num_networks = i+1;
                    }
                }
            }

         if (buffer)
            free(buffer);
        }

    return 0;
    }


void nova_list_free(nova_list_t *nl)
    {
    int i;
    int j;

    if (nl->id) 
        free(nl->id);
    if (nl->name) 
        free(nl->name);
    if (nl->inst_name) 
        free(nl->inst_name);
    if (nl->vm_host) 
        free(nl->vm_host);
    if (nl->status) 
        free(nl->status);
    for(i=0; i<nl->num_networks; i++)
        {
        if (nl->networks[i].network_name)
            free(nl->networks[i].network_name);
        for(j=0; j<nl->networks[i].num_ips; j++)
            if (nl->networks[i].ip[j])
                free(nl->networks[i].ip[j]);
        }
    }


nova_list_t* nova_list_copy(nova_list_t *dest_nl, nova_list_t *nl)
    {
    nova_list_t* new_nl;
    int i;
    int j;

    if (dest_nl)
        new_nl = dest_nl;
    else
        new_nl = malloc(sizeof(nova_list_t));

    memset(new_nl, 0, sizeof(nova_list_t));

    if (nl->id)
        new_nl->id = strdup(nl->id);
    if (nl->name)
        new_nl->name = strdup(nl->name);
    if (nl->inst_name)
        new_nl->inst_name = strdup(nl->inst_name);
    if (nl->vm_host)
        new_nl->vm_host = strdup(nl->vm_host);
    if (nl->status)
        new_nl->status = strdup(nl->status);
    new_nl->num_networks = nl->num_networks;
    for(i=0; i<nl->num_networks; i++)
        {
        new_nl->networks[i].num_ips = nl->networks[i].num_ips;
        if (nl->networks[i].network_name)
            new_nl->networks[i].network_name = strdup(nl->networks[i].network_name);
        for(j=0; j<nl->networks[i].num_ips; j++)
            if (nl->networks[i].ip[j])
                new_nl->networks[i].ip[j] = strdup(nl->networks[i].ip[j]);
        }

    return new_nl;
    }


traverse_func_return_t nova_find(nova_list_t *nl, void *arg)
    {
    nova_find_t *find = (nova_find_t*)arg;
    int found = 0;
    int i;
    int j;

    find->nl = NULL;
    switch (find->field)
        {
        case nlf_id:
            found = (nl->id && (0==strcmp(find->target, nl->id)));
            break;

        case nlf_name:
            found = (nl->name && (0==strcmp(find->target, nl->name)));
            break;

        case nlf_inst_name:
            found = (nl->inst_name && (0==strcmp(find->target, nl->inst_name)));
            break;

        case nlf_vm_host:
            found = (nl->vm_host && (0==strcmp(find->target, nl->vm_host)));
            break;

        case nlf_status:
            found = (nl->status && (0==strcmp(find->target, nl->status)));
            break;

        case nlf_network_name:
            for(i=0; i<nl->num_networks; i++)
                {
                found = (nl->networks[i].network_name && (0==strcmp(find->target, nl->networks[i].network_name)));
                }

            break;

        case nlf_ip:
            for(i=0; i<nl->num_networks && !found; i++)
                {
                for(j=0; j<nl->networks[i].num_ips && !found; j++)
                    {
                    found = (nl->networks[i].ip[j] && (0==strcmp(find->target, nl->networks[i].ip[j])));
                    }
                }

            break;

        default:
            break;
        } 

    if (found)
        {
        find->nl = nova_list_copy(NULL, nl);
        return traverse_stop;
        }

    return traverse_continue;
    }
    

traverse_return_t nova_list_traverse(traverse_func_return_t (*f)(nova_list_t *nl,
                                                                 void        *arg),
                                     void                    *arg)
    {
    char         buffer[1024];
    char         passwd[256];
    nova_list_t  nl;
    FILE        *file;
    char        *s;
    int          i=0;
    int          rc=0;

    if (get_os_env() <= 0)
       return traverse_complete;

    rc = get_os_passwd(passwd, sizeof(passwd));
    if (rc < 0)
        return traverse_complete;

    snprintf(buffer, sizeof(buffer), "nova --os_password %s list --fields name,OS-EXT-SRV-ATTR:instance_name,status,OS-EXT-SRV-ATTR:host,Networks --all-tenants 1", passwd);
    file = popen(buffer, "r");
    while ((s = fgets(buffer, sizeof(buffer), file)))
        {
        i++;
        if ((i<=3) || (s[0] == '+'))
           continue;
        rc = parse_nova_list_line(&nl, s);
        if (!rc)
            {
            rc = f(&nl, arg);
            if (rc == traverse_stop)
                {
                nova_list_free(&nl);
                pclose(file);
                return traverse_stopped;
                }
            }
        nova_list_free(&nl);
        }

    pclose(file);
    return traverse_complete;
    }

char* nova_find_id_from_name(const char* target)
    {
    nova_find_t find;
    int rc;
    char* id;

    find.nl = NULL;
    find.target = target;
    find.field = nlf_name;
    rc = nova_list_traverse(nova_find, &find);
    if (rc == traverse_stopped)
        {
        id = strdup(find.nl->id);
        nova_list_free(find.nl);
        free(find.nl);
        return id;
        }
    return NULL;
    }


char* nova_find_id_from_instance_name(const char* target)
    {
    nova_find_t find;
    int rc;
    char* id;

    find.nl = NULL;
    find.target = target;
    find.field = nlf_inst_name;
    rc = nova_list_traverse(nova_find, &find);
    if (rc == traverse_stopped)
        {
        id = strdup(find.nl->id);
        nova_list_free(find.nl);
        free(find.nl);
        return id;
        }
    return NULL;
    }

char* nova_find_id_from_ip_addr(const char* target)
    {
    nova_find_t find;
    int rc;
    char* id;

    find.nl = NULL;
    find.target = target;
    find.field = nlf_ip;
    rc = nova_list_traverse(nova_find, &find);
    if (rc == traverse_stopped)
        {
        id = strdup(find.nl->id);
        nova_list_free(find.nl);
        free(find.nl);
        return id;
        }
    return NULL;
    }


char *nova_find_network_id_from_instance_id(const char* instance_id)
    { 
    nova_find_t find;
    int rc;
    char* id;
    int i;

    find.nl = NULL;
    find.target = instance_id;
    find.field = nlf_id;
    rc = nova_list_traverse(nova_find, &find);
    if (rc == traverse_stopped)
        {
        for(i=0; i<NOVA_MAX_NETWORKS; i++)
            {
            id = quantum_find_id_from_name(find.nl->networks[i].network_name);
            if (id)
                {
                nova_list_free(find.nl);
                free(find.nl);
                return id;
                }
            }

        nova_list_free(find.nl);
        free(find.nl);
        }
    return NULL;
    }

char *nova_find_vm_host_from_id(const char* instance_id)
    {
    nova_find_t find;
    int rc;
    char* vm_host;

    find.nl = NULL;
    find.target = instance_id;
    find.field = nlf_id;
    rc = nova_list_traverse(nova_find, &find);
    if (rc == traverse_stopped)
        {
        vm_host = strdup(find.nl->vm_host);
        nova_list_free(find.nl);
        free(find.nl);
        return vm_host;
        }

    return NULL;
    }

char *nova_find_dhcp_host_from_id(const char* instance_id)
    {
    nova_find_t find;
    int rc;
    int i;
    char* host;

    find.nl = NULL;
    find.target = instance_id;
    find.field = nlf_id;
    rc = nova_list_traverse(nova_find, &find);
    if (rc == traverse_stopped)
        {
        for(i=0; i<NOVA_MAX_NETWORKS; i++)
            {
            host = quantum_find_dhcp_host_from_net(find.nl->networks[i].network_name);
            if (host)
                {
                nova_list_free(find.nl);
                free(find.nl);
                return host;
                }
            }

        nova_list_free(find.nl);
        free(find.nl);
        }

    return NULL;
    }


const char* nova_timer_names[] =
    {
    "unknown",
    "first_hb",
    "hb_interval",
    "vote",
    "shutdown_notice",
    "suspend_notice",
    "resume_notice",
    "downscale_notice",
    "restart",
    };

const char* get_nova_timer_name(nova_timer_t id)
    {
    if (id >= nt_max)
        return NULL;
    return nova_timer_names[id];
    }

nova_timer_t get_nova_timer_id(const char* timer_name)
    {
    int i;

    if (!timer_name)
        return nt_unknown;

    for(i=0; i<nt_max; i++)
        {
        if (0 == strcmp(nova_timer_names[i], timer_name))
            return (nova_timer_t)i;
        }

    return nt_unknown;
    }

int nova_set_timeout(char *instance_id, nova_timer_t id, int timeout_ms)
    {
    char        cmd[1024];
    char        passwd[256];
    const char *timer_name = NULL;
    int         rc;

    timer_name = get_nova_timer_name(id);
    if (!instance_id || !timer_name || (timeout_ms <= 0))
        return -2;

    if (get_os_env() <= 0)
       return -1;

    rc = get_os_passwd(passwd, sizeof(passwd));
    if (rc < 0)
        return -1;

    snprintf(cmd, sizeof(cmd), "nova --os_password %s hb-timeout --%s %d %s", passwd, timer_name, timeout_ms, instance_id);
    syslog(LOG_USER | LOG_INFO, "nova_set_timeout: cmd = %s", cmd);
    return system(cmd);
    }

int nova_cmd_issue(const char  *cmd,
                   int        (*alt_system)(const char* cmd))
    {
    char         buffer[1024] = "";
    char         passwd[256];
    int          rc=0;

    if (get_os_env() <= 0)
       return -2;

    rc = get_os_passwd(passwd, sizeof(passwd));
    if (rc < 0)
        return -3;

    if (0==strncmp(cmd, "nova ", 5))
        {
        if (0==strncmp(cmd, "nova --os_password ", 19))
            snprintf(buffer, sizeof(buffer), "%s", cmd);
        else
            snprintf(buffer, sizeof(buffer), "nova --os_password %s %s", passwd, &cmd[4]);
        }
    else
        {
        snprintf(buffer, sizeof(buffer), "nova --os_password %s %s", passwd, cmd);
        }

    if (alt_system)
        rc = alt_system(buffer);
    else
        rc = system(buffer);

    return rc;
    }
