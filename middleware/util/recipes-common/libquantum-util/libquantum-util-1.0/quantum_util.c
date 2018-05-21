/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

/**
*/
#include "quantum_util_types.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>


int env_set=0;

int get_os_env(void)
    {
    char         buffer[1024];
    FILE        *file;
    char        *s;
    int          i=0;
    char         c;
    char        *val;
    char        *var;
    int          found;

    if (env_set)
        return env_set;

    file = popen("cat /etc/nova/openrc", "r");
    if (!file)
        {
        env_set = -1;
        return -1;
        }

    while ((s = fgets(buffer, sizeof(buffer), file)))
        {
        i=0;
        val=NULL;
        var=NULL;
        if (strncmp(s, "export", strlen("export")))
            i=strlen("export");
        else if (strncmp(s, "declare", strlen("declare")))
            i=strlen("declare");
        else
            continue;

        for(found=0;!found;i++)
           {
           c = s[i];
           if ((!c) || (c == '\r') || (c == '\n'))
              break;
           if ((c !=' ') && (c != '\t'))
              {
              found=1;
              break;
              }
           }
        if (!found)
           {
           continue;
           }
        var = &s[i];

        for(found=0;!found;i++)
           {
           c = s[i];
           if ((!c) || (c == '\r') || (c == '\n'))
              break;
           if (c == '=')
              {
              found=1;
              break;
              }
           }
        if (!found)
           {
           continue;
           }
        s[i]='\0';
        i++;
        val=&s[i];

        for(found=0;!found;i++)
           {
           c = s[i];
           if ((!c) || (c == '\r') || (c == '\n'))
              {
              found=1;
              break;
              }
           }

        s[i]='\0';

        setenv(var, val, 1);
        }

    pclose(file);
    env_set = 1;
    return 1;
    }



int get_os_passwd(char *passwd_buf, int passwd_buf_size)
    {
    char buffer[1024];
    FILE* file;
    char *s;
    int i=0;
    int rc=0;
    int rc2=0;
    int found=0;

    rc = get_os_env();

    /* Prefered source, use kering */
    snprintf(buffer, sizeof(buffer), "keyring get CGCS admin");
    file = popen(buffer, "r");
    if (file)
        {
        if ((s = fgets(buffer, sizeof(buffer), file)))
            {
            buffer[sizeof(buffer)-1] = '\0';
            for(i=0; i<(int)sizeof(buffer) && s[i]; i++)
                {
                if (s[i] == '\n' || s[i] == '\r')
                    s[i] = '\0';
                }
            strncpy(passwd_buf, s, passwd_buf_size);
            found = 1;
            }

        /* If keyring failed, it's rc is returned by pclose */
        rc2 = pclose(file);
        if (rc2)
            found = 0;
        }

    if (!found && !rc)
        {
        /*  Alternate source, environment */
        s = getenv("OS_PASSWORD");
        if (s)
            {
            strncpy(passwd_buf, s, passwd_buf_size);
            found = 1;
            }
        }

    if (!found)
        {
        strncpy(passwd_buf, "admin", passwd_buf_size);
        found = 1;
        }

    return (found ? 0 : -1);
    }


void quantum_dhcp_agent_list_free(quantum_dhcp_agent_list_t *nl)
    {
    if (nl->id)
        free(nl->id);
    if (nl->host)
        free(nl->host);
    if (nl->admin_state_up)
        free(nl->admin_state_up);
    if (nl->alive)
        free(nl->alive);
    }

void quantum_dhcp_agent_list_print(quantum_dhcp_agent_list_t *nl)
    {
    if (nl->id)
        printf("id = %s, ", nl->id);
    if (nl->host)
        printf("host = %s, ", nl->host);
    if (nl->admin_state_up)
        printf("admin_state_up = %s, ", nl->admin_state_up);
    if (nl->alive)
        printf("alive = %s, ", nl->alive);
    printf("\n");
    }

quantum_dhcp_agent_list_t* quantum_dhcp_agent_list_copy(quantum_dhcp_agent_list_t *dest_nl, quantum_dhcp_agent_list_t *nl)
    {
    quantum_dhcp_agent_list_t* new_nl;

    if (dest_nl)
        new_nl = dest_nl;
    else
        new_nl = malloc(sizeof(quantum_dhcp_agent_list_t));

    memset(new_nl, 0, sizeof(quantum_dhcp_agent_list_t));

    if (nl->id)
        new_nl->id = strdup(nl->id);
    if (nl->host)
        new_nl->host = strdup(nl->host);
    if (nl->admin_state_up)
        new_nl->admin_state_up = strdup(nl->admin_state_up);
    if (nl->alive)
        new_nl->alive = strdup(nl->alive);

    return new_nl;
    }


int quantum_dhcp_agent_list_find(quantum_dhcp_agent_list_t *nl, void *arg)
    {
    quantum_dhcp_agent_list_find_t *find = (quantum_dhcp_agent_list_find_t*)arg;
    int found = 0;

    find->nl = NULL;
    switch (find->field)
        {
        case qdalf_id:
            found = (nl->id && (0==strcmp(find->target, nl->id)));
            break;

        case qdalf_host:
            found = (nl->host && (0==strcmp(find->target, nl->host)));
            break;

        case qdalf_admin_state_up:
            found = (nl->admin_state_up && (0==strcmp(find->target, nl->admin_state_up)));
            break;

        case qdalf_alive:
            found = (nl->alive && (0==strcmp(find->target, nl->alive)));
            break;

        default:
            break;
        }

    if (found)
        {
        find->nl = quantum_dhcp_agent_list_copy(NULL, nl);
        return TRAVERSE_STOP;
        }

    return TRAVERSE_CONTINUE;
    }


int parse_quantum_dhcp_agent_list_line(quantum_dhcp_agent_list_t *nl, char* s)
    {
    int rc=0;
    char id[128];
    char host[128];
    char admin_state_up[128];
    char alive[128];


    nl->id = NULL;
    nl->host = NULL;

    rc = sscanf(s, "| %[^ |] | %[^ |] | %[^ |] | %[^ |] |", id, host, admin_state_up, alive);
    if (rc < 4)
        return -1;

    nl->id = strdup(id);
    nl->host = strdup(host);
    nl->admin_state_up = strdup(admin_state_up);
    nl->alive = strdup(alive);

    return 0;
    }



int quantum_dhcp_agent_list_traverse(const char* net, int (*f)(quantum_dhcp_agent_list_t *nl, void *arg), void *arg)
    {
    char buffer[1024];
    char passwd[256];
    quantum_dhcp_agent_list_t nl;
    FILE* file;
    char *s;
    int i=0;
    int rc=0;

    if (get_os_env() <= 0)
        return TRAVERSE_STOPPED;

    rc = get_os_passwd(passwd, sizeof(passwd));
    if (rc < 0)
        return TRAVERSE_STOPPED;

    snprintf(buffer, sizeof(buffer), "neutron --os_password %s dhcp-agent-list-hosting-net %s", passwd, net);
    file = popen(buffer, "r");
    while ((s = fgets(buffer, sizeof(buffer), file)))
        {
        i++;
        if ((i<=3) || (s[0] == '+'))
           continue;
        rc = parse_quantum_dhcp_agent_list_line(&nl, s);
        if (!rc)
            {
            rc = f(&nl, arg);
            if (rc == TRAVERSE_STOP)
                {
                quantum_dhcp_agent_list_free(&nl);
                pclose(file);
                return TRAVERSE_STOPPED;
                }
            }
        quantum_dhcp_agent_list_free(&nl);
        }

    pclose(file);
    return TRAVERSE_COMPLETE;
    }


char* quantum_find_dhcp_host_from_net(const char* network_name)
    {
    quantum_dhcp_agent_list_find_t find;
    int rc;
    char* host;

    find.nl = NULL;
    find.target = "True";
    find.field = qdalf_admin_state_up;
    rc = quantum_dhcp_agent_list_traverse(network_name, quantum_dhcp_agent_list_find, &find);
    if (rc == TRAVERSE_STOPPED)
        {
        host = strdup(find.nl->host);
        quantum_dhcp_agent_list_free(find.nl);
        free(find.nl);
        return host;
        }
    return NULL;
    }


void quantum_net_list_free(quantum_net_list_t *nl)
    {
    int i;

    if (nl->id)
        free(nl->id);
    if (nl->name)
        free(nl->name);
    for(i=0; i<nl->num_subnets; i++)
        {
        if (nl->subnets[i].subnet_id)
            free(nl->subnets[i].subnet_id);
        if (nl->subnets[i].ip4)
            free(nl->subnets[i].ip4);
        }
    }

void quantum_net_list_print(quantum_net_list_t *nl)
    {
    int i;
    if (nl->id)
        printf("id = %s, ", nl->id);
    if (nl->name)
        printf("name = %s, ", nl->name);
    if (nl->num_subnets)
        printf("subnets: ");
    for(i=0; i<nl->num_subnets; i++)
        {
        if (nl->subnets[i].subnet_id)
            printf("subnet_id = %s, ", nl->subnets[i].subnet_id);
        if (nl->subnets[i].ip4)
            printf("ip4 = %s, ", nl->subnets[i].ip4);
        if (nl->subnets[i].mask_bits)
            printf("mask_bits = %d", nl->subnets[i].mask_bits);
        printf("; ");
        }
    printf("\n");
    }

quantum_net_list_t* quantum_net_list_copy(quantum_net_list_t *dest_nl, quantum_net_list_t *nl)
    {
    quantum_net_list_t* new_nl;
    int i;

    if (dest_nl)
        new_nl = dest_nl;
    else
        new_nl = malloc(sizeof(quantum_net_list_t));

    memset(new_nl, 0, sizeof(quantum_net_list_t));

    if (nl->id)
        new_nl->id = strdup(nl->id);
    if (nl->name)
        new_nl->name = strdup(nl->name);
    new_nl->num_subnets = nl->num_subnets;
    for(i=0; i<nl->num_subnets; i++)
        {
        if (nl->subnets[i].subnet_id)
            new_nl->subnets[i].subnet_id = strdup(nl->subnets[i].subnet_id);
        if (nl->subnets[i].ip4)
            new_nl->subnets[i].ip4 = strdup(nl->subnets[i].ip4);
        new_nl->subnets[i].mask_bits = nl->subnets[i].mask_bits;
        }

    return new_nl;
    }

int parse_quantum_net_list_line(quantum_net_list_t *nl, char* s)
    {           
    int i=0;    
    int rc=0;   
    char *buffer;
        
    char id[128];
    char name[128];
    char mask_bits[128];
    char ip4[128];
    // char ip6[128];
    char subnet_id[128];
    
    char remainder[1024];
    char subnets[1024];

    nl->id = NULL;
    nl->name = NULL;
    nl->num_subnets = 0;

    rc = sscanf(s, "| %[^ |] | %[^ |] | %[^|]|", id, name, remainder);
    if (rc < 2)
        return -1;

    nl->id = strdup(id);
    nl->name = strdup(name);

    if (rc >= 3)
        {
        buffer = strdup(remainder);
        for(i=0; buffer && (i<QUANTUM_MAX_SUBNETS_PER_NETWORK); i++)
            {
            nl->subnets[i].subnet_id = NULL;
            nl->subnets[i].mask_bits = 0;
            nl->subnets[i].ip4 = NULL;

            rc = sscanf(buffer, "%[^;]; %[^@]", subnets, remainder);
            free(buffer);
            if (rc >=2)
                buffer = strdup(remainder);
            else
                buffer = NULL;

            if (rc >= 1)
                {
                rc = sscanf(subnets, "%s %s", subnet_id, remainder);
                if (rc >= 1)
                    nl->subnets[i].subnet_id = strdup(subnet_id);

                if (rc >= 2)
                    {
                    rc = sscanf(remainder, "%[^ /]/%[^ /]", ip4, mask_bits);

                    if (rc >= 1)
                        {
                        if (rc == 1)
                            {
                            nl->subnets[i].ip4 = strdup(ip4);
                            }
                        else
                            {
                            nl->subnets[i].ip4 = strdup(ip4);
                            nl->subnets[i].mask_bits = atoi(mask_bits);
                            }

                        nl->num_subnets = i+1;
                        }
                    }
                }
            }

         if (buffer)
            free(buffer);
        }

    return 0;
    }


int quantum_net_list_find(quantum_net_list_t *nl, void *arg)
    {
    quantum_net_list_find_t *find = (quantum_net_list_find_t*)arg;
    int found = 0;
    int i;

    find->nl = NULL;
    switch (find->field)
        {
        case qnlf_id:
            found = (nl->id && (0==strcmp(find->target, nl->id)));
            break;

        case qnlf_name:
            found = (nl->name && (0==strcmp(find->target, nl->name)));
            break;

        case qnlf_subnet_id:
            for(i=0; i<nl->num_subnets; i++)
                found = (nl->subnets[i].subnet_id && (0==strcmp(find->target, nl->subnets[i].subnet_id)));

            break;

        case qnlf_ip4:
            for(i=0; i<nl->num_subnets; i++)
                found = (nl->subnets[i].ip4 && (0==strcmp(find->target, nl->subnets[i].ip4)));

            break;

        case qnlf_mask_bits:
            for(i=0; i<nl->num_subnets; i++)
                found = (nl->subnets[i].mask_bits == atoi(find->target));

            break;

        default:
            break;
        }

    if (found)
        {
        find->nl = quantum_net_list_copy(NULL, nl);
        return TRAVERSE_STOP;
        }

    return TRAVERSE_CONTINUE;
    }


int quantum_net_list_traverse(int (*f)(quantum_net_list_t *nl, void *arg), void *arg)
    {
    char buffer[1024];
    char passwd[256];
    quantum_net_list_t nl;
    FILE* file;
    char *s;
    int i=0;
    int rc=0;

    if (get_os_env() <= 0)
        return TRAVERSE_STOPPED;

    rc = get_os_passwd(passwd, sizeof(passwd));
    if (rc < 0)
        return TRAVERSE_STOPPED;

    snprintf(buffer, sizeof(buffer), "neutron --os_password %s net-list", passwd);
    file = popen(buffer, "r");
    while ((s = fgets(buffer, sizeof(buffer), file)))
        {
        i++;
        if ((i<=3) || (s[0] == '+'))
           continue;
        rc = parse_quantum_net_list_line(&nl, s);
        if (!rc)
            {
            rc = f(&nl, arg);
            if (rc == TRAVERSE_STOP)
                {
                quantum_net_list_free(&nl);
                pclose(file);
                return TRAVERSE_STOPPED;
                }
            }
        quantum_net_list_free(&nl);
        }

    pclose(file);
    return TRAVERSE_COMPLETE;
    }

char* quantum_find_id_from_ip4_addr(const char* target)
    {
    quantum_net_list_find_t find;
    int rc;
    char* id;

    find.nl = NULL;
    find.target = target;
    find.field = qnlf_ip4;
    rc = quantum_net_list_traverse(quantum_net_list_find, &find);
    if (rc == TRAVERSE_STOPPED)
        {
        id = strdup(find.nl->id);
        quantum_net_list_free(find.nl);
        free(find.nl);
        return id;
        }
    return NULL;
    }

char* quantum_find_id_from_name(const char* network_name)
    {
    quantum_net_list_find_t find;
    int rc;
    char* id;

    find.nl = NULL;
    find.target = network_name;
    find.field = qnlf_name;
    rc = quantum_net_list_traverse(quantum_net_list_find, &find);
    if (rc == TRAVERSE_STOPPED)
        {
        id = strdup(find.nl->id);
        quantum_net_list_free(find.nl);
        free(find.nl);
        return id;
        }
    return NULL;
    }
