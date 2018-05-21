/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nova_util.h"



void usage()
    {
    printf("Usage:\n");
    printf("nova_util_test [--name <str>] [--instance_name <str>] [--instance_id <str>] [--ip_addr <#.#.#.#>] [--timer <str>]\n");
    printf("\n");
    exit(0);
    }

int main(int argc, char **argv)
    {
    int i;
    int name_idx = 0;
    int instance_name_idx = 0;
    int instance_id_idx = 0;
    int ip_addr_idx = 0;
    int timer_idx = 0;
    nova_timer_t timer_id = nt_unknown;

    char* out = NULL;
    char* name = NULL;
    char* instance_name = NULL;
    char* instance_id = NULL;
    char* ip_addr = NULL;
    char* vm_host = NULL;
    char* network_id = NULL;
    char* timer_name = NULL;

    for(i=1;i<argc;i++)
        {
        if (0==strcmp(argv[i], "--name"))
            {
            i++;
            if (i<argc)
                name_idx = i;
            else
                usage();
            }
        else if (0==strcmp(argv[i], "--instance_name"))
            {
            i++;
            if (i<argc)
                instance_name_idx = i;
            else
                usage();
            }
        else if (0==strcmp(argv[i], "--instance_id"))
            {
            i++;
            if (i<argc)
                instance_id_idx = i;
            else
                usage();
            }
        else if (0==strcmp(argv[i], "--ip_addr"))
            {
            i++;
            if (i<argc)
                ip_addr_idx = i;
            else
                usage();
            }
        else if (0==strcmp(argv[i], "--timer"))
            {
            i++;
            if (i<argc)
                timer_idx = i;
            else
                usage();
            }
        else
            usage();
        }

    if (name_idx)
        name = argv[name_idx];

    if (instance_name_idx)
        instance_name = argv[instance_name_idx];

    if (instance_id_idx)
        instance_id = argv[instance_id_idx];

    if (ip_addr_idx)
        ip_addr = argv[ip_addr_idx];

    if (timer_idx)
        {
        timer_name = argv[timer_idx];
        }

    if (timer_name)
        {
        timer_id = get_nova_timer_id(timer_name);
        if (timer_id != nt_unknown)
            {
            printf("Success: mapped timer_name '%s' to timer_id '%d'.\n", timer_name, timer_id);
            }
        else
            {
            printf("Failed to map timer_name '%s' to a timer_id.\n", timer_name);
            }
        }

    if (timer_id < nt_max)
        {
        out = get_nova_timer_name(timer_id);
        if (out)
            {
            printf("Success: mapped timer_id '%d' to timer_name '%s'.\n", timer_id, out);
            }
        else
            {
            printf("Failed to map timer_id '%d' to an timer_name.\n", timer_id);
            }
        }

   
    if (name)
        {
        out = nova_find_id_from_name(name);
        if (out)
            {
            printf("Success: mapped name '%s' to instance_id '%s'.\n", name, out);
            if (instance_id)
                free(out);
            else
                instance_id = out;
            }
        else
            {
            printf("Failed to map name '%s' to an instance_id.\n", name);
            }
        }

    if (instance_name)
        {
        out = nova_find_id_from_instance_name(instance_name);
        if (out)
            {
            printf("Success: mapped instance_name '%s' to instance_id '%s'.\n", instance_name, out);
            if (instance_id)
                free(out);
            else
                instance_id = out;
            }
        else
            {
            printf("Failed to map instance_name '%s' to an instance_id.\n", instance_name);
            }
        }

    if (ip_addr)
        {
        out = nova_find_id_from_ip_addr(ip_addr);
        if (out)
            {
            printf("Success: mapped ip_addr '%s' to instance_id '%s'.\n", ip_addr, out);
            if (instance_id)
                free(out);
            else
                instance_id = out;
            }
        else
            {
            printf("Failed to map ip_addr '%s' to an instance_id.\n", ip_addr);
            }
        }

    if (instance_id)
        {
        out = nova_find_vm_host_from_id(instance_id);
        if (out)
            {
            printf("Success: mapped instance_id '%s' to vm_host '%s'.\n", instance_id, out);
            if (vm_host)
                free(out);
            else
                vm_host = out;
            }
        else
            {
            printf("Failed to map instance_id '%s' to an instance_id.\n", instance_id);
            }
        }

    if (instance_id)
        {
        out = nova_find_network_id_from_instance_id(instance_id);
        if (out)
            {
            printf("Success: mapped instance_id '%s' to network_id '%s'.\n", instance_id, out);
            if (network_id)
                free(out);
            else
                network_id = out;
            }
        else
            {
            printf("Failed to map instance_id '%s' to an instance_id.\n", instance_id);
            }
        }

    return 0;
    }
