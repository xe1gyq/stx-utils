/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

#ifndef __NOVA_UTIL_TYPES_H__
#define __NOVA_UTIL_TYPES_H__

/**
*/

#define NOVA_MAX_NETWORKS 5
#define NOVA_MAX_IPS 5

typedef struct
    {
    char *network_name;
    int   num_ips;
    char *ip[NOVA_MAX_IPS];
    } nova_network_t;

typedef enum
    {
    nlf_id,
    nlf_name,
    nlf_inst_name,
    nlf_vm_host,
    nlf_status,
    nlf_network_name,
    nlf_ip,
    } nova_list_field_t;

typedef struct
    {
    char *id;          // 6add27d8-3520-417c-ac4c-2a8e63993b4c
    char *name;        // my_cloud
    char *inst_name;   // instance-00000004
    char *vm_host;
    char *status;
    int   num_networks;
    nova_network_t networks[NOVA_MAX_NETWORKS];
    } nova_list_t;

typedef struct
    {
    nova_list_field_t field;
    const char* target;
    nova_list_t *nl;
    } nova_find_t;

typedef enum
    {
    traverse_stop,
    traverse_continue
    } traverse_func_return_t; 

typedef enum
    {
    traverse_complete,
    traverse_stopped
    } traverse_return_t;

typedef enum
    {
    nt_unknown,
    nt_first_hb,
    nt_hb_interval,
    nt_vote,
    nt_shutdown_notice,
    nt_suspend_notice,
    nt_resume_notice,
    nt_downscale_notice,
    nt_restart,
    nt_max
    } nova_timer_t;

#endif /* __NOVA_UTIL_TYPES_H__ */
