/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

#ifndef __QUANTUM_UTIL_TYPES_H__
#define __QUANTUM_UTIL_TYPES_H__

/**
*/

typedef enum
    {
    qdalf_id,
    qdalf_host,
    qdalf_admin_state_up,
    qdalf_alive,
    } quantum_dhcp_agent_list_field_t;

typedef struct
    {
    char *id;
    char *host;
    char *admin_state_up;
    char *alive;
    } quantum_dhcp_agent_list_t;

typedef struct
    {
    quantum_dhcp_agent_list_field_t field;
    const char* target;
    quantum_dhcp_agent_list_t *nl;
    } quantum_dhcp_agent_list_find_t;

#define TRAVERSE_STOP 0
#define TRAVERSE_CONTINUE 1

#define TRAVERSE_STOPPED 1
#define TRAVERSE_COMPLETE 0


typedef struct
    {
    char *subnet_id;
    char *ip4;
    int   mask_bits;
    } quantum_subnet_t;

#define QUANTUM_MAX_SUBNETS_PER_NETWORK 5

typedef enum
    {
    qnlf_id,
    qnlf_name,
    qnlf_subnet_id,
    qnlf_ip4,
    qnlf_mask_bits,
    } quantum_net_list_field_t;

typedef struct
    {
    char *id;
    char *name;
    int   num_subnets;
    quantum_subnet_t subnets[QUANTUM_MAX_SUBNETS_PER_NETWORK];
    } quantum_net_list_t;

typedef struct
    {
    quantum_net_list_field_t field;
    const char* target;
    quantum_net_list_t *nl;
    } quantum_net_list_find_t;

#endif  /* __QUANTUM_UTIL_TYPES_H__ */
