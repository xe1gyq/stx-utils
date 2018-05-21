/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

#ifndef __ATOMIC_H__
#define __ATOMIC_H__

/**
*/

#include "atomic_types.h"

#define ATOMIC_TEST_AND_SET_IF_EQ(p, o, n) \
    atomic_test_and_set_if_eq((atomic_type*)(p), (atomic_type)(o), (atomic_type)(n))

extern atomic_type atomic_test_and_set_if_eq(atomic_type *p, 
                                             atomic_type  old,
                                             atomic_type  new);


#endif /*__ATOMIC_H__ */
