/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

#include "heartbeat_macro.h"
#include "heartbeat_message.h"
#include "heartbeat_types.h"
#include "heartbeat_common.h"
#include "network_namespace.h"
#include "heartbeat_poll.h"

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

const char* guest_virtio_file = HEARTBEAT_VIRTIO_FILE;

vio_data_t vio_data;

int vio_client_init(hb_client_t *client)
{
    const char* fn;

    fn = guest_virtio_file;
    client->vio_fd = open(fn, O_RDWR | O_NONBLOCK);
    if (client->vio_fd < 0)
    {
        PRINT_ERR("Error opening filedesc for '%s': %s\n", guest_virtio_file, strerror(errno));
        return -1;
    }

    fcntl(client->vio_fd, F_SETFD, fcntl(client->vio_fd, F_GETFD) | FD_CLOEXEC);
    vio_data.client = client;

    PRINT_INFO("Connection accepted to '%s', fd = %d\n", fn, client->vio_fd);

    return 0;
}
