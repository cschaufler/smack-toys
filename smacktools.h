/*
 * Copyright (C) 2007 Casey Schaufler <casey@schaufler-ca.com>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 * 
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#define THIS_HOST	"127.0.0.1"
#define THIS_HOST6	"::1"
#define IP_PASSSEC	18
#define SMACK_LABEL	256
#define ATTR_IN		"security.SMACK64IPIN"
#define ATTR_OUT	"security.SMACK64IPOUT"
#define ATTR_EXEC	"security.SMACK64EXEC"

/*
 * This are found in linux/socket.h but the code here
 * needs sys/socket.h and they conflict.
 */
#ifndef SCM_SECURITY
#define SCM_SECURITY	0x03	/* rw: security label */
#endif

static inline int smack_self(char *smack)
{
	int fd;
	int i;
	char *cp;

	fd = open("/proc/self/attr/smack.current", O_RDONLY);
	if (fd < 0)
		fd = open("/proc/self/attr/current", O_RDONLY);
	if (fd < 0)
		return -1;
	i = read(fd, smack, SMACK_LABEL);
	if (i >= 0)
		smack[i] = '\0';
	if ((cp = strchr(smack, '\n')) != NULL)
		*cp = '\0';

	close(fd);
	return i;
}

static inline int smack_get_peer(char *cmd, int sock, char *peer, char *rawpeer)
{
	char raw[SMACK_LABEL * 2];
	int rawlen = sizeof(raw);

	if (getsockopt(sock, SOL_SOCKET, SO_PEERSEC, raw, &rawlen) < 0) {
		fprintf(stderr, "%s getsockopt SO_PEERSEC %s\n", cmd,
			strerror(errno));
		return -1;
	}

	if (rawpeer != NULL)
		strcpy(rawpeer, raw);
	if (sscanf(raw, "smack='%[^']'", peer) != 1)
		strcpy(peer, raw);

	return 0;
}

static inline int smackfs_open(char *entry)
{
	char *path;
	int fd;

	fd = strlen(entry);
	if ((path = calloc(1, fd + 20)) == NULL)
		return -1;

	sprintf(path, "/sys/fs/smackfs/%s", entry);

	if ((fd = open(path, O_RDWR)) >= 0) {
		free(path);
		return fd;
	}
	if ((fd = open(path, O_RDONLY)) >= 0) {
		free(path);
		return fd;
	}

	sprintf(path, "/smack/%s", entry);
	if ((fd = open(path, O_RDWR)) >= 0) {
		free(path);
		return fd;
	}
	if ((fd = open(path, O_RDONLY)) >= 0) {
		free(path);
		return fd;
	}

	sprintf(path, "/sys/fs/smack/%s", entry);
	if ((fd = open(path, O_RDWR)) >= 0) {
		free(path);
		return fd;
	}
	if ((fd = open(path, O_RDONLY)) >= 0) {
		free(path);
		return fd;
	}

	sprintf(path, "/proc/self/attr/%s", entry);
	if ((fd = open(path, O_RDWR)) >= 0) {
		free(path);
		return fd;
	}
	if ((fd = open(path, O_RDONLY)) >= 0) {
		free(path);
		return fd;
	}
	free(path);
	return -1;
}

