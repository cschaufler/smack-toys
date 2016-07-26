/*
 * Copyright (C) 2012 Casey Schaufler <casey@schaufler-ca.com>
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/netlink.h>
#include <linux/xattr.h>
#include "smacktools.h"

#define BUFFER_SIZE	2000
#define LOCAL_PORT	8000

int
main(int argc, char *argv[])
{
	int firstsock;
	int sock;
	struct sockaddr_in sin;
	unsigned short local_port = LOCAL_PORT;
	int len;
	int i;
	int oadd;
	unsigned char *oap = (unsigned char *)&oadd;
	char peer[SMACK_LABEL];
	char rawpeer[SMACK_LABEL];
	char callno[SMACK_LABEL];
	char from[SMACK_LABEL];
	int quiet = 0;
	int special;
	int isone = 1;
	char buffer[BUFFER_SIZE];
	char control[BUFFER_SIZE];
	struct iovec iov = { buffer, sizeof(buffer) };
	struct msghdr message = {
		(void*)&sin, sizeof(sin), &iov, 1, control, BUFFER_SIZE, 0
	};

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-p") == 0 ||
		    strcmp(argv[i], "--port") == 0)
			local_port = atoi(argv[++i]);
		if (strcmp(argv[i], "-q") == 0 ||
		    strcmp(argv[i], "--quiet") == 0)
			quiet = 1;
	}

	if ((firstsock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) { 
		perror("socket");
		exit(1);
	}

	bzero((char *)&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(local_port);
	sin.sin_addr.s_addr = INADDR_ANY;

	if (bind(firstsock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("bind");
		exit(1);
	}

	while ( 1 ) {
		if (listen(firstsock, 0) < 0) {
			perror("listen");
			exit(1);
		}

		len = sizeof(sin);
		if ((sock = accept(firstsock, (struct sockaddr *)&sin,
				   &len)) < 0) {
			perror("accept");
			exit(1);
		}

		i = smack_get_peer(argv[0], sock, peer, rawpeer);
		len = sizeof(peer);
		if (i < 0)
			exit(1);

		if (fork() == 0) {
			close(firstsock);
			break;
		}
		close(sock);
	}

	while ( 1 ) {
		bzero((char *)&sin, sizeof(sin));
		bzero(buffer, BUFFER_SIZE);
		bzero(control, BUFFER_SIZE);
		special = 0;

		message.msg_namelen = sizeof(sin);
		message.msg_controllen = BUFFER_SIZE;

		i = recvmsg(sock, &message, 0);
		if (i < 0) {
			fprintf(stderr, "%s:%d recvmsg failed\n",
				__func__, __LINE__);
			break;
		}
		if (i == 0) {
			fprintf(stderr, "%s:%d recvmsg returned 0\n",
				__func__, __LINE__);
			break;
		}

		len = strlen(peer);
		if (strncmp(buffer, peer, len) != 0)
			special = 1;
		else if (buffer[len] != ' ' && buffer[len] != '\0')
			special = 1;

		if (quiet == 0 || special != 0) {
			oadd = sin.sin_addr.s_addr;
			printf("From %u.%u.%u.%u port %d %d \"%s\" "
			       "peer = \"%s\" (\"%s\")\n",
				oap[0], oap[1], oap[2], oap[3],
				ntohs(sin.sin_port), len, buffer,
				peer, rawpeer);
		}

		i = write(sock, peer, len);
		if (i != len) {
			fprintf(stderr, "%s:%d write returned %d\n",
				__func__, __LINE__, i);
		}
	}

	close(sock);

	return 0;
}
