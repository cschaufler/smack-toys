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

#define BUFFER_SIZE 500

#define LOCAL_PORT	7000

int
main(int argc, char *argv[])
{
	int sock;
	struct sockaddr_in sin;
	unsigned short local_port = LOCAL_PORT;
	struct iphdr *ip_header;
	struct udphdr *udp_header;
	int tmp;
	int len;
	int i;
	int oadd;
	unsigned char *oap = (unsigned char *)&oadd;
	char peer[SMACK_LABEL];
	char cpeer[SMACK_LABEL];
	char rpeer[SMACK_LABEL];
	char callno[SMACK_LABEL];
	char from[SMACK_LABEL];
	char *ipin = NULL;
	int quiet = 0;
	int special;
	int right = 1;
	int isone = 1;
	char buffer[BUFFER_SIZE];
	char control[BUFFER_SIZE];
	struct iovec iov = { buffer, sizeof(buffer) };
	struct msghdr message = {
		(void*)&sin, sizeof(sin), &iov, 1, control, BUFFER_SIZE, 0
	};

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-i") == 0 ||
		    strcmp(argv[i], "--ipin") == 0)
			ipin = argv[++i];
		if (strcmp(argv[i], "-p") == 0 ||
		    strcmp(argv[i], "--port") == 0)
			local_port = atoi(argv[++i]);
		if (strcmp(argv[i], "-q") == 0 ||
		    strcmp(argv[i], "--quiet") == 0)
			quiet = 1;
	}

	if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) { 
		fprintf(stderr, "%s: socket failure %s\n",
			argv[0], strerror(errno));
		exit(1);
	}

	bzero((char *)&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(local_port);

	if (bind(sock, (struct sockaddr *)& sin, sizeof(sin)) < 0) {
		fprintf(stderr, "%s: bind failure %s\n",
			argv[0], strerror(errno));
		exit(1);
	}

        if (setsockopt(sock, SOL_IP, IP_PASSSEC, &isone, sizeof(isone)) < 0) {
		fprintf(stderr, "%s: setsockopt IP_PASSEC failure %s\n",
			argv[0], strerror(errno));
		exit(1);
	}
  
	if (ipin != NULL) {
		tmp = fsetxattr(sock, ATTR_IN, ipin, strlen(ipin)+1, 0);
		if (tmp < 0)
			fprintf(stderr, "%s: fsetxattr failure %s\n",
				argv[0], strerror(errno));
		else
			printf("security.SMACK64IPIN set = %d\n", tmp);
	}

	while ( 1 ) {
		len = sizeof(sin);
		bzero((char *)&sin, sizeof(sin));
		bzero(buffer, BUFFER_SIZE);
		bzero(control, BUFFER_SIZE);
		special = 0;

		message.msg_namelen = sizeof(sin);
		message.msg_controllen = BUFFER_SIZE;

		strcpy(peer, "UNAVAILABLE");
		smack_get_peer(argv[0], sock, cpeer, rpeer);
		i = smackrecvmsg(argv[0], sock, &message, 0, peer,
					sizeof(peer));

		i = strlen(peer);
		if (strncmp(buffer, peer, i) != 0)
			special = 1;
		else if (buffer[i] != ' ' && buffer[i] != '\0')
			special = 1;

		if (quiet == 0 || special != 0) {
			oadd = sin.sin_addr.s_addr;
			printf("From %u.%u.%u.%u port %d %d \"%s\" "
			       "peer = \"%s\" (\"%s\" \"%s\")"
			       "right %d\n",
				oap[0], oap[1], oap[2], oap[3],
				ntohs(sin.sin_port), i, buffer, peer,
				cpeer, rpeer, right);
		}
		if (special != 0)
			right = 0;
		else
			right++;
	}

	close(sock);

	return 0;
}
