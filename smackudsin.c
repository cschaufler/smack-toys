/*
 * Copyright (C) 2016 Casey Schaufler <casey@schaufler-ca.com>
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
#include <linux/un.h>
#include <linux/udp.h>
#include <linux/netlink.h>
#include <linux/xattr.h>

#include "smacktools.h"
#include "smackrecvmsg.h"

#define BUFFER_SIZE 500

int
main(int argc, char *argv[])
{
	int sock;
	struct sockaddr_un sun;
	char *path = "/tmp/testsmackuds";
	struct iphdr *ip_header;
	struct udphdr *udp_header;
	int tmp;
	int len;
	int i;
	int oadd;
	unsigned char *oap = (unsigned char *)&oadd;
	char peer[SMACK_LABEL];
	char callno[SMACK_LABEL];
	char from[SMACK_LABEL];
	char *ipin = NULL;
	int quiet = 0;
	int special;
	int right = 1;
	int one = 1;
	char buffer[BUFFER_SIZE];
	char control[BUFFER_SIZE];
	struct iovec iov = { buffer, sizeof(buffer) };
	struct msghdr message = {
		(void*)&sun, sizeof(sun), &iov, 1, control, BUFFER_SIZE, 0
	};

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-i") == 0 ||
		    strcmp(argv[i], "--ipin") == 0)
			ipin = argv[++i];
		if (strcmp(argv[i], "-p") == 0 ||
		    strcmp(argv[i], "--path") == 0)
			path = argv[++i];
		if (strcmp(argv[i], "-q") == 0 ||
		    strcmp(argv[i], "--quiet") == 0)
			quiet = 1;
	}

	if ((sock = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0) { 
		perror("socket");
		exit(1);
	}

	bzero((char *)&sun, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strcpy(sun.sun_path, path);

	unlink(path);

	if (bind(sock, (struct sockaddr *)& sun, sizeof(sun)) < 0) {
		perror("bind");
		exit(1);
	}

	chmod(path, 0777);

        if (setsockopt(sock, SOL_SOCKET, SO_PASSSEC, &one, sizeof(one)) < 0) {
		perror("setsockopt IP_PASSEC");
		exit(1);
	}
  
	if (ipin != NULL) {
		tmp = fsetxattr(sock, "security.SMACK64IPIN",
				ipin, strlen(ipin)+1, 0);
		if (tmp < 0)
			perror("fsetxattr");
		else
			printf("security.SMACK64IPIN set = %d\n", tmp);
	}

	while ( 1 ) {
		len = sizeof(sun);
		bzero((char *)&sun, sizeof(sun));
		bzero(buffer, BUFFER_SIZE);
		bzero(control, BUFFER_SIZE);
		special = 0;

		message.msg_namelen = sizeof(sun);
		message.msg_controllen = BUFFER_SIZE;

		strcpy(peer, "UNAVAILABLE");
		i = smackrecvmsg(argv[0], sock, &message, 0, peer,
					sizeof(peer));
		if (i < 0)
			fprintf(stderr, "%s:%d smackrecvmsg failed\n",
				__func__, __LINE__);

		i = strlen(peer);
		if (strncmp(buffer, peer, i) != 0)
			special = 1;
		else if (buffer[i] != ' ' && buffer[i] != '\0')
			special = 1;

		if (quiet == 0 || special != 0) {
			printf("Read \"%s\" peer = \"%s\" right %d\n",
				buffer, peer, right);
		}
		if (special != 0)
			right = 0;
		else
			right++;
	}

	close(sock);

	return 0;
}
