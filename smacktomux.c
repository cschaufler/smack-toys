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
#include "smacktools.h"

#define BUFFER_SIZE 1500
#define RBS (BUFFER_SIZE - ((sizeof (struct iphdr) + sizeof (struct udphdr))))

#define LOCAL_PORT	8001
#define REMOTE_PORT	8000

int
main(int argc, char *argv[])
{
	int sock;
	struct sockaddr_in sin;
	unsigned short local_port = LOCAL_PORT;
	unsigned short remote_port = REMOTE_PORT;
	char buffer[BUFFER_SIZE];
	char rbuffer[BUFFER_SIZE];
	char *remote_ip_str = THIS_HOST;
	char *cp;
	char *olabel = NULL;
	int i;
	int sent;
	int reply = 0;
	int replies = 0;
	int nap = 1;
	int count = 0;
	int number = -1;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-c") == 0 ||
		    strcmp(argv[i], "--count") == 0)
			count = 1;
		else if (strcmp(argv[i], "-h") == 0 ||
		    strcmp(argv[i], "--host") == 0)
			remote_ip_str = argv[++i];
		else if (strcmp(argv[i], "-p") == 0 ||
			 strcmp(argv[i], "--port") == 0)
			remote_port = atoi(argv[++i]);
		else if (strcmp(argv[i], "-s") == 0 ||
			 strcmp(argv[i], "--sleep") == 0)
			nap = atoi(argv[++i]);
		else if (strcmp(argv[i], "-n") == 0 ||
			 strcmp(argv[i], "--number") == 0)
			number = atoi(argv[++i]);
		else if (strcmp(argv[i], "-o") == 0 ||
			 strcmp(argv[i], "--out") == 0)
			olabel = argv[++i];
		else if (strcmp(argv[i], "-r") == 0 ||
		    strcmp(argv[i], "--reply") == 0) {
			reply = 1;
		}
		else
			fprintf(stderr, "arg \"%s\" ignored\n", argv[i]);
	}
	 
	if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) { 
		perror("socket");
		exit(1);
	}

	if (olabel != NULL) {
		i = fsetxattr(sock, "security.SMACK64IPOUT", olabel,
			strlen(olabel) + 1, 0);
		if (i < 0) {
			perror("Setting output Smack label");
			exit(1);
		}
		i = fsetxattr(sock, "security.SMACK64IPIN", olabel,
			strlen(olabel) + 1, 0);
		if (i < 0) {
			perror("Setting input Smack label");
			exit(1);
		}
	}

	bzero((char *)&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(local_port);

	for (i = 0; i < 1000; i++) {
		if ((bind(sock, (struct sockaddr *)&sin, sizeof(sin))) >= 0)
			break;
		sin.sin_port = htons(local_port++);
	}

	if (i >= 1000) {
		fprintf(stderr, "failed 1000 binds\n");
		exit(1);
	}

	bzero((char *)&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(remote_port);
	sin.sin_addr.s_addr = inet_addr(remote_ip_str);

	if (connect(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("connect");
		exit(1);
	}
  
	if (olabel != NULL) {
		strcpy(buffer, olabel);
		i = strlen(buffer);
	} else if ((i = smack_self(buffer)) < 0) {
		fprintf(stderr, "Cannot read process Smack label.\n");
		exit(1);
	}
	cp = buffer + i;

	for (; number != 0; number--) {
		if (count != 0)
			sprintf(cp, " %d", count++);
		sent = strlen(buffer) + 1;
		if (send(sock, buffer, sent, 0) < 0)
			perror("send");
		if (reply != 0) {
			rbuffer[0] = '\0';
			i = read(sock, rbuffer, RBS);
			if (i >= 0)
				rbuffer[i] = '\0';
			if (i <= sent && strcmp(buffer, rbuffer) == 0) {
				replies++;
				printf("Reply: \"%s\", %d right %d\n",
					rbuffer, i, replies);
			} else {
				printf("Reply: \"%s\" isn't \"%s\", %d %d\n",
					rbuffer, buffer, sent, i);
			}
		}

		if (nap > 0)
			sleep(nap);
	}

	close(sock);

	return 0;
}
