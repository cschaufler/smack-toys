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

#include "smacktools.h"

#define LOCAL_PORT	7001
#define REMOTE_PORT	7000

int
main(int argc, char *argv[])
{
	int sock;
	struct sockaddr_in sin;
	unsigned short local_port = LOCAL_PORT;
	unsigned short remote_port = REMOTE_PORT;
	char buffer[500];
	char *remote_ip_str = THIS_HOST;
	char *cp;
	char *outlabels[20];
	char plabel[SMACK_LABEL];
	int i;
	int oln;
	int outfuzz[20];
	int aln;
	int nap = 1;
	int count = 0;
	int number = -1;
	int olcount = 0;
	int ofuzz = 0;

	if ((i = smack_self(plabel)) < 0) {
		fprintf(stderr, "%s: plabel read failure\n", argv[0]);
		exit(1);
	}
	outfuzz[0] = 0;
	outlabels[0] = plabel;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-c") == 0 ||
		    strcmp(argv[i], "--count") == 0)
			count = 1;
		else if (strcmp(argv[i], "-f") == 0 ||
			 strcmp(argv[i], "--fuzz") == 0)
			ofuzz = atoi(argv[++i]);
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
			 strcmp(argv[i], "--out") == 0) {
			outfuzz[olcount] = 0;
			outlabels[olcount++] = argv[++i];
		} else
			fprintf(stderr, "arg \"%s\" ignored\n", argv[i]);
	}
	 
	if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) { 
		fprintf(stderr, "%s: socket failure %s\n",
			argv[0], strerror(errno));
		exit(1);
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

	for (cp = outlabels[0], oln = 0; number != 0; number--) {
		if (count != 0)
			sprintf(buffer, "%s %d", outlabels[oln], count++);
		else
			sprintf(buffer, "%s", outlabels[oln]);

		aln = strlen(outlabels[oln]) + 1;
		if (ofuzz) {
			if (outfuzz[oln] > ofuzz)
				outfuzz[oln] = 0 - ofuzz;
			else
				outfuzz[oln]++;
			aln += outfuzz[oln];
		}

		i = fsetxattr(sock, ATTR_OUT, outlabels[oln], aln, 0);
		cp = outlabels[oln];
		if (++oln >= olcount)
			oln = 0;
		if (i < 0) {
			fprintf(stderr, "%s: Failed fsetxattr \"%s\" %s\n",
				argv[0], cp, strerror(errno));
		}

		if (ofuzz)
			i = sendto(sock, buffer, aln, 0,
					(struct sockaddr *) &sin, sizeof(sin));
		else
			i = sendto(sock, buffer, strlen(buffer) + 1, 0,
					(struct sockaddr *) &sin, sizeof(sin));

		if (i < 0) {
			fprintf(stderr, "%s: Failed sendto \"%s\" %s\n",
				argv[0], cp, strerror(errno));
		}

		if (nap > 0)
			sleep(nap);
	}

	close(sock);

	return 0;
}
