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
#include <sys/un.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include "smacktools.h"

int
main(int argc, char *argv[])
{
	int sock;
	struct sockaddr_un sun;
	char buffer[500];
	char *path = "/tmp/testsmackuds";
	char *cp;
	char *outlabels[20];
	char plabel[SMACK_LABEL];
	int i;
	int oln;
	int nap = 1;
	int count = 0;
	int number = -1;
	int olcount = 0;

	oln = open("/proc/self/attr/smack.current", O_RDONLY);
	if (oln < 0)
		oln = open("/smack/current", O_RDONLY);
	if (oln < 0)
		oln = open("/proc/self/attr/current", O_RDONLY);
	i = read(oln, plabel, SMACK_LABEL);
	close(oln);
	plabel[i] = '\0';
	if ((cp = strchr(plabel, '\n')) != NULL)
		*cp = '\0';
	outlabels[0] = plabel;
	/*
	 *	fprintf(stderr, "plabel \"%s\"\n", plabel);
	 */

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-c") == 0 ||
		    strcmp(argv[i], "--count") == 0)
			count = 1;
		else if (strcmp(argv[i], "-s") == 0 ||
			 strcmp(argv[i], "--sleep") == 0)
			nap = atoi(argv[++i]);
		else if (strcmp(argv[i], "-n") == 0 ||
			 strcmp(argv[i], "--number") == 0)
			number = atoi(argv[++i]);
		else if (strcmp(argv[i], "-o") == 0 ||
			 strcmp(argv[i], "--out") == 0)
			outlabels[olcount++] = argv[++i];
		else if (strcmp(argv[i], "-p") == 0 ||
			 strcmp(argv[i], "--path") == 0)
			path = argv[++i];
		else
			fprintf(stderr, "arg \"%s\" ignored\n", argv[i]);
	}
	 
	if ((sock = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) { 
		perror("socket");
		exit(1);
	}

	sun.sun_family = AF_UNIX;
	strcpy(sun.sun_path, path);

	for (cp = outlabels[0], oln = 0; number != 0; number--) {
		if (count != 0)
			sprintf(buffer, "%s %d", outlabels[oln], count++);
		else
			sprintf(buffer, "%s", outlabels[oln]);

		if (olcount > 0) {
			i = fsetxattr(sock, "security.SMACK64IPOUT",
				outlabels[oln], strlen(outlabels[oln])+1, 0);
			cp = outlabels[oln];
			if (++oln >= olcount)
				oln = 0;
			if (i < 0) {
				fprintf(stderr, "Failed \"%s\" ", cp);
				perror("fsetxattr");
			}
		}
			
		if (sendto(sock, buffer, strlen(buffer) + 1, 0, 
			   (struct sockaddr *) &sun, sizeof(sun)) < 0) {
			fprintf(stderr, "Failed \"%s\" ", cp);
			perror("sendto");
		}

		if (nap > 0)
			sleep(nap);
	}

	close(sock);

	return 0;
}
