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

#define BUFFER_SIZE	2000

#define THIS_HOST	"127.0.0.1"
#define ATTR_IN		"security.SMACK64IPIN"
#define ATTR_OUT	"security.SMACK64IPOUT"

/*
 * A peer can be either a client or a server.
 */
struct peer {
	struct peer	*next;		/* in the list */
	char		*smack;		/* Smack label */
	int		port;		/* TCP port */
	int		socket;		/* The socket */
};

struct peer *peer_list;

struct peer *alloc_peer(char *smack, int port, int socket, int list)
{
	struct peer *result;

	result = malloc(sizeof(struct peer));
	if (result == NULL)
		return NULL;

	result->smack = strdup(smack ? smack : "");
	result->port = port;
	result->socket = socket;
	if (list) {
		result->next = peer_list;
		peer_list = result;
	} else
		result->next = NULL;

	return result;
}

struct peer *find_server(char *smack)
{
	struct peer *pp;

	for (pp = peer_list; pp != NULL; pp = pp->next)
		if (strcmp(pp->smack, smack) == 0)
			break;

	return pp;
}

int main(int argc, char *argv[])
{
	struct peer *client = NULL;
	struct peer *master = NULL;
	struct peer *server = NULL;
	struct sockaddr_in sin;
	char cbuff[BUFFER_SIZE];
	char sbuff[BUFFER_SIZE];
	char *serverhost = THIS_HOST;
	char *cp;
	int verbose = 0;
	int len;
	int i;
	int cpn;
	int spn;
	int slen;
	int star_socket;	/* for listening */
	int nsock;		/* for select */
	fd_set sockset;		/* for select */

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-c") == 0 ||
		    strcmp(argv[i], "--client") == 0 ||
		    strcmp(argv[i], "--clientport") == 0) {
			if (client != NULL) {
				fprintf(stderr,
					"%s: multiple client port \"%s\""
					" invalid\n", argv[0], argv[i]);
				exit(1);
			}
			i++;
			client = alloc_peer(NULL, atoi(argv[i]), -1, 0);
		}
		else if (strcmp(argv[i], "-m") == 0 ||
			 strcmp(argv[i], "--master") == 0 ||
			 strcmp(argv[i], "--masterserver") == 0) {
			i++;
			cp = strchr(argv[i], ':');
			if (cp == NULL) {
				fprintf(stderr, "%s: master \"%s\" invalid\n",
					argv[0], argv[i]);
				exit(1);
			}
			cp++;
			if (strlen(cp) < 1) {
				fprintf(stderr, "%s: master \"%s\" invalid\n",
					argv[0], argv[i]);
				exit(1);
			}
			master = alloc_peer(cp, atoi(argv[i]), -1, 0);
		}
		else if (strcmp(argv[i], "-s") == 0 ||
			 strcmp(argv[i], "--server") == 0 ||
			 strcmp(argv[i], "--smack") == 0 ||
			 strcmp(argv[i], "--serversmack") == 0) {
			i++;
			cp = strchr(argv[i], ':');
			if (cp == NULL) {
				fprintf(stderr, "%s: server \"%s\" invalid\n",
					argv[0], argv[i]);
				exit(1);
			}
			cp++;
			if (strlen(cp) < 1) {
				fprintf(stderr, "%s: server \"%s\" invalid\n",
					argv[i], argv[0]);
				exit(1);
			}
			alloc_peer(cp, atoi(argv[i]), -1, 1);
		}
		else if (strcmp(argv[i], "-h") == 0 ||
			 strcmp(argv[i], "--host") == 0 ||
			 strcmp(argv[i], "--serverhost") == 0) {
			serverhost = argv[++i];
		}
		else if (strcmp(argv[i], "-v") == 0 ||
			 strcmp(argv[i], "--verbose") == 0) {
			verbose = 1;
		}
	}

	if (client == NULL) {
		fprintf(stderr, "%s: client port not specified\n", argv[0]);
		exit(1);
	}
	if (master == NULL && peer_list == NULL) {
		fprintf(stderr, "%s: server data not specified\n",
			argv[0]);
		exit(1);
	}

	/*
	 * Create the service socket for clients to connect to.
	 */
	if ((star_socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) { 
		perror("listen socket");
		exit(1);
	}

	sin.sin_family = AF_INET;
	sin.sin_port = htons(client->port);
	sin.sin_addr.s_addr = INADDR_ANY;

	if (bind(star_socket, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("listen bind");
		exit(1);
	}

	/*
	 * Give the service socket the star label, allowing anyone
	 * to talk to it.
	 */
	if (fsetxattr(star_socket, ATTR_IN, "*", 2, 0) < 0) {
		perror("listen fsetxattr");
		exit(1);
	}

	/*
	 * Main loop. Accept incoming requests and dispatch clildren
	 * to service them.
	 */
	for (;;) {
		if (listen(star_socket, 0) < 0) {
			perror("listen");
			exit(1);
		}

		len = sizeof(sin);
		client->socket = accept(star_socket, (struct sockaddr *)&sin,
					&len);
		if (client->socket < 0) {
			perror("accept");
			exit(1);
		}

		/*
		 * Get the Smack label from the other end and
		 * apply it to the new socket.
		 */
		len = SMACK_LABEL;
		if (smack_get_peer(argv[0], client->socket, client->smack,
					NULL) < 0)
			exit(1);

		slen = strlen(client->smack) + 1;
		if (fsetxattr(client->socket, ATTR_IN,
				client->smack, slen, 0) < 0) {
			perror("client fsetxattr");
			exit(1);
		}
		if (fsetxattr(client->socket, ATTR_OUT,
				client->smack, slen, 0) < 0) {
			perror("client fsetxattr");
			exit(1);
		}

		/*
		 * Find the right server for this client's label
		 */
		server = find_server(client->smack);
		if (server == NULL)
			server = master;
		if (server == NULL) {
			fprintf(stderr, "No server available at \"%s\"\n",
				client->smack);
			close(client->socket);
			continue;
		}

		/*
		 * Child does work, parent goes to listen some more
		 */
		if (fork() == 0) {
			close(star_socket);
			break;
		}
		/*
		 * This is the parent and the parent no longer
		 * cares about this socket, having passed it off
		 * for the child to take care of
		 */
		close(client->socket);
	}

	/*
	 * Only children ever get here.
	 */
	slen = strlen(client->smack) + 1;
	if ((server->socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) { 
		perror("server socket");
		exit(1);
	}

	/*
	 * Set the socket labels to match that of the server
	 * to ensure communications. This requires CAP_MAC_ADMIN.
	 */
	if (fsetxattr(server->socket, ATTR_IN, server->smack, slen, 0) < 0) {
		perror("server fsetxattr");
		exit(1);
	}

	if (fsetxattr(server->socket, ATTR_OUT, server->smack, slen, 0) < 0) {
		perror("server fsetxattr");
		exit(1);
	}

	bzero((char *)&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(server->port);
	sin.sin_addr.s_addr = inet_addr(serverhost);

	if (connect(server->socket, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("server connect");
		exit(1);
	}

	if (client->socket > server->socket)
		nsock = client->socket + 1;
	else
		nsock = server->socket + 1;

	for (;;) {
		FD_ZERO(&sockset);
		FD_SET(client->socket, &sockset);
		FD_SET(server->socket, &sockset);
		i = select(nsock, &sockset, NULL, NULL, NULL);
		if (i < 0) {
			perror("select");
			break;
		}
		if (verbose)
			fprintf(stderr, "selected %d\n", i);

		cpn = 0;
		spn = 0;
		if (FD_ISSET(client->socket, &sockset)) {
			cpn = read(client->socket, cbuff, BUFFER_SIZE);
			if (verbose)
				fprintf(stderr, "read %d from client\n", cpn);
		}
		if (FD_ISSET(server->socket, &sockset)) {
			spn = read(server->socket, sbuff, BUFFER_SIZE);
			if (verbose)
				fprintf(stderr, "read %d from server\n", spn);
		}

		if (cpn > 0) {
			i = send(server->socket, cbuff, cpn, 0);
			if (verbose)
				fprintf(stderr, "wrote %d to server\n", i);
		}
		if (spn > 0) {
			i = send(client->socket, sbuff, spn, 0);
			if (verbose)
				fprintf(stderr, "wrote %d to client\n", i);
		}

		if (cpn <= 0 && spn <= 0)
			break;
	}
	close(client->socket);
	close(server->socket);

	exit(0);
}
