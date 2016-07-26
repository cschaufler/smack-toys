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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "smacktools.h"

#define MAXARGS 256

int main(int argc, char *argv[])
{
	int i;
	int fd;
	int smacklen;
	int newargc;
	char *newargv[MAXARGS];
	char *selfish1 = "/proc/self/attr/smack/current";
	char *selfish2 = "/proc/self/attr/current";
	char *smack;

	if (argc <= 1) {
		fprintf(stderr, "%s: No Smack value specified\n", argv[0]);
		exit(1);
	}
	if (argc > MAXARGS) {
		fprintf(stderr, "%s: Too many arguments specified\n", argv[0]);
		exit(1);
	}

	smack = argv[1];
	smacklen = strlen(smack);

	if (smacklen >= SMACK_LABEL || smacklen < 1) {
		fprintf(stderr, "%s: Bad Smack value \"%s\" specified\n",
			argv[0], smack);
		exit(1);
	}

	/*
	 * Start a shell if no command is specified
	 */
	if (argc == 1) {
		fprintf(stderr, "%s: Starting a shell at \"%s\"\n",
			argv[0], smack);
		newargv[0] = "sh";
		newargv[1] = NULL;
	} else {
		for (i = 2; i < argc; i++)
			newargv[i - 2] = argv[i];
		newargv[i - 2] = NULL;
	}

	/*
	 * Set the process label.
	 */
	if ((fd = open(selfish1, O_RDWR)) < 0 &&
	    (fd = open(selfish2, O_RDWR)) < 0) {
		fprintf(stderr, "%s: cannot open to set smack\n", argv[0]);
		exit(1);
	}
	if (write(fd, smack, smacklen) < 0) {
		fprintf(stderr, "%s: cannot write to set smack\n", argv[0]);
		exit(1);
	}
	close(fd);
	/*
	 * Do the exec
	 */
	execvp(newargv[0], newargv);

	fprintf(stderr, "%s: exec failure.\n", argv[0]);
	exit(0);
}
