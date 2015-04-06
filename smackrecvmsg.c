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
 * Authors:
 *	Casey Schaufler <casey@schaufler-ca.com>
 *	Ahmed S. Darwish <darwish.07@gmail.com>
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "smacktools.h"

int smackrecvmsg(char *cmd, int sock, struct msghdr *msgp, int flags,
		 char *smack, int smacklen)
{
	struct cmsghdr *chp;
	char *cp;
	int len;
	int rc;

	rc = recvmsg(sock, msgp, flags);
	if (rc < 0) {
		fprintf(stderr, "%s: recvmsg error %s\n", cmd, strerror(errno));
		return -1;
	}
	if (msgp->msg_controllen <= sizeof(struct cmsghdr)) {
		fprintf(stderr, "%s %s out of control %ld <= %lu\n",
			cmd, __func__, msgp->msg_controllen,
			sizeof(struct cmsghdr));
		return -1;
	}
	chp = CMSG_FIRSTHDR(msgp);
	if (chp->cmsg_type != SCM_SECURITY) {
		fprintf(stderr, "%s type not SCM_SECURITY\n", __func__);
		return -1;
	}
	cp = (char *) CMSG_DATA(chp);
	len = chp->cmsg_len - (cp - (char *)chp);
	if (len < 1) {
		fprintf(stderr, "%s cmsg_len %d too small\n", __func__,
			(int)chp->cmsg_len);
		return -1;
	}
	if (strlen(cp) != len) {
		fprintf(stderr, "%s len %d not strlen %d \"%s\"\n", __func__,
			len, (int)strlen(cp), cp);
		return -1;
	}
	if (strlen(cp) >= smacklen) {
		fprintf(stderr, "%s len %d too small, smack is %d\n", __func__,
			smacklen, (int)strlen(cp));
		return -1;
	}
	if (chp->cmsg_len >= smacklen) {
		fprintf(stderr, "%s len %d too small, needed %d\n", __func__,
			smacklen, (int)chp->cmsg_len);
		return -1;
	}
	strcpy(smack, cp);
	return 0;
}
