/*
 * smackspeedtest - provide a relative smack speed impact number
 *
 * Copyright (C) 2007 Casey Schaufler <casey@schaufler-ca.com>
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
 *
 * Authors:
 *      Casey Schaufler <casey@schaufler-ca.com>
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define LLSIZE 255
#define LSIZE 23
#define ASIZE 5

#define WRITE_LONG (LLSIZE + LLSIZE + ASIZE + 2)
#define WRITE_NEW (LSIZE + LSIZE + ASIZE + 2)
#define WRITE_OLD (WRITE_NEW - 1)

#define SPEEDS 200
#define WHERE "/tmp/smack-speed-test"
#define LFIX "com.smack-laboritories-duty-now-for-the-future"
#define SMACKX "security.SMACK64"

int writeload(void)
{
	int loadfd;
	char rule[WRITE_NEW + 1];
	int sub;
	int obj;
	int err;
	int writesize = WRITE_NEW;

	loadfd = open("/sys/fs/smackfs/load", O_RDWR);
	if (loadfd < 0)
		loadfd = open("/smack/load", O_RDWR);
	if (loadfd < 0) {
		perror("opening rules list");
		return -1;
	}

	for (sub = 1; sub <= SPEEDS; sub++) {
		for (obj = 1; obj <= SPEEDS; obj++) {
			if (sub == obj)
				continue;
			if (sub == obj + 1)
				sprintf(rule, "speed-%-17d speed-%-17d rwxa-\n",
					sub, obj);
			else
				sprintf(rule, "speed-%-17d speed-%-17d -----\n",
					sub, obj);

			err = write(loadfd, rule, writesize);
			if (err == writesize)
				continue;

			if (err == -1 && errno == EINVAL &&
			    writesize == WRITE_NEW) {
				writesize = WRITE_OLD;
				err = write(loadfd, rule, writesize);
				if (err == writesize)
					continue;
			}
			perror("writing rules list (load)");
			exit(1);
		}
	}

	close(loadfd);
	return 0;
}

int writeload2(void)
{
	int fd;
	int sub;
	int obj;
	int err;
	int writesize;
	char *rule;

	rule = malloc(WRITE_LONG);
	if (rule == NULL) {
		perror("allocating buffer");
		return -1;
	}
	fd = open("/sys/fs/smackfs/load2", O_RDWR);
	if (fd < 0)
		fd = open("/smack/load2", O_RDWR);
	if (fd < 0) {
		perror("opening rules list (load2)");
		return -1;
	}

	for (sub = 1; sub <= SPEEDS; sub++) {
		for (obj = 1; obj <= SPEEDS; obj++) {
			if (sub == obj)
				continue;
			if (sub == obj + 1)
				sprintf(rule, LFIX "-%d " LFIX "-%d rwxa-\n",
					sub, obj);
			else
				sprintf(rule, LFIX "-%d " LFIX "-%d -----\n",
					sub, obj);

			writesize = strlen(rule);
			err = write(fd, rule, writesize);
			if (err != writesize) {
				perror("writing rules list (load2)");
				exit(1);
			}
		}
	}

	close(fd);
	return 0;
}

int main(int argc, char *argv[])
{
	struct timeval start_time;
	struct timeval end_time;
	struct stat buf;
	char runlabel[256];
	char label[256];
	char path[256];
	char *cp;
	int sub;
	int obj;
	int cfd;
	int rc;
	int i;

	cfd = open("/proc/self/attr/smack/current", O_RDWR);
	if (cfd < 0)
		cfd = open("/proc/self/attr/current", O_RDWR);
	if (cfd < 0)
		perror("Preparing to read Smack label");
	rc = read(cfd, runlabel, sizeof(runlabel));
	runlabel[rc] = '\0';
	if ((cp = strchr(runlabel, '\n')) != NULL)
		*cp = '\0';
	close(cfd);

	cfd = open("/proc/self/attr/smack/current", O_RDWR);
	if (cfd < 0)
		cfd = open("/proc/self/attr/current", O_RDWR);
	if (cfd < 0)
		perror("Preparing to set Smack labels");

	if (writeload() == -1)
		exit(1);

	system("/bin/rm -rf " WHERE);

	if (mkdir(WHERE, 0777) < 0) {
		perror("mkdir of " WHERE);
		exit(1);
	}

	for (obj = 1; obj <= SPEEDS; obj++) {
		sprintf(label, "speed-%d", obj);
		sprintf(path, "%s/speed-%d", WHERE, obj);
		if (mkdir(path, 0777) < 0) {
			perror(path);
			exit(1);
		}
		if (setxattr(path, SMACKX, label, strlen(label), 0) < 0) {
			perror(path);
			exit(1);
		}
	}

	gettimeofday(&start_time, NULL);

	for (sub = 1; sub <= SPEEDS; sub++) {
		sprintf(path, "speed-%d", sub);
		if (write(cfd, path, strlen(path) + 1) < 0)
			perror("Setting process Smack");
		if (seteuid(99) < 0) {
			perror("seteuid(99)");
			exit(1);
		}
		for (obj = 1; obj <= SPEEDS; obj++) {
			sprintf(path, "%s/speed-%d", WHERE, obj);
			rc = stat(path, &buf);
			if (sub == obj && rc < 0)
				fprintf(stderr,
					"Unexpected failure for %d %d\n",
					sub, obj);
			else if (sub == obj + 1) {
				if (rc < 0)
					fprintf(stderr,
					    "Unexpected failure for %d %d\n",
					    sub, obj);
			}
			else if (sub != obj && rc >= 0)
				fprintf(stderr,
					"Unexpected success for %d %d\n",
					sub, obj);
#ifdef VERBOSE
			else
				fprintf(stderr,
					"Expected result for %d %d\n",
					sub, obj);
#endif
		}
		if (seteuid(0) < 0) {
			perror("seteuid(0)");
			exit(1);
		}
	}

	gettimeofday(&end_time, NULL);

	if (start_time.tv_usec > end_time.tv_usec) {
		end_time.tv_usec += 1000000;
		end_time.tv_sec -= 1;
	}
	printf("%s: short label speed factor %d %d.%06d seconds\n",
		argv[0], SPEEDS,
		(int)end_time.tv_sec - (int)start_time.tv_sec,
		(int)end_time.tv_usec - (int)start_time.tv_usec);

	seteuid(0);
	write(cfd, runlabel, strlen(runlabel) + 1);
	if (writeload2() == -1)
		exit(1);

	system("/bin/rm -rf " WHERE);
	if (mkdir(WHERE, 0777) < 0) {
		perror("mkdir of " WHERE);
		exit(1);
	}

	for (obj = 1; obj <= SPEEDS; obj++) {
		sprintf(label, LFIX "-%d", obj);
		sprintf(path, "%s/speed-%d", WHERE, obj);
		if (mkdir(path, 0777) < 0) {
			perror(path);
			exit(1);
		}
		if (setxattr(path, "security.SMACK64", label, strlen(label), 0)
		    < 0) {
			perror(path);
			exit(1);
		}
	}

	gettimeofday(&start_time, NULL);

	for (sub = 1; sub <= SPEEDS; sub++) {
		sprintf(path, LFIX "-%d", sub);
		if (write(cfd, path, strlen(path)) < 0)
			perror("Setting process Smack");

		if (seteuid(99) < 0) {
			perror("seteuid(99)");
			exit(1);
		}
		for (obj = 1; obj <= SPEEDS; obj++) {
			sprintf(path, "%s/speed-%d", WHERE, obj);
			rc = stat(path, &buf);
			if (sub == obj && rc < 0) {
				seteuid(0);
				i = lgetxattr(path, "security.SMACK64",
						label, sizeof(label));
				seteuid(99);
				if (i >= 0)
					label[i] = '\0';
				else
					label[0] = '\0';
				fprintf(stderr,
					"Unexpected failure for %d %d (%s)\n",
					sub, obj, label);
			}
			else if (sub == obj + 1) {
				seteuid(0);
				i = lgetxattr(path, "security.SMACK64",
						label, sizeof(label));
				seteuid(99);
				if (i >= 0)
					label[i] = '\0';
				else
					label[0] = '\0';
				if (rc < 0)
					fprintf(stderr,
						"Unexpected failure for "
						"%d %d (%s)\n",
						sub, obj, label);
			}
			else if (sub != obj && rc >= 0)
				fprintf(stderr,
					"Unexpected success for %d %d\n",
					sub, obj);
		}
		if (seteuid(0) < 0) {
			perror("seteuid(0)");
			exit(1);
		}
	}

	gettimeofday(&end_time, NULL);

	if (start_time.tv_usec > end_time.tv_usec) {
		end_time.tv_usec += 1000000;
		end_time.tv_sec -= 1;
	}
	printf("%s: long label speed factor %d %d.%06d seconds\n",
		argv[0], SPEEDS,
		(int)end_time.tv_sec - (int)start_time.tv_sec,
		(int)end_time.tv_usec - (int)start_time.tv_usec);

	system("/bin/rm -rf " WHERE);

	exit(0);
}
