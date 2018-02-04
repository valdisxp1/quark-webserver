/* See LICENSE file for copyright and license details. */
#include <errno.h>
#include <grp.h>
#include <netinet/in.h>
#include <pwd.h>
#include <regex.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "http.h"
#include "sock.h"
#include "util.h"

#include "config.h"

static char *udsname;

static void
serve(int insock)
{
	struct request r;
	struct sockaddr_storage in_sa;
	pid_t p;
	socklen_t in_sa_len;
	time_t t;
	enum status status;
	int infd;
	char inaddr[INET6_ADDRSTRLEN /* > INET_ADDRSTRLEN */];
	char tstmp[25];

	while (1) {
		/* accept incoming connections */
		in_sa_len = sizeof(in_sa);
		if ((infd = accept(insock, (struct sockaddr *)&in_sa,
		                   &in_sa_len)) < 0) {
			warn("accept:");
			continue;
		}

		/* fork and handle */
		switch ((p = fork())) {
		case -1:
			warn("fork:");
			break;
		case 0:
			close(insock);

			/* set connection timeout */
			if (sock_set_timeout(infd, 30)) {
				goto cleanup;
			}

			/* handle request */
			if (!(status = http_get_request(infd, &r))) {
				status = http_send_response(infd, &r);
			}

			/* write output to log */
			t = time(NULL);
			if (!strftime(tstmp, sizeof(tstmp), "%Y-%m-%dT%H:%M:%S",
			              gmtime(&t))) {
				warn("strftime: Exceeded buffer capacity");
				goto cleanup;
			}
			if (sock_get_inaddr_str(&in_sa, inaddr, LEN(inaddr))) {
				goto cleanup;
			}
			printf("%s\t%s\t%d\t%s\t%s\n", tstmp, inaddr, status,
			       r.field[REQ_HOST], r.target);
cleanup:
			/* clean up and finish */
			shutdown(infd, SHUT_RD);
			shutdown(infd, SHUT_WR);
			close(infd);
			exit(0);
		default:
			/* close the connection in the parent */
			close(infd);
		}
	}
}

static void
cleanup(void)
{
	if (udsname)
		 sock_rem_uds(udsname);
}

static void
sigcleanup(int sig)
{
	cleanup();
	kill(0, sig);
	_exit(1);
}

static void
handlesignals(void(*hdl)(int))
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = hdl;

	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
}

static void
usage(void)
{
	die("usage: %s [-l | -L] [-v | -V] [[[-h host] [-p port]] | [-U sockfile]] "
	    "[-d dir] [-u user] [-g group]", argv0);
}

int
main(int argc, char *argv[])
{
	struct passwd *pwd = NULL;
	struct group *grp = NULL;
	struct rlimit rlim;
	pid_t cpid, wpid;
	int i, insock, status = 0;

	ARGBEGIN {
	case 'd':
		servedir = EARGF(usage());
		break;
	case 'g':
		group = EARGF(usage());
		break;
	case 'h':
		host = EARGF(usage());
		break;
	case 'l':
		listdirs = 0;
		break;
	case 'L':
		listdirs = 1;
		break;
	case 'p':
		port = EARGF(usage());
		break;
	case 'u':
		user = EARGF(usage());
		break;
	case 'U':
		udsname = EARGF(usage());
		break;
	case 'v':
		vhosts = 0;
		break;
	case 'V':
		vhosts = 1;
		break;
	default:
		usage();
	} ARGEND

	if (argc) {
		usage();
	}

	if (udsname && (!access(udsname, F_OK) || errno != ENOENT)) {
		die("UNIX-domain socket: %s", errno ?
		    strerror(errno) : "file exists");
	}

	/* compile and check the supplied vhost regexes */
	if (vhosts) {
		for (i = 0; i < LEN(vhost); i++) {
			if (regcomp(&vhost[i].re, vhost[i].regex,
			            REG_EXTENDED | REG_ICASE | REG_NOSUB)) {
				die("regcomp '%s': invalid regex",
				    vhost[i].regex);
			}
		}
	}

	/* raise the process limit */
	rlim.rlim_cur = rlim.rlim_max = maxnprocs;
	if (setrlimit(RLIMIT_NPROC, &rlim) < 0) {
		die("setrlimit RLIMIT_NPROC:");
	}

	/* validate user and group */
	errno = 0;
	if (user && !(pwd = getpwnam(user))) {
		die("getpwnam '%s': %s", user, errno ? strerror(errno) :
		    "Entry not found");
	}
	errno = 0;
	if (group && !(grp = getgrnam(group))) {
		die("getgrnam '%s': %s", group, errno ? strerror(errno) :
		    "Entry not found");
	}

	handlesignals(sigcleanup);

	/* bind socket */
	insock = udsname ? sock_get_uds(udsname, pwd->pw_uid, grp->gr_gid) :
	                   sock_get_ips(host, port);

	switch (cpid = fork()) {
	case -1:
		warn("fork:");
		break;
	case 0:
		/* restore default handlers */
		handlesignals(SIG_DFL);

		/* reap children automatically */
		if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
			die("signal: Failed to set SIG_IGN on SIGCHLD");
		}

		/* chroot */
		if (chdir(servedir) < 0) {
			die("chdir '%s':", servedir);
		}
		if (chroot(".") < 0) {
			die("chroot .:");
		}

		/* drop root */
		if (grp && setgroups(1, &(grp->gr_gid)) < 0) {
			die("setgroups:");
		}
		if (grp && setgid(grp->gr_gid) < 0) {
			die("setgid:");
		}
		if (pwd && setuid(pwd->pw_uid) < 0) {
			die("setuid:");
		}
		if (getuid() == 0) {
			die("Won't run as root user", argv0);
		}
		if (getgid() == 0) {
			die("Won't run as root group", argv0);
		}

		serve(insock);
		exit(0);
	default:
		while ((wpid = wait(&status)) > 0)
			;
	}

	cleanup();
	return status;
}
