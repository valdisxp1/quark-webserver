/* See LICENSE file for license details. */
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "arg.h"

char *argv0;

#include "config.h"

static char *status[] = {
	[200] = "OK",
	[206] = "Partial Content",
	[301] = "Moved Permanently",
	[400] = "Bad Request",
	[403] = "Forbidden",
	[404] = "Not Found",
	[405] = "Method Not Allowed",
	[408] = "Request Time-out",
	[431] = "Request Header Fields Too Large",
	[500] = "Internal Server Error",
	[505] = "HTTP Version not supported",

};

#undef MIN
#define MIN(x,y)  ((x) < (y) ? (x) : (y))

static char *
timestamp(time_t t)
{
	static char s[30];

	if (!t)
		t = time(NULL);
	strftime(s, sizeof(s), "%a, %d %b %Y %H:%M:%S GMT", gmtime(&t));

	return s;
}

static int
sendstatus(int code, int fd, ...)
{
	va_list ap;
	char buf[4096];
	size_t written, buflen;
	ssize_t ret;
	long lower, upper, size;

	buflen = snprintf(buf, 4096, "HTTP/1.1 %d %s\r\n", code,
	                  status[code]);

	buflen += snprintf(buf + buflen, 4096 - buflen, "Date: %s\r\n",
	                   timestamp(0));
	va_start(ap, fd);
	switch (code) {
	case 200: /* arg-list: mime, size */
		buflen += snprintf(buf + buflen, 4096 - buflen,
		                   "Content-Type: %s\r\n",
		                   va_arg(ap, char *));
		if ((size = va_arg(ap, long)) >= 0) {
			buflen += snprintf(buf + buflen, 4096 - buflen,
			                   "Content-Length: %ld\r\n",
					   size);
		}
		break;
	case 206: /* arg-list: mime, lower, upper, size */
		buflen += snprintf(buf + buflen, 4096 - buflen,
		                   "Content-Type: %s\r\n",
		                   va_arg(ap, char *));
		lower = va_arg(ap, long);
		upper = va_arg(ap, long);
		size = va_arg(ap, long);
		buflen += snprintf(buf + buflen, 4096 - buflen,
		                   "Content-Range: bytes %ld-%ld/%ld\r\n",
		                   lower, upper, size);
		buflen += snprintf(buf + buflen, 4096 - buflen,
		                   "Content-Length: %ld\r\n",
		                   (upper - lower) + 1);
		break;
	case 301: /* arg-list: host, url */
		if (!strcmp(port, "80")) {
			buflen += snprintf(buf + buflen, 4096 - buflen,
		                           "Location: http://%s%s\r\n",
				           va_arg(ap, char *),
			                   va_arg(ap, char *));
		} else {
			buflen += snprintf(buf + buflen, 4096 - buflen,
		                           "Location: http://%s:%s%s\r\n",
				           va_arg(ap, char *), port,
			                   va_arg(ap, char *));
		}
		break;
	case 405: /* arg-list: none */
		buflen += snprintf(buf + buflen, 4096 - buflen,
		                   "Allow: GET\r\n");
		break;
	}
	va_end(ap);

	buflen += snprintf(buf + buflen, 4096 - buflen,
	                   "Connection: close\r\n");

	if (code != 200 && code != 206) {
		buflen += snprintf(buf + buflen, 4096 - buflen,
		                   "Content-Type: text/html\r\n");
		buflen += snprintf(buf + buflen, 4096 - buflen,
	                           "\r\n<!DOCTYPE html>\r\n<html>\r\n"
	                           "\t<head><title>%d %s</title></head>"
				   "\r\n\t<body><h1>%d %s</h1></body>\r\n"
				   "</html>\r\n", code, status[code],
				   code, status[code]);
	} else {
		buflen += snprintf(buf + buflen, 4096 - buflen, "\r\n");
	}

	for (written = 0; buflen > 0; written += ret, buflen -= ret) {
		if ((ret = write(fd, buf + written, buflen)) < 0) {
			code = 408;
			break;
		}
	}

	return code;
}

static size_t
decode(char src[PATH_MAX], char dest[PATH_MAX])
{
	size_t i;
	uint8_t n;
	char *s;

	for (s = src, i = 0; *s; s++, i++) {
		if (*s == '+') {
			dest[i] = ' ';
		} else if (*s == '%' && (sscanf(s + 1, "%2hhx", &n) == 1)) {
			dest[i] = (char)(n & 255);
			s += 2;
		} else {
			dest[i] = *s;
		}
	}
	dest[i] = '\0';

	return i;
}

static size_t
encode(char src[PATH_MAX], char dest[PATH_MAX])
{
	size_t i;
	char *s;

	for (s = src, i = 0; *s; s++) {
		if (isalnum(*s) || *s == '~' || *s == '-' || *s == '.' ||
		    *s == '_') {
			i += snprintf(dest + i, PATH_MAX - i, "%%%02X", *s);
		} else {
			dest[i] = *s;
			i++;
		}
	}

	return 0;
}

static int
listdir(char *dir, int fd)
{
	struct dirent **e = NULL;
	static char buf[BUFSIZ];
	size_t buflen;
	ssize_t bread, written;
	int dirlen, ret, i;

	if ((dirlen = scandir(dir, &e, NULL, alphasort)) < 0) {
		return sendstatus(403, fd);
	}
	if ((ret = sendstatus(200, fd, "text/html", (long)-1)) != 200) {
		return ret;
	}
	if ((buflen = snprintf(buf, sizeof(buf), "<!DOCTYPE html>\r\n"
	                       "<html>\r\n<head><title>Index of %s"
	                       "</title></head>\r\n<body>\r\n"
	                       "<a href=\"..\">..</a><br />\r\n",
	                       dir)) >= sizeof(buf)) {
		return 500;
	}
	written = 0;
	while (buflen > 0) {
		if ((bread = write(fd, buf + written, buflen)) < 0) {
			return 408;
		}
		written += bread;
		buflen -= bread;
	}

	for (i = 0; i < dirlen; i++) {
		if (e[i]->d_name[0] == '.') { /* hidden files, ., .. */
			continue;
		}
		if ((buflen = snprintf(buf, sizeof(buf), "<a href=\"%s"
		                       "\">%s</a><br />\r\n", e[i]->d_name,
		                       e[i]->d_name)) >= sizeof(buf)) {
			return 500;
		}
		written = 0;
		while (buflen > 0) {
			if ((bread = write(fd, buf + written, buflen)) < 0) {
				return 408;
			}
			written += bread;
			buflen -= bread;
		}
	}

	if ((buflen = snprintf(buf, sizeof(buf), "\r\n</body></html>\r\n"))
	    >= sizeof(buf)) {
		return 500;
	}
	written = 0;
	while (buflen > 0) {
		if ((bread = write(fd, buf + written, buflen)) < 0) {
			return 408;
		}
		written += bread;
		buflen -= bread;
	}

	return 200;
}

static int
handle(int infd, char **url)
{
	FILE *fp;
	struct stat st;
	size_t reqlen, urllen, i;
	ssize_t off, buflen, written;
	long lower, upper, fsize, remaining;
	int needredirect, ret;
	static char req[MAXREQLEN], buf[BUFSIZ],
	            urlenc[PATH_MAX], urldec[PATH_MAX],
	            urldecnorm[PATH_MAX], urldecnormind[PATH_MAX],
	            reqhost[256], range[128], modsince[30];
	char *p, *q, *mime;

	/* get request header */
	for (reqlen = 0; ;) {
		if ((off = read(infd, req + reqlen, MAXREQLEN - reqlen)) < 0) {
			return sendstatus(408, infd);
		} else if (off == 0) {
			break;
		}
		reqlen += off;
		if (reqlen >= 4 && !memcmp(req + reqlen - 4, "\r\n\r\n", 4)) {
			break;
		}
		if (reqlen == MAXREQLEN) {
			return sendstatus(431, infd);
		}
	}
	if (reqlen < 2) {
		return sendstatus(400, infd);
	}
	reqlen -= 2; /* remove last \r\n */
	req[reqlen] = '\0'; /* make it safe */

	/* parse request line */
	if (reqlen < 3) {
		return sendstatus(400, infd);
	} else if (strncmp(req, "GET", sizeof("GET") - 1)) {
		return sendstatus(405, infd);
	} else if (req[3] != ' ') {
		return sendstatus(400, infd);
	}
	for (p = req + sizeof("GET ") - 1; *p && *p != ' '; p++)
		;
	if (!*p) {
		return sendstatus(400, infd);
	}
	*p = '\0';
	if (snprintf(urlenc, sizeof(urlenc), "%s",
	    req + sizeof("GET ") - 1) >= sizeof(urlenc)) {
		return sendstatus(400, infd);
	}
	*url = urldecnorm;
	if (!strlen(urlenc)) {
		return sendstatus(400, infd);
	}
	p += sizeof(" ") - 1;
	if (strncmp(p, "HTTP/", sizeof("HTTP/") - 1)) {
		return sendstatus(400, infd);
	}
	p += sizeof("HTTP/") - 1;
	if (strncmp(p, "1.0", sizeof("1.0") - 1) &&
	    strncmp(p, "1.1", sizeof("1.1") - 1)) {
		return sendstatus(505, infd);
	}
	p += sizeof("1.*") - 1;
	if (strncmp(p, "\r\n", sizeof("\r\n") - 1)) {
		return sendstatus(400, infd);
	}
	p += sizeof("\r\n") - 1;

	/* parse header fields */
	for (; (q = strstr(p, "\r\n")); p = q + sizeof("\r\n") - 1) {
		*q = '\0';
		if (!strncmp(p, "Host:", sizeof("Host:") - 1)) {
			p += sizeof("Host:") - 1;
			while (isspace(*p)) {
				p++;
			}
			if (snprintf(reqhost, sizeof(reqhost), "%s", p) >=
			    sizeof(reqhost)) {
				return sendstatus(500, infd);
			}
		} else if (!strncmp(p, "Range:", sizeof("Range:") - 1)) {
			p += sizeof("Range:") - 1;
			while (isspace(*p)) {
				p++;
			}
			if (snprintf(range, sizeof(range), "%s", p) >=
			    sizeof(range)) {
				return sendstatus(500, infd);
			}
		} else if (!strncmp(p, "If-Modified-Since:",
		           sizeof("If-Modified-Since:") - 1)) {
			p+= sizeof("If-Modified-Since:") - 1;
			while (isspace(*p)) {
				p++;
			}
			if (snprintf(modsince, sizeof(modsince), "%s", p) >=
			    sizeof(modsince)) {
				return sendstatus(500, infd);
			}
		}
	}

	/* normalization */
	needredirect = 0;
	decode(urlenc, urldec);
	if (!realpath(urldec, urldecnorm)) {
		/* todo: break up the cases */
		return sendstatus((errno == EACCES) ? 403 : 404, infd);
	}

	/* hidden path? */
	if (urldecnorm[0] == '.' || strstr(urldecnorm, "/.")) {
		return sendstatus(403, infd);
	}
	/* check if file or directory */
	if (stat(urldecnorm, &st) < 0) {
		/* todo: break up the cases */
		return sendstatus(404, infd);
	}
	if (S_ISDIR(st.st_mode)) {
		/* add / at the end, was removed by realpath */
		urllen = strlen(urldecnorm);
		if (urldecnorm[urllen - 1] != '/') {
			urldecnorm[urllen + 1] = '\0';
			urldecnorm[urllen] = '/';
		}

		/* is a / at the end on the raw string? */
		urllen = strlen(urldec);
		if (urldec[urllen - 1] != '/') {
			needredirect = 1;
		} else if (!needredirect) {
			/* check index */
			if (snprintf(urldecnormind, sizeof(urldecnormind),
			             "%s/%s", urldecnorm, docindex) >=
				     sizeof(urldecnorm)) {
				return sendstatus(400, infd);
			}
			if (stat(urldecnormind, &st) < 0) {
				/* no index, serve dir */
				if (!listdirs) {
					return sendstatus(403, infd);
				}
				return listdir(urldecnorm, infd);
			}
		}
	}
	if (strcmp(urldec, urldecnorm)) {
		needredirect = 1;
	}
	if (needredirect) {
		encode(urldecnorm, urlenc);
		return sendstatus(301, infd, urlenc,
		                  reqhost[0] ? reqhost : host);
	}

	/* range */
	lower = 0;
	upper = LONG_MAX;
	if (range[0]) {
		if (strncmp(range, "bytes=", sizeof("bytes=") - 1)) {
			return sendstatus(400, infd);
		}
		p = range + sizeof("bytes=") - 1;
		if (!(q = strchr(p, '-'))) {
			return sendstatus(400, infd);
		}
		*(q++) = '\0';
		if (p[0]) {
			lower = atoi(p);
		}
		if (q[0]) {
			upper = atoi(q);
		}
	}

	/* serve file */
	if (!(fp = fopen(urldecnorm, "r"))) {
		return sendstatus(403, infd);
	}
	mime = "text/plain";
	if ((p = strrchr(urldecnorm, '.'))) {
		for (i = 0; i < sizeof(mimes)/sizeof(*mimes); i++) {
			if (!strcmp(mimes[i].ext, p + 1)) {
				mime = mimes[i].type;
				break;
			}
		}
	}
	if (fseek(fp, 0, SEEK_END) || (fsize = ftell(fp)) < 0) {
		return sendstatus(500, infd);
	}
	rewind(fp);
	if (fsize && upper > fsize) {
		upper = fsize - 1;
	}
	if (fseek(fp, lower, SEEK_SET)) {
		return sendstatus(500, infd);
	}
	if (!range[0]) {
		if ((ret = sendstatus(200, infd, mime, (long)fsize)) != 200) {
			return ret;
		}
	} else {
		if ((ret = sendstatus(206, infd, mime, lower,
		                      upper, fsize)) != 206) {
			return ret;
		}
	}
	remaining = (upper - lower) + 1;
	while ((buflen = fread(buf, 1, MIN(sizeof(buf), remaining),
	                     fp))) {
		remaining -= buflen;
		if (buflen < 0) {
			return 500;
		}
		p = buf;
		while (buflen > 0) {
			written = write(infd, p, buflen);
			if (written <= 0) {
				return 408;
			}
			buflen -= written;
			p += written;
		}
	}

	return 200;
}

static void
serve(int insock)
{
	struct sockaddr_storage in_sa;
	struct timeval tv;
	pid_t p;
	socklen_t in_sa_len;
	time_t t;
	int infd, status;
	char inip4[INET_ADDRSTRLEN], inip6[INET6_ADDRSTRLEN], *url = "",
	     tstmp[25];

	while (1) {
		in_sa_len = sizeof(in_sa);
		if ((infd = accept(insock, (struct sockaddr *)&in_sa,
		                   &in_sa_len)) < 0) {
			fprintf(stderr, "%s: accept: %s\n", argv0,
			        strerror(errno));
			continue;
		}

		switch ((p = fork())) {
		case -1:
			fprintf(stderr, "%s: fork: %s", argv0,
			        strerror(errno));
			break;
		case 0:
			close(insock);

			/* timeouts */
			tv.tv_sec = 30;
			tv.tv_usec = 0;
			if (setsockopt(infd, SOL_SOCKET, SO_RCVTIMEO, &tv,
			               sizeof(tv)) < 0 ||
			    setsockopt(infd, SOL_SOCKET, SO_SNDTIMEO, &tv,
			               sizeof(tv)) < 0) {
				fprintf(stderr, "%s: setsockopt: %s\n",
				        argv0, strerror(errno));
				return;
			}

			status = handle(infd, &url);

			/* log */
			t = time(NULL);
			strftime(tstmp, sizeof(tstmp), "%Y-%m-%dT%H:%M:%S",
			         gmtime(&t));

			if (in_sa.ss_family == AF_INET) {
				inet_ntop(AF_INET,
				          &(((struct sockaddr_in *)&in_sa)->sin_addr),
				          inip4, sizeof(inip4));
				printf("%s\t%s\t%d\t%s\n", tstmp, inip4, status, url);
			} else {
				inet_ntop(AF_INET6,
				          &(((struct sockaddr_in6*)&in_sa)->sin6_addr),
				          inip6, sizeof(inip6));
				printf("%s\t%s\t%d\t%s\n", tstmp, inip6, status, url);
			}

			shutdown(infd, SHUT_RD);
			shutdown(infd, SHUT_WR);
			close(infd);
			_exit(EXIT_SUCCESS);
		default:
			close(infd);
		}
	}
}

void
die(const char *errstr, ...)
{
	va_list ap;

	va_start(ap, errstr);
	vfprintf(stderr, errstr, ap);
	va_end(ap);

	exit(1);
}

static int
getipsock(void)
{
	struct addrinfo hints, *ai, *p;
	int ret, insock = 0, yes;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((ret = getaddrinfo(host, port, &hints, &ai))) {
		die("%s: getaddrinfo: %s\n", argv0, gai_strerror(ret));
	}

	for (yes = 1, p = ai; p; p = p->ai_next) {
		if ((insock = socket(p->ai_family, p->ai_socktype,
		                     p->ai_protocol)) < 0) {
			continue;
		}
		if (setsockopt(insock, SOL_SOCKET, SO_REUSEADDR, &yes,
		               sizeof(int)) < 0) {
			die("%s: setsockopt: %s\n", argv0, strerror(errno));
		}
		if (bind(insock, p->ai_addr, p->ai_addrlen) < 0) {
			close(insock);
			continue;
		}
		break;
	}
	freeaddrinfo(ai);
	if (!p) {
		die("%s: failed to bind\n", argv0);
	}

	if (listen(insock, SOMAXCONN) < 0) {
		die("%s: listen: %s\n", argv0, strerror(errno));
	}

	return insock;
}

static int
getusock(char *udsname)
{
	struct sockaddr_un addr;
	int insock;

	if ((insock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		die("%s: socket: %s\n", argv0, strerror(errno));
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, udsname, sizeof(addr.sun_path) - 1);

	unlink(udsname);

	if (bind(insock, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
		die("%s: bind: %s\n", argv0, strerror(errno));
	}

	if (listen(insock, SOMAXCONN) < 0) {
		die("%s: listen: %s\n", argv0, strerror(errno));
	}

	return insock;
}

static void
usage(void)
{
	die("usage: %s [-v] [[[-h host] [-p port]] | [-U udsocket]] "
	    "[-d dir] [-u user] [-g group]\n", argv0);
}

int
main(int argc, char *argv[])
{
	struct passwd *pwd = NULL;
	struct group *grp = NULL;
	struct rlimit rlim;
	int insock;
	char *udsname = NULL;

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
		fputs("quark-"VERSION"\n", stderr);
		return 0;
	default:
		usage();
	} ARGEND

	if (argc)
		usage();

	/* reap children automatically */
	if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
		fprintf(stderr, "%s: signal: Failed to set SIG_IGN on"
		        "SIGCHLD\n", argv0);
		return 1;
	}

	/* raise the process limit */
	rlim.rlim_cur = rlim.rlim_max = maxnprocs;
	if (setrlimit(RLIMIT_NPROC, &rlim) < 0) {
		fprintf(stderr, "%s: setrlimit RLIMIT_NPROC: %s\n", argv0,
		        strerror(errno));
		return 1;
	}

	/* validate user and group */
	errno = 0;
	if (user && !(pwd = getpwnam(user))) {
		die("%s: invalid user %s\n", argv0, user);
	}
	errno = 0;
	if (group && !(grp = getgrnam(group))) {
		die("%s: invalid group %s\n", argv0, group);
	}

	/* bind socket */
	insock = udsname ? getusock(udsname) : getipsock();

	/* chroot */
	if (chdir(servedir) < 0) {
		die("%s: chdir %s: %s\n", argv0, servedir, strerror(errno));
	}
	if (chroot(".") < 0) {
		die("%s: chroot .: %s\n", argv0, strerror(errno));
	}

	/* drop root */
	if (grp && setgroups(1, &(grp->gr_gid)) < 0) {
		die("%s: setgroups: %s\n", argv0, strerror(errno));
	}
	if (grp && setgid(grp->gr_gid) < 0) {
		die("%s: setgid: %s\n", argv0, strerror(errno));
	}
	if (pwd && setuid(pwd->pw_uid) < 0) {
		die("%s: setuid: %s\n", argv0, strerror(errno));
	}
	if (getuid() == 0) {
		die("%s: won't run as root user\n", argv0);
	}
	if (getgid() == 0) {
		die("%s: won't run as root group\n", argv0);
	}

	serve(insock);
	close(insock);

	return 0;
}
