/* See LICENSE file for copyright and license details. */
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <regex.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "http.h"
#include "resp.h"
#include "util.h"

const char *req_field_str[] = {
	[REQ_HOST]              = "Host",
	[REQ_RANGE]             = "Range",
	[REQ_IF_MODIFIED_SINCE] = "If-Modified-Since",
};

const char *req_method_str[] = {
	[M_GET]  = "GET",
	[M_HEAD] = "HEAD",
};

const char *status_str[] = {
	[S_OK]                    = "OK",
	[S_PARTIAL_CONTENT]       = "Partial Content",
	[S_MOVED_PERMANENTLY]     = "Moved Permanently",
	[S_NOT_MODIFIED]          = "Not Modified",
	[S_BAD_REQUEST]           = "Bad Request",
	[S_FORBIDDEN]             = "Forbidden",
	[S_NOT_FOUND]             = "Not Found",
	[S_METHOD_NOT_ALLOWED]    = "Method Not Allowed",
	[S_REQUEST_TIMEOUT]       = "Request Time-out",
	[S_RANGE_NOT_SATISFIABLE] = "Range Not Satisfiable",
	[S_REQUEST_TOO_LARGE]     = "Request Header Fields Too Large",
	[S_INTERNAL_SERVER_ERROR] = "Internal Server Error",
	[S_VERSION_NOT_SUPPORTED] = "HTTP Version not supported",
};

const char *res_field_str[] = {
	[RES_ACCEPT_RANGES]  = "Accept-Ranges",
	[RES_ALLOW]          = "Allow",
	[RES_LOCATION]       = "Location",
	[RES_LAST_MODIFIED]  = "Last-Modified",
	[RES_CONTENT_LENGTH] = "Content-Length",
	[RES_CONTENT_RANGE]  = "Content-Range",
	[RES_CONTENT_TYPE]   = "Content-Type",
};

enum status
http_send_header(int fd, const struct response *res)
{
	char t[FIELD_MAX], esc[PATH_MAX];
	size_t i;

	if (timestamp(t, sizeof(t), time(NULL))) {
		return S_INTERNAL_SERVER_ERROR;
	}

	if (dprintf(fd,
	            "HTTP/1.1 %d %s\r\n"
	            "Date: %s\r\n"
	            "Connection: close\r\n",
	            res->status, status_str[res->status], t) < 0) {
		return S_REQUEST_TIMEOUT;
	}

	for (i = 0; i < NUM_RES_FIELDS; i++) {
		if (res->field[i][0] != '\0') {
			if (dprintf(fd, "%s: %s\r\n", res_field_str[i],
			            res->field[i]) < 0) {
				return S_REQUEST_TIMEOUT;
			}
		}
	}

	if (dprintf(fd, "\r\n") < 0) {
		return S_REQUEST_TIMEOUT;
	}

	/* listing header */
	if (res->type == RESTYPE_DIRLISTING) {
		html_escape(res->uri, esc, sizeof(esc));
		if (dprintf(fd,
		            "<!DOCTYPE html>\n<html>\n\t<head>"
		            "<title>Index of %s</title></head>\n"
		            "\t<body>\n\t\t<a href=\"..\">..</a>",
		            esc) < 0) {
			return S_REQUEST_TIMEOUT;
		}
	}

	return res->status;
}

enum status
http_send_status(int fd, enum status s)
{
	enum status sendstatus;

	struct response res = {
		.status                  = s,
		.field[RES_CONTENT_TYPE] = "text/html; charset=utf-8",
	};

	if (s == S_METHOD_NOT_ALLOWED) {
		if (esnprintf(res.field[RES_ALLOW],
		              sizeof(res.field[RES_ALLOW]), "%s",
			      "Allow: GET, HEAD")) {
			return S_INTERNAL_SERVER_ERROR;
		}
	}

	if ((sendstatus = http_send_header(fd, &res)) != s) {
		return sendstatus;
	}

	if (dprintf(fd,
	            "<!DOCTYPE html>\n<html>\n\t<head>\n"
	            "\t\t<title>%d %s</title>\n\t</head>\n\t<body>\n"
	            "\t\t<h1>%d %s</h1>\n\t</body>\n</html>\n",
	            s, status_str[s], s, status_str[s]) < 0) {
		return S_REQUEST_TIMEOUT;
	}

	return s;
}

static void
decode(const char src[PATH_MAX], char dest[PATH_MAX])
{
	size_t i;
	uint8_t n;
	const char *s;

	for (s = src, i = 0; *s; s++, i++) {
		if (*s == '%' && (sscanf(s + 1, "%2hhx", &n) == 1)) {
			dest[i] = n;
			s += 2;
		} else {
			dest[i] = *s;
		}
	}
	dest[i] = '\0';
}

enum status
http_recv_header(int fd, char *h, size_t hsiz, size_t *off)
{
	ssize_t r;

	if (h == NULL || off == NULL || *off > hsiz) {
		return S_INTERNAL_SERVER_ERROR;
	}

	while (1) {
		if ((r = read(fd, h + *off, hsiz - *off)) <= 0) {
			return S_REQUEST_TIMEOUT;
		}
		*off += r;

		/* check if we are done (header terminated) */
		if (*off >= 4 && !memcmp(h + *off - 4, "\r\n\r\n", 4)) {
			break;
		}

		/* buffer is full or read over, but header is not terminated */
		if (r == 0 || *off == hsiz) {
			return S_REQUEST_TOO_LARGE;
		}
	}

	/* header is complete, remove last \r\n and null-terminate */
	h[*off - 2] = '\0';

	/* set *off to 0 to indicate we are finished */
	*off = 0;

	return 0;
}

enum status
http_parse_header(const char *h, struct request *req)
{
	struct in6_addr addr;
	size_t i, mlen;
	const char *p, *q;
	char *m, *n;

	/* empty all fields */
	memset(req, 0, sizeof(*req));

	/*
	 * parse request line
	 */

	/* METHOD */
	for (i = 0; i < NUM_REQ_METHODS; i++) {
		mlen = strlen(req_method_str[i]);
		if (!strncmp(req_method_str[i], h, mlen)) {
			req->method = i;
			break;
		}
	}
	if (i == NUM_REQ_METHODS) {
		return S_METHOD_NOT_ALLOWED;
	}

	/* a single space must follow the method */
	if (h[mlen] != ' ') {
		return S_BAD_REQUEST;
	}

	/* basis for next step */
	p = h + mlen + 1;

	/* TARGET */
	if (!(q = strchr(p, ' '))) {
		return S_BAD_REQUEST;
	}
	if (q - p + 1 > PATH_MAX) {
		return S_REQUEST_TOO_LARGE;
	}
	memcpy(req->uri, p, q - p);
	req->uri[q - p] = '\0';
	decode(req->uri, req->uri);

	/* basis for next step */
	p = q + 1;

	/* HTTP-VERSION */
	if (strncmp(p, "HTTP/", sizeof("HTTP/") - 1)) {
		return S_BAD_REQUEST;
	}
	p += sizeof("HTTP/") - 1;
	if (strncmp(p, "1.0", sizeof("1.0") - 1) &&
	    strncmp(p, "1.1", sizeof("1.1") - 1)) {
		return S_VERSION_NOT_SUPPORTED;
	}
	p += sizeof("1.*") - 1;

	/* check terminator */
	if (strncmp(p, "\r\n", sizeof("\r\n") - 1)) {
		return S_BAD_REQUEST;
	}

	/* basis for next step */
	p += sizeof("\r\n") - 1;

	/*
	 * parse request-fields
	 */

	/* match field type */
	for (; *p != '\0';) {
		for (i = 0; i < NUM_REQ_FIELDS; i++) {
			if (!strncasecmp(p, req_field_str[i],
			                 strlen(req_field_str[i]))) {
				break;
			}
		}
		if (i == NUM_REQ_FIELDS) {
			/* unmatched field, skip this line */
			if (!(q = strstr(p, "\r\n"))) {
				return S_BAD_REQUEST;
			}
			p = q + (sizeof("\r\n") - 1);
			continue;
		}

		p += strlen(req_field_str[i]);

		/* a single colon must follow the field name */
		if (*p != ':') {
			return S_BAD_REQUEST;
		}

		/* skip whitespace */
		for (++p; *p == ' ' || *p == '\t'; p++)
			;

		/* extract field content */
		if (!(q = strstr(p, "\r\n"))) {
			return S_BAD_REQUEST;
		}
		if (q - p + 1 > FIELD_MAX) {
			return S_REQUEST_TOO_LARGE;
		}
		memcpy(req->field[i], p, q - p);
		req->field[i][q - p] = '\0';

		/* go to next line */
		p = q + (sizeof("\r\n") - 1);
	}

	/*
	 * clean up host
	 */

	m = strrchr(req->field[REQ_HOST], ':');
	n = strrchr(req->field[REQ_HOST], ']');

	/* strip port suffix but don't interfere with IPv6 bracket notation
	 * as per RFC 2732 */
	if (m && (!n || m > n)) {
		/* port suffix must not be empty */
		if (*(m + 1) == '\0') {
			return S_BAD_REQUEST;
		}
		*m = '\0';
	}

	/* strip the brackets from the IPv6 notation and validate the address */
	if (n) {
		/* brackets must be on the outside */
		if (req->field[REQ_HOST][0] != '[' || *(n + 1) != '\0') {
			return S_BAD_REQUEST;
		}

		/* remove the right bracket */
		*n = '\0';
		m = req->field[REQ_HOST] + 1;

		/* validate the contained IPv6 address */
		if (inet_pton(AF_INET6, m, &addr) != 1) {
			return S_BAD_REQUEST;
		}

		/* copy it into the host field */
		memmove(req->field[REQ_HOST], m, n - m + 1);
	}

	return 0;
}

static void
encode(const char src[PATH_MAX], char dest[PATH_MAX])
{
	size_t i;
	const char *s;

	for (s = src, i = 0; *s && i < (PATH_MAX - 4); s++) {
		if (iscntrl(*s) || (unsigned char)*s > 127) {
			i += snprintf(dest + i, PATH_MAX - i, "%%%02X",
			              (unsigned char)*s);
		} else {
			dest[i] = *s;
			i++;
		}
	}
	dest[i] = '\0';
}

static int
normabspath(char *path)
{
	size_t len;
	int last = 0;
	char *p, *q;

	/* require and skip first slash */
	if (path[0] != '/') {
		return 1;
	}
	p = path + 1;

	/* get length of path */
	len = strlen(p);

	for (; !last; ) {
		/* bound path component within (p,q) */
		if (!(q = strchr(p, '/'))) {
			q = strchr(p, '\0');
			last = 1;
		}

		if (p == q || (q - p == 1 && p[0] == '.')) {
			/* "/" or "./" */
			goto squash;
		} else if (q - p == 2 && p[0] == '.' && p[1] == '.') {
			/* "../" */
			if (p != path + 1) {
				/* place p right after the previous / */
				for (p -= 2; p > path && *p != '/'; p--);
				p++;
			}
			goto squash;
		} else {
			/* move on */
			p = q + 1;
			continue;
		}
squash:
		/* squash (p,q) into void */
		if (last) {
			*p = '\0';
			len = p - path;
		} else {
			memmove(p, q + 1, len - ((q + 1) - path) + 2);
			len -= (q + 1) - p;
		}
	}

	return 0;
}

static enum status
parse_range(const char *str, size_t size, size_t *lower, size_t *upper)
{
	char first[FIELD_MAX], last[FIELD_MAX];
	const char *p, *q, *r, *err;

	/* default to the complete range */
	*lower = 0;
	*upper = size - 1;

	/* done if no range-string is given */
	if (str == NULL || *str == '\0') {
		return 0;
	}

	/* skip opening statement */
	if (strncmp(str, "bytes=", sizeof("bytes=") - 1)) {
		return S_BAD_REQUEST;
	}
	p = str + (sizeof("bytes=") - 1);

	/* check string (should only contain numbers and a hyphen) */
	for (r = p, q = NULL; *r != '\0'; r++) {
		if (*r < '0' || *r > '9') {
			if (*r == '-') {
				if (q != NULL) {
					/* we have already seen a hyphen */
					return S_BAD_REQUEST;
				} else {
					/* place q after the hyphen */
					q = r + 1;
				}
			} else if (*r == ',' && r > p) {
				/*
				 * we refuse to accept range-lists out
				 * of spite towards this horrible part
				 * of the spec
				 */
				return S_RANGE_NOT_SATISFIABLE;
			} else {
				return S_BAD_REQUEST;
			}
		}
	}
	if (q == NULL) {
		/* the input string must contain a hyphen */
		return S_BAD_REQUEST;
	}
	r = q + strlen(q);

	/*
	 *  byte-range=first-last\0
	 *             ^     ^   ^
	 *             |     |   |
	 *             p     q   r
	 */

	/* copy 'first' and 'last' to their respective arrays */
	if ((size_t)((q - 1) - p + 1) > sizeof(first) ||
	    (size_t)(r - q + 1) > sizeof(last)) {
		return S_REQUEST_TOO_LARGE;
	}
	memcpy(first, p, (q - 1) - p);
	first[(q - 1) - p] = '\0';
	memcpy(last, q, r - q);
	last[r - q] = '\0';

	if (first[0] != '\0') {
		/*
		 * range has format "first-last" or "first-",
		 * i.e. return bytes 'first' to 'last' (or the
		 * last byte if 'last' is not given),
		 * inclusively, and byte-numbering beginning at 0
		 */
		*lower = strtonum(first, 0, SIZE_MAX, &err);
		if (!err) {
			if (last[0] != '\0') {
				*upper = strtonum(last, 0, SIZE_MAX, &err);
			} else {
				*upper = size - 1;
			}
		}
		if (err) {
			/* one of the strtonum()'s failed */
			return S_BAD_REQUEST;
		}

		/* check ranges */
		if (*lower > *upper || *lower >= size) {
			return S_RANGE_NOT_SATISFIABLE;
		}

		/* adjust upper limit to be at most the last byte */
		*upper = MIN(*upper, size - 1);
	} else {
		/* last must not also be empty */
		if (last[0] == '\0') {
			return S_BAD_REQUEST;
		}

		/*
		 * Range has format "-num", i.e. return the 'num'
		 * last bytes
		 */

		/*
		 * use upper as a temporary storage for 'num',
		 * as we know 'upper' is size - 1
		 */
		*upper = strtonum(last, 0, SIZE_MAX, &err);
		if (err) {
			return S_BAD_REQUEST;
		}

		/* determine lower */
		if (*upper > size) {
			/* more bytes requested than we have */
			*lower = 0;
		} else {
			*lower = size - *upper;
		}

		/* set upper to the correct value */
		*upper = size - 1;
	}

	return 0;
}

#undef RELPATH
#define RELPATH(x) ((!*(x) || !strcmp(x, "/")) ? "." : ((x) + 1))

enum status
http_prepare_response(const struct request *req, struct response *res,
                      const struct server *srv)
{
	enum status returnstatus;
	struct in6_addr addr;
	struct stat st;
	struct tm tm = { 0 };
	struct vhost *vhost;
	size_t len, i;
	int hasport, ipv6host;
	static char realuri[PATH_MAX], tmpuri[PATH_MAX];
	char *p, *mime;
	const char *targethost;

	/* empty all response fields */
	memset(res, 0, sizeof(*res));

	/* make a working copy of the URI and normalize it */
	memcpy(realuri, req->uri, sizeof(realuri));
	if (normabspath(realuri)) {
		return S_BAD_REQUEST;
	}

	/* match vhost */
	vhost = NULL;
	if (srv->vhost) {
		for (i = 0; i < srv->vhost_len; i++) {
			if (!regexec(&(srv->vhost[i].re), req->field[REQ_HOST],
			             0, NULL, 0)) {
				/* we have a matching vhost */
				vhost = &(srv->vhost[i]);
				break;
			}
		}
		if (i == srv->vhost_len) {
			return S_NOT_FOUND;
		}

		/* if we have a vhost prefix, prepend it to the URI */
		if (vhost->prefix &&
		    prepend(realuri, LEN(realuri), vhost->prefix)) {
			return S_REQUEST_TOO_LARGE;
		}
	}

	/* apply URI prefix mapping */
	for (i = 0; i < srv->map_len; i++) {
		len = strlen(srv->map[i].from);
		if (!strncmp(realuri, srv->map[i].from, len)) {
			/* match canonical host if vhosts are enabled and
			 * the mapping specifies a canonical host */
			if (srv->vhost && srv->map[i].chost &&
			    strcmp(srv->map[i].chost, vhost->chost)) {
				continue;
			}

			/* swap out URI prefix */
			memmove(realuri, realuri + len, strlen(realuri) + 1);
			if (prepend(realuri, LEN(realuri), srv->map[i].to)) {
				return S_REQUEST_TOO_LARGE;
			}
			break;
		}
	}

	/* normalize URI again, in case we introduced dirt */
	if (normabspath(realuri)) {
		return S_BAD_REQUEST;
	}

	/* stat the relative path derived from the URI */
	if (stat(RELPATH(realuri), &st) < 0) {
		return (errno == EACCES) ? S_FORBIDDEN : S_NOT_FOUND;
	}

	if (S_ISDIR(st.st_mode)) {
		/* append '/' to URI if not present */
		len = strlen(realuri);
		if (len + 1 + 1 > PATH_MAX) {
			return S_REQUEST_TOO_LARGE;
		}
		if (len > 0 && realuri[len - 1] != '/') {
			realuri[len] = '/';
			realuri[len + 1] = '\0';
		}
	}

	/*
	 * reject hidden targets, except if it is a well-known URI
	 * according to RFC 8615
	 */
	if (strstr(realuri, "/.") && strncmp(realuri,
	    "/.well-known/", sizeof("/.well-known/") - 1)) {
		return S_FORBIDDEN;
	}

	/*
	 * redirect if the original URI and the "real" URI differ or if
	 * the requested host is non-canonical
	 */
	if (strcmp(req->uri, realuri) || (srv->vhost && vhost &&
	    strcmp(req->field[REQ_HOST], vhost->chost))) {
		res->status = S_MOVED_PERMANENTLY;

		/* encode realuri */
		encode(realuri, tmpuri);

		/* determine target location */
		if (srv->vhost) {
			/* absolute redirection URL */
			targethost = req->field[REQ_HOST][0] ? vhost->chost ?
			             vhost->chost : req->field[REQ_HOST] :
				     srv->host ? srv->host : "localhost";

			/* do we need to add a port to the Location? */
			hasport = srv->port && strcmp(srv->port, "80");

			/* RFC 2732 specifies to use brackets for IPv6-addresses
			 * in URLs, so we need to check if our host is one and
			 * honor that later when we fill the "Location"-field */
			if ((ipv6host = inet_pton(AF_INET6, targethost,
			                          &addr)) < 0) {
				return S_INTERNAL_SERVER_ERROR;
			}

			/* write location to response struct */
			if (esnprintf(res->field[RES_LOCATION],
			              sizeof(res->field[RES_LOCATION]),
			              "//%s%s%s%s%s%s",
			              ipv6host ? "[" : "",
			              targethost,
			              ipv6host ? "]" : "", hasport ? ":" : "",
			              hasport ? srv->port : "", tmpuri)) {
				return S_REQUEST_TOO_LARGE;
			}
		} else {
			/* write relative redirection URI to response struct */
			if (esnprintf(res->field[RES_LOCATION],
			              sizeof(res->field[RES_LOCATION]),
			              "%s", tmpuri)) {
				return S_REQUEST_TOO_LARGE;
			}
		}

		return 0;
	} else {
		/*
		 * the URI is well-formed, we can now write the URI into
		 * the response-URI and corresponding relative path
		 * (optionally including the vhost servedir as a prefix)
		 * into the actual response-path
		 */
		if (esnprintf(res->uri, sizeof(res->uri), "%s", req->uri)) {
			return S_REQUEST_TOO_LARGE;
		}
		if (esnprintf(res->path, sizeof(res->path), "%s%s",
		    vhost ? vhost->dir : "", RELPATH(req->uri))) {
			return S_REQUEST_TOO_LARGE;
		}
	}

	if (S_ISDIR(st.st_mode)) {
		/*
		 * check if the directory index exists by appending it to
		 * the URI
		 */
		if (esnprintf(tmpuri, sizeof(tmpuri), "%s%s",
		              req->uri, srv->docindex)) {
			return S_REQUEST_TOO_LARGE;
		}

		/* stat the docindex, which must be a regular file */
		if (stat(RELPATH(tmpuri), &st) < 0 || !S_ISREG(st.st_mode)) {
			if (srv->listdirs) {
				/* serve directory listing */
				res->type = RESTYPE_DIRLISTING;
				res->status = (access(res->path, R_OK)) ?
				              S_FORBIDDEN : S_OK;

				if (esnprintf(res->field[RES_CONTENT_TYPE],
				              sizeof(res->field[RES_CONTENT_TYPE]),
					      "%s", "text/html; charset=utf-8")) {
					return S_INTERNAL_SERVER_ERROR;
				}

				return 0;
			} else {
				/* reject */
				return (!S_ISREG(st.st_mode) || errno == EACCES) ?
				       S_FORBIDDEN : S_NOT_FOUND;
			}
		}
	}

	/* modified since */
	if (req->field[REQ_IF_MODIFIED_SINCE][0]) {
		/* parse field */
		if (!strptime(req->field[REQ_IF_MODIFIED_SINCE],
		              "%a, %d %b %Y %T GMT", &tm)) {
			return S_BAD_REQUEST;
		}

		/* compare with last modification date of the file */
		if (difftime(st.st_mtim.tv_sec, timegm(&tm)) <= 0) {
			res->status = S_NOT_MODIFIED;
			return 0;
		}
	}

	/* range */
	if ((returnstatus = parse_range(req->field[REQ_RANGE], st.st_size,
	                                &(res->file.lower),
	                                &(res->file.upper)))) {
		if (returnstatus == S_RANGE_NOT_SATISFIABLE) {
			res->status = S_RANGE_NOT_SATISFIABLE;

			if (esnprintf(res->field[RES_CONTENT_RANGE],
			              sizeof(res->field[RES_CONTENT_RANGE]),
			              "bytes */%zu", st.st_size)) {
				return S_INTERNAL_SERVER_ERROR;
			}

			return 0;
		} else {
			return returnstatus;
		}
	}

	/* mime */
	mime = "application/octet-stream";
	if ((p = strrchr(realuri, '.'))) {
		for (i = 0; i < LEN(mimes); i++) {
			if (!strcmp(mimes[i].ext, p + 1)) {
				mime = mimes[i].type;
				break;
			}
		}
	}

	/* fill response struct */
	res->type = RESTYPE_FILE;

	/* check if file is readable */
	res->status = (access(res->path, R_OK)) ? S_FORBIDDEN :
	              (req->field[REQ_RANGE][0] != '\0') ?
	              S_PARTIAL_CONTENT : S_OK;

	if (esnprintf(res->field[RES_ACCEPT_RANGES],
	              sizeof(res->field[RES_ACCEPT_RANGES]),
		      "%s", "bytes")) {
		return S_INTERNAL_SERVER_ERROR;
	}

	if (esnprintf(res->field[RES_CONTENT_LENGTH],
	              sizeof(res->field[RES_CONTENT_LENGTH]),
	              "%zu", res->file.upper - res->file.lower + 1)) {
		return S_INTERNAL_SERVER_ERROR;
	}
	if (req->field[REQ_RANGE][0] != '\0') {
		if (esnprintf(res->field[RES_CONTENT_RANGE],
		              sizeof(res->field[RES_CONTENT_RANGE]),
		              "bytes %zd-%zd/%zu", res->file.lower,
			      res->file.upper, st.st_size)) {
			return S_INTERNAL_SERVER_ERROR;
		}
	}
	if (esnprintf(res->field[RES_CONTENT_TYPE],
	              sizeof(res->field[RES_CONTENT_TYPE]),
	              "%s", mime)) {
		return S_INTERNAL_SERVER_ERROR;
	}
	if (timestamp(res->field[RES_LAST_MODIFIED],
	              sizeof(res->field[RES_LAST_MODIFIED]),
	              st.st_mtim.tv_sec)) {
		return S_INTERNAL_SERVER_ERROR;
	}

	return 0;
}
