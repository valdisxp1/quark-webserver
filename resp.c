/* See LICENSE file for copyright and license details. */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "http.h"
#include "resp.h"
#include "util.h"

static int
compareent(const struct dirent **d1, const struct dirent **d2)
{
	int v;

	v = ((*d2)->d_type == DT_DIR ? 1 : -1) -
	    ((*d1)->d_type == DT_DIR ? 1 : -1);
	if (v) {
		return v;
	}

	return strcmp((*d1)->d_name, (*d2)->d_name);
}

static char *
suffix(int t)
{
	switch (t) {
	case DT_FIFO: return "|";
	case DT_DIR:  return "/";
	case DT_LNK:  return "@";
	case DT_SOCK: return "=";
	}

	return "";
}

static void
html_escape(char *src, char *dst, size_t dst_siz)
{
	const struct {
		char c;
		char *s;
	} escape[] = {
		{ '&',  "&amp;"  },
		{ '<',  "&lt;"   },
		{ '>',  "&gt;"   },
		{ '"',  "&quot;" },
		{ '\'', "&#x27;" },
	};
	size_t i, j, k, esclen;

	for (i = 0, j = 0; src[i] != '\0'; i++) {
		for (k = 0; k < LEN(escape); k++) {
			if (src[i] == escape[k].c) {
				break;
			}
		}
		if (k == LEN(escape)) {
			/* no escape char at src[i] */
			if (j == dst_siz - 1) {
				/* silent truncation */
				break;
			} else {
				dst[j++] = src[i];
			}
		} else {
			/* escape char at src[i] */
			esclen = strlen(escape[k].s);

			if (j >= dst_siz - esclen) {
				/* silent truncation */
				break;
			} else {
				memcpy(&dst[j], escape[k].s, esclen);
				j += esclen;
			}
		}
	}
	dst[j] = '\0';
}

enum status
resp_dir(int fd, char *name, struct request *r)
{
	enum status sendstatus;
	struct dirent **e;
	struct response res = {
		.status                  = S_OK,
		.field[RES_CONTENT_TYPE] = "text/html; charset=utf-8",
	};
	size_t i;
	int dirlen;
	char esc[PATH_MAX /* > NAME_MAX */ * 6]; /* strlen("&...;") <= 6 */

	/* read directory */
	if ((dirlen = scandir(name, &e, NULL, compareent)) < 0) {
		return http_send_status(fd, S_FORBIDDEN);
	}

	/* send header as late as possible */
	if ((sendstatus = http_send_header(fd, &res)) != res.status) {
		res.status = sendstatus;
		goto cleanup;
	}

	if (r->method == M_GET) {
		/* listing header */
		html_escape(name, esc, sizeof(esc));
		if (dprintf(fd,
		            "<!DOCTYPE html>\n<html>\n\t<head>"
		            "<title>Index of %s</title></head>\n"
		            "\t<body>\n\t\t<a href=\"..\">..</a>",
		            esc) < 0) {
			res.status = S_REQUEST_TIMEOUT;
			goto cleanup;
		}

		/* listing */
		for (i = 0; i < (size_t)dirlen; i++) {
			/* skip hidden files, "." and ".." */
			if (e[i]->d_name[0] == '.') {
				continue;
			}

			/* entry line */
			html_escape(e[i]->d_name, esc, sizeof(esc));
			if (dprintf(fd, "<br />\n\t\t<a href=\"%s%s\">%s%s</a>",
			            esc,
			            (e[i]->d_type == DT_DIR) ? "/" : "",
			            esc,
			            suffix(e[i]->d_type)) < 0) {
				res.status = S_REQUEST_TIMEOUT;
				goto cleanup;
			}
		}

		/* listing footer */
		if (dprintf(fd, "\n\t</body>\n</html>\n") < 0) {
			res.status = S_REQUEST_TIMEOUT;
			goto cleanup;
		}
	}

cleanup:
	while (dirlen--) {
		free(e[dirlen]);
	}
	free(e);

	return res.status;
}

enum status
resp_file(int fd, char *name, struct request *r, struct stat *st, char *mime,
          off_t lower, off_t upper)
{
	FILE *fp;
	enum status sendstatus;
	struct response res = {
		.status = (r->field[REQ_RANGE][0] != '\0') ?
		          S_PARTIAL_CONTENT : S_OK,
		.field[RES_ACCEPT_RANGES] = "bytes",
	};
	ssize_t bread, bwritten;
	off_t remaining;
	static char buf[BUFSIZ], *p;

	/* open file */
	if (!(fp = fopen(name, "r"))) {
		res.status = http_send_status(fd, S_FORBIDDEN);
		goto cleanup;
	}

	/* seek to lower bound */
	if (fseek(fp, lower, SEEK_SET)) {
		res.status = http_send_status(fd, S_INTERNAL_SERVER_ERROR);
		goto cleanup;
	}

	/* build header */
	if (esnprintf(res.field[RES_CONTENT_LENGTH],
	              sizeof(res.field[RES_CONTENT_LENGTH]),
	              "%zu", upper - lower + 1)) {
		return http_send_status(fd, S_INTERNAL_SERVER_ERROR);
	}
	if (r->field[REQ_RANGE][0] != '\0') {
		if (esnprintf(res.field[RES_CONTENT_RANGE],
		              sizeof(res.field[RES_CONTENT_RANGE]),
		              "bytes %zd-%zd/%zu", lower, upper,
			      st->st_size)) {
			return http_send_status(fd, S_INTERNAL_SERVER_ERROR);
		}
	}
	if (esnprintf(res.field[RES_CONTENT_TYPE],
	              sizeof(res.field[RES_CONTENT_TYPE]),
	              "%s", mime)) {
		return http_send_status(fd, S_INTERNAL_SERVER_ERROR);
	}
	if (timestamp(res.field[RES_LAST_MODIFIED],
	              sizeof(res.field[RES_LAST_MODIFIED]),
	              st->st_mtim.tv_sec)) {
		return http_send_status(fd, S_INTERNAL_SERVER_ERROR);
	}

	/* send header as late as possible */
	if ((sendstatus = http_send_header(fd, &res)) != res.status) {
		res.status = sendstatus;
		goto cleanup;
	}

	if (r->method == M_GET) {
		/* write data until upper bound is hit */
		remaining = upper - lower + 1;

		while ((bread = fread(buf, 1, MIN(sizeof(buf),
		                      (size_t)remaining), fp))) {
			if (bread < 0) {
				res.status = S_INTERNAL_SERVER_ERROR;
				goto cleanup;
			}
			remaining -= bread;
			p = buf;
			while (bread > 0) {
				bwritten = write(fd, p, bread);
				if (bwritten <= 0) {
					res.status = S_REQUEST_TIMEOUT;
					goto cleanup;
				}
				bread -= bwritten;
				p += bwritten;
			}
		}
	}
cleanup:
	if (fp) {
		fclose(fp);
	}

	return res.status;
}
