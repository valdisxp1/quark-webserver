/* See LICENSE file for copyright and license details. */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "http.h"
#include "data.h"
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
html_escape(const char *src, char *dst, size_t dst_siz)
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
data_send_dirlisting(int fd, const struct response *res)
{
	enum status ret = 0;
	struct dirent **e;
	size_t i;
	int dirlen;
	char esc[PATH_MAX /* > NAME_MAX */ * 6]; /* strlen("&...;") <= 6 */

	/* read directory */
	if ((dirlen = scandir(res->path, &e, NULL, compareent)) < 0) {
		return S_FORBIDDEN;
	}

	/* listing header (we use esc because sizeof(esc) >= PATH_MAX) */
	html_escape(res->uri, esc, MIN(PATH_MAX, sizeof(esc)));
	if (dprintf(fd,
	            "<!DOCTYPE html>\n<html>\n\t<head>"
	            "<title>Index of %s</title></head>\n"
	            "\t<body>\n\t\t<a href=\"..\">..</a>",
	            esc) < 0) {
		ret = S_REQUEST_TIMEOUT;
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
			ret = S_REQUEST_TIMEOUT;
			goto cleanup;
		}
	}

	/* listing footer */
	if (dprintf(fd, "\n\t</body>\n</html>\n") < 0) {
		ret = S_REQUEST_TIMEOUT;
		goto cleanup;
	}

cleanup:
	while (dirlen--) {
		free(e[dirlen]);
	}
	free(e);

	return ret;
}

enum status
data_send_error(int fd, const struct response *res)
{
	if (dprintf(fd,
	            "<!DOCTYPE html>\n<html>\n\t<head>\n"
	            "\t\t<title>%d %s</title>\n\t</head>\n\t<body>\n"
	            "\t\t<h1>%d %s</h1>\n\t</body>\n</html>\n",
	            res->status, status_str[res->status],
		    res->status, status_str[res->status]) < 0) {
		return S_REQUEST_TIMEOUT;
	}

	return 0;
}

enum status
data_send_file(int fd, const struct response *res)
{
	FILE *fp;
	enum status ret = 0;
	ssize_t bread, bwritten;
	size_t remaining;
	static char buf[BUFSIZ], *p;

	/* open file */
	if (!(fp = fopen(res->path, "r"))) {
		ret = S_FORBIDDEN;
		goto cleanup;
	}

	/* seek to lower bound */
	if (fseek(fp, res->file.lower, SEEK_SET)) {
		ret = S_INTERNAL_SERVER_ERROR;
		goto cleanup;
	}

	/* write data until upper bound is hit */
	remaining = res->file.upper - res->file.lower + 1;

	while ((bread = fread(buf, 1, MIN(sizeof(buf),
	                      remaining), fp))) {
		if (bread < 0) {
			ret = S_INTERNAL_SERVER_ERROR;
			goto cleanup;
		}
		remaining -= bread;
		p = buf;
		while (bread > 0) {
			bwritten = write(fd, p, bread);
			if (bwritten <= 0) {
				ret = S_REQUEST_TIMEOUT;
				goto cleanup;
			}
			bread -= bwritten;
			p += bwritten;
		}
	}
cleanup:
	if (fp) {
		fclose(fp);
	}

	return ret;
}
