/* See LICENSE file for copyright and license details. */
#ifndef HTTP_H
#define HTTP_H

#include <limits.h>

#include "util.h"

#define HEADER_MAX 4096
#define FIELD_MAX 200

enum req_field {
	REQ_HOST,
	REQ_RANGE,
	REQ_IF_MODIFIED_SINCE,
	NUM_REQ_FIELDS,
};

extern const char *req_field_str[];

enum req_method {
	M_GET,
	M_HEAD,
	NUM_REQ_METHODS,
};

extern const char *req_method_str[];

struct request {
	enum req_method method;
	char uri[PATH_MAX];
	char field[NUM_REQ_FIELDS][FIELD_MAX];
};

enum status {
	S_OK                    = 200,
	S_PARTIAL_CONTENT       = 206,
	S_MOVED_PERMANENTLY     = 301,
	S_NOT_MODIFIED          = 304,
	S_BAD_REQUEST           = 400,
	S_FORBIDDEN             = 403,
	S_NOT_FOUND             = 404,
	S_METHOD_NOT_ALLOWED    = 405,
	S_REQUEST_TIMEOUT       = 408,
	S_RANGE_NOT_SATISFIABLE = 416,
	S_REQUEST_TOO_LARGE     = 431,
	S_INTERNAL_SERVER_ERROR = 500,
	S_VERSION_NOT_SUPPORTED = 505,
};

extern const char *status_str[];

enum res_field {
	RES_ACCEPT_RANGES,
	RES_ALLOW,
	RES_LOCATION,
	RES_LAST_MODIFIED,
	RES_CONTENT_LENGTH,
	RES_CONTENT_RANGE,
	RES_CONTENT_TYPE,
	NUM_RES_FIELDS,
};

extern const char *res_field_str[];

enum res_type {
	RESTYPE_ERROR,
	RESTYPE_FILE,
	RESTYPE_DIRLISTING,
	NUM_RES_TYPES,
};

struct response {
	enum res_type type;
	enum status status;
	char field[NUM_RES_FIELDS][FIELD_MAX];
	char uri[PATH_MAX];
	char path[PATH_MAX];
	struct {
		size_t lower;
		size_t upper;
	} file;
};

enum conn_state {
	C_VACANT,
	C_RECV_HEADER,
	C_SEND_HEADER,
	C_SEND_DATA,
	NUM_CONN_STATES,
};

struct connection {
	enum conn_state state;
	int fd;
	char header[HEADER_MAX]; /* general req/res-header buffer */
	size_t off;              /* general offset (header/file/dir) */
	struct request req;
	struct response res;
};

enum status http_send_header(int, const struct response *);
enum status http_send_status(int, enum status);
enum status http_recv_header(int, char *, size_t, size_t *);
enum status http_parse_header(const char *, struct request *);
enum status http_prepare_response(const struct request *, struct response *,
                                  const struct server *);

#endif /* HTTP_H */
