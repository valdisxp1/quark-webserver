/* See LICENSE file for copyright and license details. */
#ifndef RESP_H
#define RESP_H

#include <sys/stat.h>
#include <sys/types.h>

#include "http.h"

enum status resp_dir(int, const struct response *);
enum status resp_file(int, const struct response *);

#endif /* RESP_H */
