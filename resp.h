/* See LICENSE file for copyright and license details. */
#ifndef RESP_H
#define RESP_H

#include <sys/stat.h>
#include <sys/types.h>

#include "http.h"

enum status resp_dir(int, const char *, const struct request *);
enum status resp_file(int, const char *, const struct request *,
                      const struct stat *, const char *, off_t, off_t);

#endif /* RESP_H */
