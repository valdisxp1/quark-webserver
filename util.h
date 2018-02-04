/* See LICENSE file for copyright and license details. */
#ifndef UTIL_H
#define UTIL_H

#include <time.h>

#include "arg.h"

#undef MIN
#define MIN(x,y)  ((x) < (y) ? (x) : (y))
#undef MAX
#define MAX(x,y)  ((x) > (y) ? (x) : (y))
#undef LEN
#define LEN(x) (sizeof (x) / sizeof *(x))

extern char *argv0;

void warn(const char *, ...);
void die(const char *, ...);

long long strtonum(const char *, long long, long long, const char **);

#define TIMESTAMP_LEN 30

char *timestamp(time_t, char buf[TIMESTAMP_LEN]);

#endif /* UTIL_H */
