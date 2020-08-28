/* See LICENSE file for copyright and license details. */
#ifndef DATA_H
#define DATA_H

#include "http.h"

enum status data_send_dirlisting(int, const struct response *);
enum status data_send_error(int, const struct response *);
enum status data_send_file(int, const struct response *);

#endif /* DATA_H */
