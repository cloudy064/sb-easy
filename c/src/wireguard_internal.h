/* Private helpers shared by the wireguard*.c files. Not part of the public API. */
#ifndef SB_WIREGUARD_INTERNAL_H
#define SB_WIREGUARD_INTERNAL_H
#include "sb/wireguard.h"

#define S(x) ((x) ? (x) : "")

struct sb_wireguard {
    sb_store *store;
    sb_wireguard_options options;
};

int run(const char *const *argv, bool check, int *exit_code, sb_err *err);
char *subnet_cidr(const char *address);

#endif
