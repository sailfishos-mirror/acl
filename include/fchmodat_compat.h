#ifndef FCHMODAT_COMPAT_H
#define FCHMODAT_COMPAT_H

#include <fcntl.h>

int fchmodat_compat(int dirfd, const char *pathname, mode_t mode, int flags);

#ifndef DECLARATIONS_ONLY
# define fchmodat fchmodat_compat
#endif

#endif /* FCHMODAT_COMPAT_H */
