/*
  File: fchmodat_compat.c

  Copyright (C) 2026 Andreas Gruenbacher <andreas.gruenbacher@gmail.com>

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, see <https://www.gnu.org/licenses/>.
*/

#include "config.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "libmisc/proc-self-fd.h"

#define DECLARATIONS_ONLY
#include "fchmodat_compat.h"

/*
 * Support for the AT_SYMLINK_NOFOLLOW flag was added in commit 09da082b07bb
 * ("fs: Add fchmodat2()") and support for the AT_EMPTY_PATH flag was added in
 * commit 5daeb41a6fc9d ("fchmodat2: add support for AT_EMPTY_PATH"), both
 * merged in kernel version 6.6 from October 2023.
 */

static int no_symlink_nofollow;

int fchmodat_compat(int dirfd, const char *pathname, mode_t mode, int flags)
{
	struct proc_self_fd_buffer buffer;
	int fd = dirfd;
	int ret;

	if ((flags & AT_SYMLINK_NOFOLLOW) && no_symlink_nofollow)
			goto no_symlink_nofollow;
	if ((flags & AT_EMPTY_PATH) && no_symlink_nofollow) {
		if (!*pathname)
			goto proc_self_fd_path;
		flags &= ~AT_EMPTY_PATH;
	}
	ret = fchmodat(dirfd, pathname, mode, flags);
	if (ret != -1)
		return ret;
	if (errno == ENOTSUP && (flags & AT_SYMLINK_NOFOLLOW)) {
		no_symlink_nofollow = 1;
		goto no_symlink_nofollow;
	}
	if (errno == EINVAL && (flags & AT_EMPTY_PATH)) {
		no_symlink_nofollow = 1;
		goto proc_self_fd_path;
	}
	return ret;

no_symlink_nofollow:
	if (*pathname) {
		int open_flags = O_PATH | O_CLOEXEC;
		if (flags & AT_SYMLINK_NOFOLLOW)
			open_flags |= O_NOFOLLOW;
		fd = openat(dirfd, pathname, open_flags);
		if (fd == -1)
			return -1;
	}
	/* fall through */

proc_self_fd_path:
	ret = chmod(proc_self_fd_path(fd, &buffer), mode);
	if (ret == -1 && errno == ENOENT)
		errno = EBADF;
	if (fd != dirfd) {
		int saved_errno = errno;
		close(fd);
		errno = saved_errno;
	}
	return ret;
}
