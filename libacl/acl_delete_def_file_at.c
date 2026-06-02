/*
  File: acl_delete_def_file_at.c

  Copyright (C) 1999, 2000
  Andreas Gruenbacher, <andreas.gruenbacher@gmail.com>
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
#include <sys/types.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include "acl_ea.h"
#include "xattrat_compat.h"
#include "libacl.h"

int
acl_delete_def_file_at(int dirfd, const char *path_p, int at_flags)
{
	int error;

	if (at_flags & ~(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW)) {
		errno = EINVAL;
		return -1;
	}

	error = removexattrat(dirfd, path_p, at_flags, ACL_EA_DEFAULT);
	if (error < 0 && errno != ENOATTR && errno != ENODATA)
		return -1;
	return 0;
}

