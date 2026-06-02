/*
  File: acl_extended_file_at.c

  Copyright (C) 2000, 2011
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
#include <unistd.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include "libacl.h"
#include "xattrat_compat.h"
#include "acl_ea.h"


int
acl_extended_file_at(int dirfd, const char *path_p, int at_flags)
{
	int base_size = sizeof(acl_ea_header) + 3 * sizeof(acl_ea_entry);
	int retval;

	if (at_flags & ~(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW)) {
		errno = EINVAL;
		return -1;
	}

	retval = getxattrat(dirfd, path_p, at_flags, ACL_EA_ACCESS, NULL, 0);
	if (retval < 0 && errno != ENOATTR && errno != ENODATA)
		return -1;
	if (retval > base_size)
		return 1;
	retval = getxattrat(dirfd, path_p, at_flags, ACL_EA_DEFAULT, NULL, 0);
	if (retval < 0 && errno != ENOATTR && errno != ENODATA)
		return -1;
	if (retval >= base_size)
		return 1;
	return 0;
}
