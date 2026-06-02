/*
  File: acl_get_file_at.c

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
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include "libacl.h"
#include "xattrat_compat.h"
#include "__acl_from_xattr.h"
#include "acl_ea.h"

acl_t
acl_get_file_at(int dirfd, const char *path_p, int at_flags, acl_type_t type)
{
	size_t size_guess = acl_ea_size(16);
	char *onstack_buffer = alloca(size_guess);
	char *ext_acl_p = onstack_buffer;
	const char *name;
	acl_t acl = NULL;
	int retries = 0;
	int retval;

	switch(type) {
		case ACL_TYPE_ACCESS:
			name = ACL_EA_ACCESS;
			break;
		case ACL_TYPE_DEFAULT:
			name = ACL_EA_DEFAULT;
			break;
		default:
			errno = EINVAL;
			goto out;
	}

	if (at_flags & ~(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW)) {
		errno = EINVAL;
		goto out;
	}

	for (;;) {
		retval = getxattrat(dirfd, path_p, at_flags, name, ext_acl_p,
				    size_guess);
		if (retval != -1 || errno != ERANGE)
			break;
		if (++retries >= 8)
			break;

		retval = getxattrat(dirfd, path_p, at_flags, name, NULL, 0);
		if (retval <= 0)
			break;
		size_guess = retval;

		if (ext_acl_p != onstack_buffer)
			free(ext_acl_p);
		ext_acl_p = malloc(size_guess);
		if (!ext_acl_p)
                       goto out;
	}
	if (retval > 0) {
		acl = __acl_from_xattr(ext_acl_p, retval);
	} else if (retval == 0 || errno == ENOATTR || errno == ENODATA) {
		struct stat st;

		if (fstatat(dirfd, path_p, &st, at_flags) != 0)
			goto out;

		if (S_ISLNK(st.st_mode)) {
			errno = ENOTSUP;
			goto out;
		}
		if (type == ACL_TYPE_DEFAULT) {
			if (S_ISDIR(st.st_mode))
				acl = acl_init(0);
			else
				errno = EACCES;
		} else
			acl = acl_from_mode(st.st_mode);
	}

out:
	if (ext_acl_p != onstack_buffer)
		free(ext_acl_p);
	return acl;
}

