/* Copy POSIX 1003.1e draft 17 (abandoned) ACLs between files. */
 
/* Copyright (C) 2002 Andreas Gruenbacher <agruen@suse.de>, SuSE Linux AG.

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
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include "libacl.h"
#include "fchmodat_compat.h"

#define ERROR_CONTEXT_MACROS
#include <attr/error_context.h>

/* Set the access control list of path to the permissions defined by mode.  */
static int
set_acl_fd (char const *path, int fd, mode_t mode, struct error_context *ctx)
{
	int ret = 0;
	acl_t acl = acl_from_mode (mode);
	if (!acl) {
		error (ctx, "");
		return -1;
	}

	if (acl_set_file_at (fd, "", AT_EMPTY_PATH, ACL_TYPE_ACCESS, acl) != 0) {
		ret = -1;
		if (errno == ENOTSUP || errno == ENOSYS) {
			(void) acl_free (acl);
			goto chmod_only;
		} else {
			const char *qpath = quote (ctx, path);
			error (ctx, _("setting permissions for %s"), qpath);
			quote_free (ctx, qpath);
		}
	}
	(void) acl_free (acl);
	return ret;

chmod_only:
	ret = fchmodat (fd, "", mode, AT_EMPTY_PATH);
	if (ret != 0) {
		const char *qpath = quote (ctx, path);
		error (ctx, _("setting permissions for %s"), qpath);
		quote_free (ctx, qpath);
	}
	return ret;
}

/* Copy the permissions of src_path to dst_path. This includes the
   file mode permission bits and ACLs. File ownership is not copied.
 */
int
perm_copy_fd (const char *src_path, int src_fd,
	       const char *dst_path, int dst_fd,
	       struct error_context *ctx)
{
	acl_t acl;
	struct stat st;
	int ret = 0;

	ret = fstat(src_fd, &st);
	if (ret != 0) {
		const char *qpath = quote (ctx, src_path);
		error (ctx, "%s", qpath);
		quote_free (ctx, qpath);
		return -1;
	}
	acl = acl_get_file_at (src_fd, "", AT_EMPTY_PATH, ACL_TYPE_ACCESS);
	if (acl == NULL) {
		ret = -1;
		if (errno == ENOSYS || errno == ENOTSUP)
			ret = set_acl_fd (dst_path, dst_fd, st.st_mode, ctx);
		else {
			const char *qpath = quote (ctx, src_path);
			error (ctx, "%s", qpath);
			quote_free (ctx, qpath);
		}
		return ret;
	}

	if (acl_set_file_at (dst_fd, "", AT_EMPTY_PATH, ACL_TYPE_ACCESS, acl) != 0) {
		int saved_errno = errno;
		__acl_apply_mask_to_mode(&st.st_mode, acl);
		ret = fchmodat (dst_fd, "", st.st_mode, AT_EMPTY_PATH);
		if ((errno != ENOSYS && errno != ENOTSUP) ||
		    acl_entries (acl) != 3) {
			const char *qpath = quote (ctx, dst_path);
			errno = saved_errno;
			error (ctx, _("preserving permissions for %s"), qpath);
			quote_free (ctx, qpath);
			ret = -1;
		}
	}
	(void) acl_free (acl);

	if (ret == 0 && S_ISDIR (st.st_mode)) {
		acl = acl_get_file_at (src_fd, "", AT_EMPTY_PATH, ACL_TYPE_DEFAULT);
		if (acl == NULL) {
			const char *qpath = quote (ctx, src_path);
			error (ctx, "%s", qpath);
			quote_free (ctx, qpath);
			return -1;
		}
		if (acl_entries(acl) == 0)
			ret = acl_delete_def_file_at(dst_fd, "", AT_EMPTY_PATH);
		else
			ret = acl_set_file_at (dst_fd, "", AT_EMPTY_PATH, ACL_TYPE_DEFAULT, acl);
		if (ret != 0) {
			const char *qpath = quote (ctx, dst_path);
			error (ctx, _("preserving permissions for %s"), qpath);
			quote_free (ctx, qpath);
		}
		(void) acl_free(acl);
	}
	return ret;
}

