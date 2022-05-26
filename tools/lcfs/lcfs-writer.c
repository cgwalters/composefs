/* lcfs
   Copyright (C) 2021 Giuseppe Scrivano <giuseppe@scrivano.org>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define _GNU_SOURCE

#include "lcfs.h"
#include "lcfs-writer.h"
#include "hash.h"

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/xattr.h>
#include <assert.h>

/* In memory representation used to build the file.  */

struct lcfs_xattr_s {
	char *key;
	char *value;
	size_t value_len;
};

struct lcfs_node_s {
	struct lcfs_node_s *next; /* Use for the queue in compute_tree */

	struct lcfs_node_s *parent;

	struct lcfs_node_s **children;
	size_t children_size;

	/* Used to create hard links.  */
	struct lcfs_node_s *link_to;

	bool in_tree;

	char *name;
	char *payload;
	uint64_t st_size;
	struct lcfs_dentry_s data;
	lcfs_off_t inode_index;

	struct lcfs_xattr_s *xattrs;
	size_t n_xattrs;

	struct lcfs_inode_s inode;
};

struct lcfs_ctx_s {
	char *vdata;
	size_t vdata_len;
	size_t vdata_allocated;
	size_t curr_off;
	struct lcfs_node_s *root;

	/* User for dedup.  */
	Hash_table *ht;

	/* Used by compute_tree.  */
	struct lcfs_node_s *queue_end;
	loff_t inode_table_size;
};

int lcfs_append_vdata(struct lcfs_ctx_s *ctx, struct lcfs_vdata_s *out,
		      const void *data, size_t len);

int lcfs_append_vdata_no_dedup(struct lcfs_ctx_s *ctx, struct lcfs_vdata_s *out,
			       const void *data, size_t len);

int lcfs_append_vdata_opts(struct lcfs_ctx_s *ctx, struct lcfs_vdata_s *out,
			   const void *data, size_t len, bool dedup);

static int lcfs_close(struct lcfs_ctx_s *ctx);

static char *memdup(const char *s, size_t len)
{
	char *s2 = malloc(len);
	if (s2 == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	memcpy(s2, s, len);
	return s2;
}


struct hasher_vdata_s {
	const char *const *vdata;
	lcfs_off_t off;
	lcfs_off_t len;
};

static size_t hash_memory(const char *string, size_t len, size_t n_buckets)
{
	size_t i, value = 0;

	for (i = 0; i < len; i++) {
		value = (value * 31 + string[i]) % n_buckets;
	}
	return value;
}

static size_t vdata_ht_hasher(const void *d, size_t n)
{
	const struct hasher_vdata_s *v = d;

	return hash_memory(*v->vdata + v->off, v->len, n);
}

static bool vdata_ht_comparator(const void *d1, const void *d2)
{
	const struct hasher_vdata_s *v1 = d1;
	const struct hasher_vdata_s *v2 = d2;
	const char *c1, *c2;

	if (v1->len != v2->len)
		return false;

	c1 = *v1->vdata + v1->off;
	c2 = *v2->vdata + v2->off;

	return memcmp(c1, c2, v1->len) == 0;
}

static void vdata_ht_freer(void *data)
{
	free(data);
}

static struct lcfs_ctx_s *lcfs_new_ctx(void)
{
	struct lcfs_ctx_s *ret;

	ret = calloc(1, sizeof *ret);
	if (ret == NULL)
		return ret;

	ret->ht = hash_initialize(0, NULL, vdata_ht_hasher, vdata_ht_comparator,
				  vdata_ht_freer);

	return ret;
}

#define max(a, b) ((a > b) ? (a) : (b))

int lcfs_append_vdata_opts(struct lcfs_ctx_s *ctx, struct lcfs_vdata_s *out,
			   const void *data, size_t len, bool dedup)
{
	struct hasher_vdata_s *key;
	char *new_vdata;

	if (dedup) {
		struct hasher_vdata_s *ent;
		const char *_data = data;
		struct hasher_vdata_s hkey = {
			.vdata = (const char *const *)&_data,
			.off = 0,
			.len = len,
		};

		ent = hash_lookup(ctx->ht, &hkey);
		if (ent) {
			out->off = ent->off;
			out->len = ent->len;
			return 0;
		}
	}

	if (ctx->vdata_len + len > ctx->vdata_allocated) {
		size_t new_size, increment;

		increment = max(1 << 20, len);

		new_size = ctx->vdata_allocated + increment;
		new_vdata = realloc(ctx->vdata, new_size);
		if (new_vdata == NULL)
			return -1;

		ctx->vdata_allocated = new_size;
		ctx->vdata = new_vdata;
	}

	memcpy(ctx->vdata + ctx->vdata_len, data, len);

	out->off = ctx->vdata_len;
	out->len = len;

	/* Update to the new length.  */
	ctx->vdata_len += len;

	key = malloc(sizeof(struct hasher_vdata_s));
	if (key) {
		void *ent;

		key->vdata = (const char *const *)&ctx->vdata;
		key->off = out->off;
		key->len = out->len;

		ent = hash_insert(ctx->ht, key);
		/* Should not really happen.  */
		if (ent != key)
			free(key);
	}

	return 0;
}

static int node_get_dtype(struct lcfs_node_s *node)
{
	switch ((node->inode.st_mode & S_IFMT)) {
	case S_IFLNK:
		return DT_LNK;
	case S_IFDIR:
		return DT_DIR;
	case S_IFREG:
		return DT_REG;
	case S_IFBLK:
		return DT_BLK;
	case S_IFCHR:
		return DT_CHR;
	case S_IFSOCK:
		return DT_SOCK;
	case S_IFIFO:
		return DT_FIFO;
	default:
		return DT_UNKNOWN;
	}
}

static int cmp_nodes(const void *a, const void *b)
{
	const struct lcfs_node_s *na = *((const struct lcfs_node_s **)a);
	const struct lcfs_node_s *nb = *((const struct lcfs_node_s **)b);

	return strcmp(na->name, nb->name);
}

static int cmp_xattr(const void *a, const void *b)
{
	const struct lcfs_xattr_s *na = a;
	const struct lcfs_xattr_s *nb = b;

	return strcmp(na->key, nb->key);
}

static ssize_t compute_payload_size(struct lcfs_node_s *node)
{
	ssize_t payload_size = 0;
	size_t i;

	if ((node->inode.st_mode & S_IFMT) == S_IFLNK) {
		if (node->payload && strlen(node->payload) != 0) {
			payload_size = strlen(node->payload);
		}
	} else if ((node->inode.st_mode & S_IFMT) == S_IFREG) {
		if (node->payload && strlen(node->payload) != 0 && node->st_size != 0) {
			payload_size = lcfs_backing_size(strlen(node->payload));
		}
	} else if ((node->inode.st_mode & S_IFMT) == S_IFDIR) {
		if (node->children_size > 0) {
			size_t names_len = 0;

			for (i = 0; i < node->children_size; i++) {
				struct lcfs_node_s *child = node->children[i];
				/* Need valid names for all children */
				if (child->name == NULL ||
				    strlen(child->name) > UINT16_MAX) {
					errno = EINVAL;
					return -1;
				}
				names_len += strlen(child->name);
			}
			payload_size = lcfs_dir_size(node->children_size) + names_len;
		}
	}

	return payload_size;
}

/* This ensures that the tree is in a well defined order, with
   children sorted by name, and the nodes visited in breadth-first
   order.  It also updates the payload length of the nodes and using
   that, their inode offset. */
static int compute_tree(struct lcfs_ctx_s *ctx, struct lcfs_node_s *root)
{
	size_t i;
	ssize_t payload_length;
	struct lcfs_node_s *node;

	/* Start with the root node. */

	ctx->queue_end = root;
	root->in_tree = true;

	node = root;

	for (node = root; node != NULL; node = node->next) {
		if ((node->inode.st_mode & S_IFMT) != S_IFDIR &&
		    node->children_size != 0) {
			/* Only dirs can have children */
			errno = EINVAL;
			return -1;
		}

		/* Fix up directory n_links counts, they are 2 + nr of subdirs */
		if ((node->inode.st_mode & S_IFMT) == S_IFDIR) {
			size_t n_link = 2;
			for (i = 0; i < node->children_size; i++) {
				struct lcfs_node_s *child = node->children[i];
				if ((child->inode.st_mode & S_IFMT) == S_IFDIR) {
					n_link++;
				}
			}
			node->inode.st_nlink = n_link;
		}

		/* Canonical order */
		qsort(node->children, node->children_size, sizeof(node->children[0]), cmp_nodes);
		qsort(node->xattrs, node->n_xattrs, sizeof(node->xattrs[0]), cmp_xattr);

		/* Compute payload length */
		payload_length = compute_payload_size(node);
		if (payload_length < 0)
			return payload_length;
		if (payload_length > UINT32_MAX) {
			errno = EINVAL;
			return -1;
		}
		node->inode.payload_length = payload_length;

		/* Assign inode index */
		node->inode_index = ctx->inode_table_size;
		ctx->inode_table_size += sizeof(struct lcfs_inode_s) + payload_length;

		node->in_tree = true;
		/* Append to queue for more work */
		for (i = 0; i < node->children_size; i++) {
			struct lcfs_node_s *child = node->children[i];

			/* Skip hardlinks, they will not be serialized separately */
			if (node->link_to != NULL) {
				continue;
			}

			/* Avoid recursion */
			assert(!child->in_tree);

			ctx->queue_end->next = child;
			ctx->queue_end = child;
		}
	}

	return 0;
}

/* Canonicalizes and computes xattrs, sharing equal vdatas */
static int compute_xattrs(struct lcfs_ctx_s *ctx) {
	struct lcfs_node_s *node;
	size_t data_length;
	size_t i;
	uint8_t *buffer, *data;
	size_t header_len;
	size_t buffer_len;
	struct lcfs_xattr_header_s *header;
	struct lcfs_vdata_s out;
	int r;

	for (node = ctx->root; node != NULL; node = node->next) {
		qsort(node->xattrs, node->n_xattrs, sizeof(node->xattrs[0]), cmp_xattr);

		if (node->n_xattrs == 0)
			continue;

		data_length = 0;
		for (i = 0; i < node->n_xattrs; i++) {
			struct lcfs_xattr_s *xattr = &node->xattrs[i];
			data_length += strlen(xattr->key) + xattr->value_len;
		}
		header_len = lcfs_xattr_header_size(node->n_xattrs);
		buffer_len = header_len + data_length;
		buffer = calloc(1, buffer_len);
		if (buffer == NULL) {
			errno = ENOMEM;
			return -1;
		}
		header = (struct lcfs_xattr_header_s *)buffer;
		header->n_attr = node->n_xattrs;

		data = buffer +  header_len;
		for (i = 0; i < node->n_xattrs; i++) {
			struct lcfs_xattr_s *xattr = &node->xattrs[i];

			header->attr[i].key_length = strlen(xattr->key);
			memcpy(data, xattr->key, strlen(xattr->key));
			data += strlen(xattr->key);

			header->attr[i].value_length = xattr->value_len;
			memcpy(data, xattr->value, xattr->value_len);
			data += xattr->value_len;
		}

		r = lcfs_append_vdata(ctx, &out, buffer, buffer_len);
		if (r < 0) {
			free(buffer);
			return r;
		}

		free(buffer);

		node->inode.xattrs = out;
	}

	return 0;
}

static struct lcfs_node_s *follow_links(struct lcfs_node_s *node) {
	if (node->link_to)
		return follow_links(node->link_to);
	return node;
}

static int write_inodes(struct lcfs_ctx_s *ctx, FILE *out) {
	struct lcfs_node_s *node;
	size_t i;
	int ret;

	for (node = ctx->root; node != NULL; node = node->next) {
		struct lcfs_inode_s *ino = &(node->inode);

		ret = fwrite(ino, sizeof(struct lcfs_inode_s), 1, out);
		if (ret < 0)
			return ret;

		if (ino->payload_length == 0)
			continue;

		if ((node->inode.st_mode & S_IFMT) == S_IFLNK) {
			ret = fwrite(node->payload, strlen(node->payload), 1, out);
			if (ret < 0)
				return ret;
		} else if ((node->inode.st_mode & S_IFMT) == S_IFREG) {
			struct lcfs_backing_s backing = { node->st_size };
			backing.payload_len = strlen(node->payload);

			ret = fwrite(&backing, sizeof(backing), 1, out);
			if (ret < 0)
				return ret;
			ret = fwrite(node->payload, strlen(node->payload), 1, out);
			if (ret < 0)
				return ret;
		} else if ((node->inode.st_mode & S_IFMT) == S_IFDIR) {
			struct lcfs_dir_s dir = { node->children_size };
			ret = fwrite(&dir, sizeof(dir), 1, out);
			if (ret < 0)
				return ret;
			for (i = 0; i < node->children_size; i++) {
				struct lcfs_node_s *dirent_child = node->children[i];
				struct lcfs_node_s *target_child = follow_links(dirent_child);
				struct lcfs_dentry_s dentry;

				dentry.inode_index = target_child->inode_index;
				dentry.name_len = strlen(dirent_child->name);
				dentry.d_type = node_get_dtype(target_child);
				dentry.pad = 0;
				ret = fwrite(&dentry, sizeof(dentry), 1, out);
				if (ret < 0)
					return ret;
			}
			for (i = 0; i < node->children_size; i++) {
				struct lcfs_node_s *dirent_child = node->children[i];
				ret = fwrite(dirent_child->name, strlen(dirent_child->name), 1, out);
				if (ret < 0)
					return ret;
			}
		}
	}

	return 0;
}

int lcfs_write_to(struct lcfs_node_s *root, FILE *out)
{
	struct lcfs_header_s header = {
		.version = LCFS_VERSION,
		.unused1 = 0,
		.unused2 = 0,
		.inode_len = sizeof(struct lcfs_inode_s),
	};
	int ret = 0;
	struct lcfs_ctx_s *ctx;

	ctx = lcfs_new_ctx();
	if (ctx == NULL) {
		errno = ENOMEM;
		return -1;
	}

	ctx->root = root;

	ret = compute_tree(ctx, root);
	if (ret < 0) {
		lcfs_close(ctx);
		return ret;
	}

	header.data_offset = sizeof(struct lcfs_header_s) + ctx->inode_table_size;

	ret = compute_xattrs(ctx);
	if (ret < 0) {
		lcfs_close(ctx);
		return ret;
	}

	ret = fwrite(&header, sizeof(header), 1, out);
	if (ret < 0) {
		lcfs_close(ctx);
		return ret;
	}

	ret = write_inodes(ctx, out);
	if (ret < 0) {
		lcfs_close(ctx);
		return ret;
	}

	if (ctx->vdata) {
		ret = fwrite(ctx->vdata, ctx->vdata_len, 1, out);
		if (ret < 0) {
			lcfs_close(ctx);
			return ret;
		}
	}

	return 0;
}

static int lcfs_close(struct lcfs_ctx_s *ctx)
{
	if (ctx == NULL)
		return 0;

	hash_free(ctx->ht);
	free(ctx->vdata);
	lcfs_node_free(ctx->root);
	free(ctx);

	return 0;
}

int lcfs_append_vdata(struct lcfs_ctx_s *ctx, struct lcfs_vdata_s *out,
		      const void *data, size_t len)
{
	return lcfs_append_vdata_opts(ctx, out, data, len, true);
}

int lcfs_append_vdata_no_dedup(struct lcfs_ctx_s *ctx, struct lcfs_vdata_s *out,
			       const void *data, size_t len)
{
	return lcfs_append_vdata_opts(ctx, out, data, len, false);
}

static int read_xattrs(struct lcfs_node_s *ret,
		       int dirfd, const char *fname, int flags)
{
	char path[PATH_MAX];
	ssize_t list_size;
	char *list, *it;
	ssize_t r;

	if (flags & AT_EMPTY_PATH)
		sprintf(path, "/proc/self/fd/%d", dirfd);
	else
		sprintf(path, "/proc/self/fd/%d/%s", dirfd, fname);

	list_size = llistxattr(path, NULL, 0);
	if (list_size < 0)
		return list_size;

	list = malloc(list_size);
	if (list == NULL)
		return -1;

	r = llistxattr(path, list, list_size);
	if (r < 0)
		return r;

	for (it = list; *it;) {
		ssize_t value_size;
		size_t len = strlen(it);
		char *value;

		value_size = lgetxattr(path, it, NULL, 0);
		if (value_size < 0) {
			free(list);
			return value_size;
		}

		value = malloc(value_size);
		if (value == NULL) {
			free(list);
			return -1;
		}

		r = lgetxattr(path, it, value, value_size);
		if (r < 0) {
			free(list);
			free(value);
			return r;
		}

		r = lcfs_node_append_xattr(ret, it, value, value_size);
		if (r < 0) {
			free(list);
			free(value);
			return r;
		}

		free(value);
		it += len;
	}

	free(list);

	return r;
}

struct lcfs_node_s *lcfs_node_new(void)
{
	return calloc(1, sizeof(struct lcfs_node_s));
}

struct lcfs_node_s *lcfs_load_node_from_file(int dirfd,
					     const char *fname,
					     int flags,
					     int buildflags)
{
	struct lcfs_node_s *ret;
	struct stat sb;
	int r;

	if (buildflags & ~(BUILD_SKIP_XATTRS | BUILD_USE_EPOCH | BUILD_SKIP_DEVICES)) {
		errno = EINVAL;
		return NULL;
	}

	if (flags & ~AT_EMPTY_PATH) {
		errno = EINVAL;
		return NULL;
	}

	r = fstatat(dirfd, fname, &sb, AT_SYMLINK_NOFOLLOW | flags);
	if (r < 0)
		return NULL;

	ret = lcfs_node_new();
	if (ret == NULL)
		return NULL;

	ret->inode.st_mode = sb.st_mode;
	ret->inode.st_uid = sb.st_uid;
	ret->inode.st_gid = sb.st_gid;
	ret->inode.st_rdev = sb.st_rdev;

	if ((sb.st_mode & S_IFMT) == S_IFREG) {
		ret->st_size = sb.st_size;
	}

	if ((buildflags & BUILD_USE_EPOCH) == 0) {
		ret->inode.st_mtim = sb.st_mtim;
		ret->inode.st_ctim = sb.st_ctim;
	}

	if ((buildflags & BUILD_SKIP_XATTRS) == 0) {
		r = read_xattrs(ret, dirfd, fname, flags);
		if (r < 0) {
			free(ret);
			return NULL;
		}
	}

	return ret;
}

int lcfs_node_set_payload(struct lcfs_node_s *node,
                          const char *payload)
{
	node->payload = strdup(payload);
	if (node->payload == NULL) {
		errno = ENOMEM;
		return -1;
	}

	return 0;
}

const char *lcfs_node_get_name(struct lcfs_node_s *node)
{
	return node->name;
}

size_t lcfs_node_get_n_children(struct lcfs_node_s *node)
{
	return node->children_size;
}

struct lcfs_node_s * lcfs_node_get_child(struct lcfs_node_s *node, size_t i)
{
	if (i < node->children_size)
		return node->children[i];
	return NULL;
}


uint32_t lcfs_node_get_mode(struct lcfs_node_s *node)
{
	return node->inode.st_mode;
}

void lcfs_node_set_mode(struct lcfs_node_s *node,
			uint32_t mode)
{
	node->inode.st_mode = mode;
}

uint32_t lcfs_node_get_uid(struct lcfs_node_s *node)
{
	return node->inode.st_uid;
}

void lcfs_node_set_uid(struct lcfs_node_s *node,
                       uint32_t uid)
{
	node->inode.st_uid = uid;
}

uint32_t lcfs_node_get_gid(struct lcfs_node_s *node)
{
	return node->inode.st_gid;
}

void lcfs_node_set_gid(struct lcfs_node_s *node,
                      uint32_t gid)
{
	node->inode.st_gid = gid;
}

uint32_t lcfs_node_get_rdev(struct lcfs_node_s *node)
{
	return node->inode.st_rdev;
}

void lcfs_node_set_rdev(struct lcfs_node_s *node,
                       uint32_t rdev)
{
	node->inode.st_rdev = rdev;
}

uint32_t lcfs_node_get_nlink(struct lcfs_node_s *node)
{
	return node->inode.st_nlink;
}

void lcfs_node_set_nlink(struct lcfs_node_s *node,
			 uint32_t nlink)
{
	node->inode.st_nlink = nlink;
}

uint64_t lcfs_node_get_size(struct lcfs_node_s *node)
{
	return node->st_size;
}

void lcfs_node_set_size(struct lcfs_node_s *node,
			 uint64_t size)
{
	node->st_size = size;
}

struct lcfs_node_s *lcfs_node_lookup_child(struct lcfs_node_s *node,
					   const char *name)
{
	size_t i;

	for (i = 0; i < node->children_size; ++i) {
		struct lcfs_node_s *child = node->children[i];

		if (child->name && strcmp(child->name, name) == 0)
			return child;
	}

	return NULL;
}

struct lcfs_node_s *lcfs_node_get_parent(struct lcfs_node_s *node)
{
	return node->parent;
}

void lcfs_node_make_hardlink(struct lcfs_node_s *node,
			     struct lcfs_node_s *target)
{
	node->link_to = target;
	target->inode.st_nlink++;
}

int lcfs_node_add_child(struct lcfs_node_s *parent,
                        struct lcfs_node_s *child,
			const char *name)
{
	struct lcfs_node_s **new_children;
	size_t new_size;
	char *name_copy;

	if ((parent->inode.st_mode & S_IFMT) != S_IFDIR) {
		errno = ENOTDIR;
		return -1;
	}

	/* Each node can only be added once */
	if (child->name != NULL) {
		errno = EMLINK;
		return -1;
	}

	if (lcfs_node_lookup_child(parent, name) != NULL) {
		errno = EEXIST;
		return -1;
	}

	name_copy = strdup(name);
	if (name_copy == NULL) {
		errno = ENOMEM;
		return -1;
	}

	new_size = parent->children_size + 1;

	new_children = reallocarray(parent->children, sizeof(*parent->children),
				    new_size);
	if (new_children == NULL) {
		errno = ENOMEM;
		free(name_copy);
		return -1;
	}

	parent->children = new_children;

	parent->children[parent->children_size] = child;
	parent->children_size = new_size;
	child->parent = parent;
	child->name = name_copy;

	return 0;
}

void lcfs_node_free(struct lcfs_node_s *node)
{
	size_t i;

	for (i = 0; i < node->children_size; i++)
		lcfs_node_free(node->children[i]);
	free(node->children);
	free(node->name);
	free(node->payload);

	for (i = 0; i < node->n_xattrs; i++) {
		free (node->xattrs[i].key);
		free (node->xattrs[i].value);
	}
	free(node->xattrs);

	free(node);
}

bool lcfs_node_dirp(struct lcfs_node_s *node)
{
	return (node->inode.st_mode & S_IFMT) == S_IFDIR;
}

struct lcfs_node_s *lcfs_build(struct lcfs_node_s *parent, int fd,
			       const char *fname, const char *name,
			       int flags,
			       int buildflags)
{
	struct lcfs_node_s *node;
	struct dirent *de;
	DIR *dir;
	int dfd;

	node = lcfs_load_node_from_file(fd, fname, flags,
					buildflags);
	if (node == NULL) {
		close(fd);
		return NULL;
	}

	if (!lcfs_node_dirp(node)) {
		close(fd);
		return node;
	}

	dir = fdopendir(fd);
	if (dir == NULL) {
		close(fd);
		lcfs_node_free(node);
		return NULL;
	}

	dfd = dirfd(dir);
	for (;;) {
		struct lcfs_node_s *n;
		int r;

		errno = 0;
		de = readdir(dir);
		if (de == NULL) {
			if (errno)
				goto fail;

			break;
		}

		if (strcmp(de->d_name, ".") == 0 ||
		    strcmp(de->d_name, "..") == 0)
			continue;

		if (de->d_type == DT_DIR) {
			int subdir_fd;

			subdir_fd = openat(dfd, de->d_name, O_RDONLY | O_NOFOLLOW);
			if (subdir_fd < 0)
				goto fail;

			n = lcfs_build(node, subdir_fd, "", de->d_name,
				       AT_EMPTY_PATH, buildflags);
			if (n == NULL)
				goto fail;
		} else {
			if (buildflags & BUILD_SKIP_DEVICES) {
				if (de->d_type == DT_BLK
				    || de->d_type == DT_CHR)
					continue;
			}

			n = lcfs_load_node_from_file(dfd, de->d_name,
						     0, buildflags);
			if (n == NULL)
				goto fail;
		}

		r = lcfs_node_add_child(node, n, de->d_name);
		if (r < 0)
			goto fail;
	}

	closedir(dir);
	return node;

fail:
	lcfs_node_free(node);
	closedir(dir);
	return NULL;
}

int lcfs_node_append_xattr(struct lcfs_node_s *node,
			   const char *key,
			   const char *value, size_t value_len)
{
	struct lcfs_xattr_s *xattrs;
	char *k, *v;

	xattrs = realloc(node->xattrs, (node->n_xattrs + 1) * sizeof(struct lcfs_xattr_s));
	if (xattrs == NULL) {
		errno = ENOMEM;
		return -1;
	}
	node->xattrs = xattrs;

	k = strdup (key);
	v = memdup (value, value_len);
	if (k == NULL || v == NULL) {
		free(k);
		free(v);
		errno = ENOMEM;
		return -1;
	}

	xattrs[node->n_xattrs].key = k;
	xattrs[node->n_xattrs].value = v;
	xattrs[node->n_xattrs].value_len = value_len;
	node->n_xattrs++;

	return 0;
}
