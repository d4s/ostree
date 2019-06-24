/* vim:set et sw=2 cin cino=t0,f0,(0,{s,>2s,n-s,^-s,e2s: */

/*
 * Copyright (C) 2015 Colin Walters <walters@verbum.org>
 *
 * SPDX-License-Identifier: LGPL-2.0+
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Author: Colin Walters <walters@verbum.org>
 */

#include "config.h"

#include "ot-main.h"
#include "ot-builtins.h"
#include "ostree.h"
#include "otutil.h"
#include "ostree-core-private.h"
#include "ostree-sign.h"
#include "ostree-sign-dummy.h"

static gboolean opt_delete;
static gboolean opt_verify;

/* ATTENTION:
 * Please remember to update the bash-completion script (bash/ostree) and
 * man page (man/ostree-sign.xml) when changing the option list.
 */

static GOptionEntry options[] = {
  { "delete", 'd', 0, G_OPTION_ARG_NONE, &opt_delete, "Delete signatures having any of the KEY-IDs", NULL},
#if defined(OSTREE_ENABLE_EXPERIMENTAL_API)
  { "verify", 0, 0, G_OPTION_ARG_NONE, &opt_verify, "Verify signatures", NULL},
#endif
#if defined(HAVE_LIBSODIUM)
#endif
   { NULL }
};

static void
usage_error (GOptionContext *context, const char *message, GError **error)
{
  g_autofree char *help = g_option_context_get_help (context, TRUE, NULL);
  g_printerr ("%s", help);
  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, message);
}

static gboolean
delete_signatures (OstreeRepo *repo,
                   const char *commit_checksum,
                   const char * const *key_ids,
                   guint n_key_ids,
                   guint *out_n_deleted,
                   GCancellable *cancellable,
                   GError **error)
{
  return TRUE;
}


#if defined(__linux__)
# include <fcntl.h>
# include <unistd.h>
# include <sys/ioctl.h>
# include <linux/random.h>
#endif

#if defined(HAVE_LIBSODIUM)
#include <sodium.h>
#endif

gboolean
ostree_repo_sign_init (GError **error);

gboolean
ostree_repo_sign_init (GError **error)
{
#if 0
#if defined(__linux__) && defined(RNDGETENTCNT)
  int fd;
  int c;
  if ((fd = open("/dev/random", O_RDONLY)) != -1) {
    if (ioctl(fd, RNDGETENTCNT, &c) == 0 && c < 160) {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
          "This system doesn't provide enough entropy to quickly generate high-quality random numbers.");
      goto err;
    }
    (void) close(fd);
  }
#endif

  if (sodium_init() < 0) {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "libsodium library couldn't be initialized");
      goto err;
    }

#endif

  return TRUE;

err:
  return FALSE;
}
//////////////////////////////////////////////////////////////////////

gboolean
ostree_builtin_sign (int argc, char **argv, OstreeCommandInvocation *invocation, GCancellable *cancellable, GError **error)
{
  g_autoptr(GOptionContext) context = NULL;
  g_autoptr(OstreeRepo) repo = NULL;
  g_autoptr (OstreeSign) sign = NULL;
  g_autofree char *resolved_commit = NULL;
  const char *commit;
  char **key_ids;
  int n_key_ids, ii;
  gboolean ret = FALSE;


  context = g_option_context_new ("COMMIT KEY-ID...");

  if (!ostree_option_context_parse (context, options, &argc, &argv, invocation, &repo, cancellable, error))
    goto out;

  if (argc < 2)
    {
      usage_error (context, "Need a COMMIT to sign or verify", error);
      goto out;
    }

  commit = argv[1];

  if (!opt_verify && argc < 3)
    {
      usage_error (context, "Need at least one KEY-ID to sign with", error);
      goto out;
    }

  key_ids = argv + 2;
  n_key_ids = argc - 2;

  if (!ostree_repo_resolve_rev (repo, commit, FALSE, &resolved_commit, error))
    goto out;

  /* Initialize crypto system */
  sign = ostree_sign_get_by_name("dummy");
  if (sign == NULL)
    {
      ret = FALSE;
      goto out;
    }

  if (opt_delete)
    {
      guint n_deleted = 0;

      if (delete_signatures (repo, resolved_commit,
                             (const char * const *) key_ids, n_key_ids,
                             &n_deleted, cancellable, error))
        {
          g_print ("Signatures deleted: %u\n", n_deleted);
          ret = TRUE;
        }

      goto out;
    }

  if (opt_verify)
    {
      ret = ostree_sign_commit_verify (sign,
                                       repo,
                                       resolved_commit,
                                       cancellable,
                                       error);
      goto out;
    }

  for (ii = 0; ii < n_key_ids; ii++)
    {
      if (!g_strcmp0(ostree_sign_get_name(sign), "dummy"))
          // Just use the string as signature
          ostree_sign_dummy_set_signature(sign, key_ids[ii]);

      if (!ostree_sign_commit (sign, repo, resolved_commit,
                               cancellable, error))
        goto out;
    }

  ret = TRUE;

out:
  return ret;
}
