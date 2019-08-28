/* vim:set et sw=2 cin cino=t0,f0,(0,{s,>2s,n-s,^-s,e2s: */

/*
 * Copyright (C) 2015 Colin Walters <walters@verbum.org>
 * Copyright (C) 2019 Denis Pynkin (d4s) <denis.pynkin@collabora.com>
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

static gboolean opt_delete;
static gboolean opt_verify;
static char *opt_sign_name;
static char *opt_filename;

/* ATTENTION:
 * Please remember to update the bash-completion script (bash/ostree) and
 * man page (man/ostree-sign.xml) when changing the option list.
 */

static GOptionEntry options[] = {
  { "delete", 'd', 0, G_OPTION_ARG_NONE, &opt_delete, "Delete signatures having any of the KEY-IDs", NULL},
  { "verify", 0, 0, G_OPTION_ARG_NONE, &opt_verify, "Verify signatures", NULL},
  { "sign-type", 's', 0, G_OPTION_ARG_STRING, &opt_sign_name, "Signature type to use (defaults to 'ed25519')", "NAME"},
#if defined(HAVE_LIBSODIUM)
  { "keys-file", 's', 0, G_OPTION_ARG_STRING, &opt_filename, "Read key(s) from file", "NAME"},
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
#if defined(HAVE_LIBSODIUM)
  g_autoptr (GVariant) ed25519_sk = NULL;
  g_autoptr (GVariant) ed25519_pk = NULL;
#endif


  context = g_option_context_new ("COMMIT KEY-ID...");


  if (!ostree_option_context_parse (context, options, &argc, &argv, invocation, &repo, cancellable, error))
    goto out;

  if (argc < 2)
    {
      usage_error (context, "Need a COMMIT to sign or verify", error);
      goto out;
    }

  commit = argv[1];

  if (!opt_filename && argc < 3)
    {
      usage_error (context, "Need at least one KEY-ID to sign with", error);
      goto out;
    }

  key_ids = argv + 2;
  n_key_ids = argc - 2;

  if (!ostree_repo_resolve_rev (repo, commit, FALSE, &resolved_commit, error))
    goto out;

  /* Initialize crypto system */
  if (!opt_sign_name)
    opt_sign_name = "ed25519";

  sign = ostree_sign_get_by_name (opt_sign_name, error);
  if (sign == NULL)
    {
      ret = FALSE;
      goto out;
    }

  for (ii = 0; ii < n_key_ids; ii++)
    {
      g_autoptr (GVariant) sk = NULL;
      g_autoptr (GVariant) pk = NULL;
      g_autofree guchar *key = NULL;

      if (!g_strcmp0(ostree_sign_get_name(sign), "dummy"))
        {
          // Just use the string as signature
          sk = g_variant_new_string(key_ids[ii]);
          pk = g_variant_new_string(key_ids[ii]);
        }
      if (opt_verify)
        {
          if (!g_strcmp0(ostree_sign_get_name(sign), "ed25519"))
            {
              gsize key_len = 0;
              g_autofree guchar *key = g_base64_decode (key_ids[ii], &key_len);
              pk = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, key, key_len, sizeof(guchar));
            }

          if (!ostree_sign_set_pk (sign, pk, error))
            {
              ret = FALSE;
              goto out;
            }

          if (ostree_sign_commit_verify (sign,
                                         repo,
                                         resolved_commit,
                                         cancellable,
                                         error))
            ret = TRUE;
        }
      else
        {
          if (!g_strcmp0(ostree_sign_get_name(sign), "ed25519"))
            {
              gsize key_len = 0;
              g_autofree guchar *key = g_base64_decode (key_ids[ii], &key_len);
              sk = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, key, key_len, sizeof(guchar));
            }

          if (!ostree_sign_set_sk (sign, sk, error))
            {
              ret = FALSE;
              goto out;
            }

          ret = ostree_sign_commit (sign,
                                    repo,
                                    resolved_commit,
                                    cancellable,
                                    error);
          if (ret != TRUE)
            goto out;
        }
    }

  /* Read signatures from file */
  if (opt_filename)
    {
      if (opt_verify)
        {
          g_autoptr (GVariantBuilder) builder = NULL;
          g_autoptr (GVariant) options = NULL;

          builder = g_variant_builder_new (G_VARIANT_TYPE ("a{sv}"));
          g_variant_builder_add (builder, "{sv}", "filename", g_variant_new_string (opt_filename));
          options = g_variant_builder_end (builder);

          if (!ostree_sign_load_pk (sign, options, error))
            {
              ret = FALSE;
              goto out;
            }
          if (ostree_sign_commit_verify (sign,
                                         repo,
                                         resolved_commit,
                                         cancellable,
                                         error))
            ret = TRUE;
          if (ret != TRUE)
            goto out;
        } /* Check via file */
      else
        { /* Sign with keys from provided file */
          g_autoptr (GFile) keyfile = NULL;
          g_autoptr (GFileInputStream) key_stream_in = NULL;
          g_autoptr (GDataInputStream) key_data_in = NULL;

          if (!g_file_test (opt_filename, G_FILE_TEST_IS_REGULAR))
            {
              g_warning ("Can't open file '%s' with keys", opt_filename);
              g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "File object '%s' is not a regular file", opt_filename);
              goto out;
            }

          keyfile = g_file_new_for_path (opt_filename);
          key_stream_in = g_file_read (keyfile, NULL, error);
          if (key_stream_in == NULL)
            goto out;

          key_data_in = g_data_input_stream_new (G_INPUT_STREAM(key_stream_in));
          g_assert (key_data_in != NULL);

          /* Use simple file format with just a list of base64 public keys per line */
          while (TRUE)
            {
              gsize len = 0;
              g_autofree char *line = g_data_input_stream_read_line (key_data_in, &len, NULL, error);
              g_autoptr (GVariant) sk = NULL;

              if (*error != NULL)
                goto out;

              if (line == NULL)
                goto out;


              if (!g_strcmp0(ostree_sign_get_name(sign), "dummy"))
                {
                  // Just use the string as signature
                  sk = g_variant_new_string(line);
                }


              if (!g_strcmp0(ostree_sign_get_name(sign), "ed25519"))
                {
                  gsize key_len = 0;
                  g_autofree guchar *key = g_base64_decode (line, &key_len);
                  sk = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, key, key_len, sizeof(guchar));
                }

              if (!ostree_sign_set_sk (sign, sk, error))
                continue;

              ret = ostree_sign_commit (sign,
                                        repo,
                                        resolved_commit,
                                        cancellable,
                                        error);
              if (ret != TRUE)
                goto out;
            }
        }
    }

  // No valid signature found
  if (opt_verify && (ret != TRUE))
    g_set_error_literal (error,
                         G_IO_ERROR, G_IO_ERROR_FAILED,
                         "No valid signatures found");

out:
  return ret;
}
