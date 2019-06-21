/*
 * Copyright © 2019 Collabora Ltd.
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
 * Authors:
 *  - Denis Pynkin (d4s) <denis.pynkin@collabora.com>
 */

#pragma once

#include <glib.h>
#include <glib-object.h>

#include "ostree-ref.h"
#include "ostree-remote.h"
#include "ostree-types.h"

G_BEGIN_DECLS

#define OSTREE_TYPE_SIGN (ostree_sign_get_type ())

_OSTREE_PUBLIC
G_DECLARE_INTERFACE (OstreeSign, ostree_sign, OSTREE, SIGN, GObject)

struct _OstreeSignInterface
{
  GTypeInterface g_iface;
  gchar *(* get_name) (OstreeSign *self);
  gboolean (* commit) (OstreeSign *self, GError **error);
  gboolean (* data)   (OstreeSign *self,
                       GBytes *data,
                       GBytes **signature,
                       GCancellable *cancellable,
                       GError **error);
  gchar *(* metadata_key) (OstreeSign *self);
  gchar *(* metadata_format) (OstreeSign *self);
/*
  gboolean (* commit_verify) (OstreeSign *self, GError **error);
  gboolean (* commit_delete_signature) (OstreeSign *self, GError **error);
  gboolean (* commit_print_signature) (OstreeSign *self, GError **error);
  gboolean (* summary) (OstreeSign *self, GError **error);
  gboolean (* summary_verify) (OstreeSign *self, GError **error);
*/
};

_OSTREE_PUBLIC
gchar * ostree_sign_get_name (OstreeSign *self);

_OSTREE_PUBLIC
gboolean ostree_sign_commit (OstreeSign *self, GError **error);

_OSTREE_PUBLIC
gboolean ostree_sign_data (OstreeSign *self,
                             GBytes *data,
                             GBytes **signature,
                             GCancellable *cancellable,
                             GError **error);


_OSTREE_PUBLIC
gchar * ostree_sign_metadata_key (OstreeSign *self);

_OSTREE_PUBLIC
gchar * ostree_sign_metadata_format (OstreeSign *self);

_OSTREE_PUBLIC
GVariant * ostree_sign_detached_metadata_append (OstreeSign *self,
                                                 GVariant   *existing_metadata,
                                                 GBytes     *signature_bytes);
/**
 * ostree_sign_get_by_name:
 *
 * Tries to find and return proper signing engine by it's name.
 *
 * Returns: (transfer full): a constant, free when you used it
 */
_OSTREE_PUBLIC
OstreeSign * ostree_sign_get_by_name (const gchar *name);

/*
_OSTREE_PUBLIC
gboolean ostree_sign_commit_verify (OstreeSign *self, GError **error);

_OSTREE_PUBLIC
gboolean ostree_sign_commit_delete_signature (OstreeSign *self, GError **error);

_OSTREE_PUBLIC
gboolean ostree_sign_commit_print_signature (OstreeSign *self, GError **error);

_OSTREE_PUBLIC
gboolean ostree_sign_summary (OstreeSign *self, GError **error);

_OSTREE_PUBLIC
gboolean ostree_sign_summary_verify (OstreeSign *self, GError **error);
*/
G_END_DECLS

