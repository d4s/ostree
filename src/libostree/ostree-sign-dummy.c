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
 */

#include "ostree-sign-dummy.h"

#define OSTREE_SIGN_DUMMY_NAME "dummy"

#define OSTREE_SIGN_METADATA_DUMMY_KEY "ostree.sign.dummy"
#define OSTREE_SIGN_METADATA_DUMMY_FORMAT "aay"

struct _OstreeSignDummy
{
  GObject parent;
  gchar *key_id;
};

static void
ostree_sign_dummy_iface_init (OstreeSignInterface *self);

G_DEFINE_TYPE_WITH_CODE (OstreeSignDummy, ostree_sign_dummy, G_TYPE_OBJECT,
        G_IMPLEMENT_INTERFACE (OSTREE_TYPE_SIGN, ostree_sign_dummy_iface_init));

static void
ostree_sign_dummy_init (OstreeSignDummy *self)
{
  g_message("%s enter", __FUNCTION__);

  // Initialize key and commit with predefined values

  self->key_id = "key_id";
}

gboolean ostree_sign_dummy_commit (OstreeSign *self, GError **error)
{
  g_message("%s enter", __FUNCTION__);
  g_return_val_if_fail (OSTREE_IS_SIGN (self), FALSE);

  return TRUE;
}

gboolean ostree_sign_dummy_data (OstreeSign *self,
                                 GBytes *data,
                                 GBytes **signature,
                                 GCancellable *cancellable,
                                 GError **error)
{

  g_message("%s enter", __FUNCTION__);
  g_return_val_if_fail (OSTREE_IS_SIGN (self), FALSE);

  const gchar * signature_ascii = "deadbeef";

  *signature = g_bytes_new (signature_ascii, sizeof(signature_ascii));

  return TRUE;
}

gchar * ostree_sign_dummy_get_name (OstreeSign *self)
{
    g_message("%s enter", __FUNCTION__);
    g_return_val_if_fail (OSTREE_IS_SIGN (self), FALSE);

    g_autofree gchar *name = g_strdup(OSTREE_SIGN_DUMMY_NAME);

    return g_steal_pointer (&name);
}

gchar * ostree_sign_dummy_metadata_key (OstreeSign *self)
{
    g_message("%s enter", __FUNCTION__);

    g_autofree gchar *key = g_strdup(OSTREE_SIGN_METADATA_DUMMY_KEY);
    return g_steal_pointer (&key);
}

gchar * ostree_sign_dummy_metadata_format (OstreeSign *self)
{
    g_message("%s enter", __FUNCTION__);

    g_autofree gchar *format = g_strdup(OSTREE_SIGN_METADATA_DUMMY_FORMAT);
    return g_steal_pointer (&format);
}


static void
ostree_sign_dummy_iface_init (OstreeSignInterface *self)
{
  g_message("%s enter", __FUNCTION__);

  self->commit = ostree_sign_dummy_commit;
  self->data = ostree_sign_dummy_data;
  self->get_name = ostree_sign_dummy_get_name;
  self->metadata_key = ostree_sign_dummy_metadata_key;
  self->metadata_format= ostree_sign_dummy_metadata_format;
}

static void
ostree_sign_dummy_class_init (OstreeSignDummyClass *self)
{
}
