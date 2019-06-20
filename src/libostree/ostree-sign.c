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

#include "config.h"

#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include "libglnx.h"
#include "otutil.h"

#include "ostree-autocleanups.h"
#include "ostree-core.h"
#include "ostree-sign.h"
#include "ostree-sign-dummy.h"

G_DEFINE_INTERFACE (OstreeSign, ostree_sign, G_TYPE_OBJECT)

static void
ostree_sign_default_init (OstreeSignInterface *iface)
{
  g_message("OstreeSign initialization");
}

gboolean ostree_sign_commit (OstreeSign *self, GError **error)
{
  g_message("%s enter", __FUNCTION__);
  g_return_val_if_fail (OSTREE_IS_SIGN (self), FALSE);
  g_return_val_if_fail (OSTREE_SIGN_GET_IFACE (self)->commit != NULL, FALSE);

  return OSTREE_SIGN_GET_IFACE (self)->commit (self, error);
}

gchar * ostree_sign_metadata_key (OstreeSign *self)
{
  g_message("%s enter", __FUNCTION__);

  g_return_val_if_fail (OSTREE_SIGN_GET_IFACE (self)->metadata_key != NULL, NULL);
  return OSTREE_SIGN_GET_IFACE (self)->metadata_key (self);
}

gchar * ostree_sign_metadata_format (OstreeSign *self)
{
  g_message("%s enter", __FUNCTION__);

  g_return_val_if_fail (OSTREE_SIGN_GET_IFACE (self)->metadata_format != NULL, NULL);
  return OSTREE_SIGN_GET_IFACE (self)->metadata_format (self);
}


gboolean ostree_sign_data (OstreeSign *self,
                           GBytes *data,
                           GBytes **signature,
                           GCancellable *cancellable,
                           GError **error)
{

  g_message("%s enter", __FUNCTION__);
  g_return_val_if_fail (OSTREE_IS_SIGN (self), FALSE);
  g_return_val_if_fail (OSTREE_SIGN_GET_IFACE (self)->data != NULL, FALSE);

  return OSTREE_SIGN_GET_IFACE (self)->data (self, data, signature, cancellable, error);
}

/*
 * Adopted version of _ostree_detached_metadata_append_gpg_sig ()
 */
GVariant *
ostree_sign_detached_metadata_append (OstreeSign *self,
                                      GVariant   *existing_metadata,
                                      GBytes     *signature_bytes)
{
  g_message("%s enter", __FUNCTION__);
  if (existing_metadata != NULL)
    g_print("%s", g_variant_print(existing_metadata, TRUE));

  GVariantDict metadata_dict;
  g_autoptr(GVariant) signature_data = NULL;
  g_autoptr(GVariantBuilder) signature_builder = NULL;

  g_variant_dict_init (&metadata_dict, existing_metadata);

  g_autofree gchar *signature_key = ostree_sign_metadata_key(self);
  g_autofree GVariantType *signature_format = (GVariantType *) ostree_sign_metadata_format(self);

  signature_data = g_variant_dict_lookup_value (&metadata_dict,
                                                signature_key,
                                                (GVariantType*)signature_format);

  /* signature_data may be NULL */
  signature_builder = ot_util_variant_builder_from_variant (signature_data, signature_format);

  g_variant_builder_add (signature_builder, "@ay", ot_gvariant_new_ay_bytes (signature_bytes));

  g_variant_dict_insert_value (&metadata_dict,
                               signature_key,
                               g_variant_builder_end (signature_builder));

  return  g_variant_dict_end (&metadata_dict);
}

/*
gboolean
ostree_sign_commit_verify (OstreeSign *self, GError **error)
{
    g_message("%s enter", __FUNCTION__);
    g_return_val_if_fail (OSTREE_IS_SIGN (self), FALSE);
    g_return_val_if_fail (OSTREE_SIGN_GET_IFACE (self)->commit_verify != NULL, FALSE);

    return OSTREE_SIGN_GET_IFACE (self)->commit_verify(self, error);
}

gboolean
ostree_sign_commit_delete_signature (OstreeSign *self, GError **error)
{
    g_message("%s enter", __FUNCTION__);
    g_return_val_if_fail (OSTREE_IS_SIGN (self), FALSE);
    g_return_val_if_fail (OSTREE_SIGN_GET_IFACE (self)->commit_delete_signature != NULL, FALSE);

    return OSTREE_SIGN_GET_IFACE (self)->commit_delete_signature (self, error);
}

gboolean
ostree_sign_commit_print_signature (OstreeSign *self, GError **error)
{
    g_message("%s enter", __FUNCTION__);
    g_return_val_if_fail (OSTREE_IS_SIGN (self), FALSE);
    g_return_val_if_fail (OSTREE_SIGN_GET_IFACE (self)->commit_print_signature != NULL, FALSE);

    return OSTREE_SIGN_GET_IFACE (self)->commit_print_signature (self, error);
}

gboolean
ostree_sign_summary (OstreeSign *self, GError **error)
{
    g_message("%s enter", __FUNCTION__);
    g_return_val_if_fail (OSTREE_IS_SIGN (self), FALSE);
    g_return_val_if_fail (OSTREE_SIGN_GET_IFACE (self)->summary != NULL, FALSE);

    return OSTREE_SIGN_GET_IFACE (self)->summary (self, error);
}

gboolean
ostree_sign_summary_verify (OstreeSign *self, GError **error)
{
    g_message("%s enter", __FUNCTION__);
    g_return_val_if_fail (OSTREE_IS_SIGN (self), FALSE);
    g_return_val_if_fail (OSTREE_SIGN_GET_IFACE (self)->summary_verify != NULL, FALSE);

    return OSTREE_SIGN_GET_IFACE (self)->summary_verify (self, error);
}
*/

gchar * ostree_sign_get_name (OstreeSign *self)
{
    g_message("%s enter", __FUNCTION__);
    g_return_val_if_fail (OSTREE_IS_SIGN (self), FALSE);
    g_return_val_if_fail (OSTREE_SIGN_GET_IFACE (self)->get_name != NULL, FALSE);

    return OSTREE_SIGN_GET_IFACE (self)->get_name (self);
}

OstreeSign * ostree_sign_get_by_name (const gchar *name)
{
  g_message("%s enter", __FUNCTION__);

  GType types [] = { OSTREE_TYPE_SIGN_DUMMY };
  OstreeSign *ret = NULL;

  for (gint i=0; i < G_N_ELEMENTS(types); i++)
  {
    g_autoptr (OstreeSign) sign = g_object_new (types[i], NULL);
    g_autofree gchar *sign_name = OSTREE_SIGN_GET_IFACE (sign)->get_name(sign);

    g_message("Found '%s' signing module", sign_name);

    if (g_strcmp0 (name, sign_name) == 0)
    {
      ret = g_steal_pointer (&sign);
      break;
    }
  }

  return ret;
}
