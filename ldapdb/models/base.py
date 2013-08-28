# -*- coding: utf-8 -*-
#
# django-ldapdb
# Copyright (c) 2009-2011, Bolloré telecom
# All rights reserved.
#
# See AUTHORS file for a full list of contributors.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#     1. Redistributions of source code must retain the above copyright notice,
#        this list of conditions and the following disclaimer.
#
#     2. Redistributions in binary form must reproduce the above copyright
#        notice, this list of conditions and the following disclaimer in the
#        documentation and/or other materials provided with the distribution.
#
#     3. Neither the name of Bolloré telecom nor the names of its contributors
#        may be used to endorse or promote products derived from this software
#        without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#


from django.conf import settings
from django.db import connections, router
from django.db.models import signals

from ldapdb import _LDAPDBConfig

from functools import partial, wraps

import django.db.models

import copy
import ldap


logger = _LDAPDBConfig.get_logger()


def classorinstancemethod(f):
    class wrapper(object):
        @wraps(f)
        def __get__(self, instance, owner):
            return partial(f, instance or owner)
    return wrapper()


class Model(django.db.models.base.Model):
    """
    Base class for all LDAP models.
    """
    dn = django.db.models.fields.CharField(max_length=200)

    # meta-data
    base_dn = None
    bound_alias = None
    search_scope = ldap.SCOPE_SUBTREE
    object_classes = ['top']

    def __init__(self, *args, **kwargs):
        super(Model, self).__init__(*args, **kwargs)
        self.saved_pk = self.pk

    def _get_connection(self, using=None):
        """
        Get the proper LDAP connection.
        """
        using = (using or self.bound_alias
                 or router.db_for_write(self.__class__, instance=self))
        return connections[using]

    @classmethod
    def bind_as(base_class, alias, dn=None, password=None, **kwargs):
        """
        Return the database class wrapped to use connection bound
        to another LDAP user.

        Alias specifies the database alias to use. If the database does
        not exist, a new one will be created. If dn is provided,
        the new connection will use that DN. Otherwise, it will be bound
        to self.build_dn(**kwargs).
        """
        if alias not in settings.DATABASES:
            base_alias = router.db_for_write(base_class)
            new_db = copy.deepcopy(settings.DATABASES[base_alias])
            settings.DATABASES[alias] = new_db
        else:
            new_db = settings.DATABASES[alias]

        if dn is None:
            dn = base_class.build_dn(**kwargs)
        new_db['USER'] = dn
        new_db['PASSWORD'] = password or ''

        class Meta:
            proxy = True
        name = "%s_%s" % (base_class.__name__, str(alias))
        new_class = type(name, (base_class,), {
            'bound_alias': alias,
            '__module__': base_class.__module__,
            'Meta': Meta,
        })
        return new_class

    @classorinstancemethod
    def build_rdn(self, **keys):
        """
        Build the Relative Distinguished Name for this entry.

        When called as a class function, values for all the keys
        need to be provided. Otherwise, they will be obtained
        from the model.
        """
        bits = []
        for field in self._meta.fields:
            if not field.db_column:
                continue
            elif field.name in keys:
                bits.append("%s=%s" % (field.db_column,
                                       keys[field.name]))
            elif field.primary_key:
                if not isinstance(self, Model):
                    raise TypeError("All keys must be specified when called on a class")
                bits.append("%s=%s" % (field.db_column,
                                       getattr(self, field.name)))
        if not len(bits):
            raise Exception("Could not build Distinguished Name")
        return '+'.join(bits)

    @classorinstancemethod
    def build_dn(self, **keys):
        """
        Build the Distinguished Name for this entry.
        """
        return "%s,%s" % (self.build_rdn(**keys), self.base_dn)
        raise Exception("Could not build Distinguished Name")

    def delete(self, using=None):
        """
        Delete this entry.
        """
        connection = self._get_connection(using)
        logger.debug("Deleting LDAP entry %s" % self.dn)
        connection.delete_s(self.dn)
        signals.post_delete.send(sender=self.__class__, instance=self)

    def save(self, using=None):
        """
        Saves the current instance.
        """
        connection = self._get_connection(using)
        if not self.dn:
            # create a new entry
            record_exists = False
            entry = [('objectClass', self.object_classes)]
            new_dn = self.build_dn()

            for field in self._meta.fields:
                if not field.db_column:
                    continue
                value = getattr(self, field.name)
                if value:
                    entry.append((field.db_column, field.get_db_prep_save(value, connection=connection)))

            logger.debug("Creating new LDAP entry %s" % new_dn)
            connection.add_s(new_dn, entry)

            # update object
            self.dn = new_dn

        else:
            # update an existing entry
            record_exists = True
            modlist = []
            orig = self.__class__.objects.get(pk=self.saved_pk)
            for field in self._meta.fields:
                if not field.db_column:
                    continue
                old_value = getattr(orig, field.name, None)
                new_value = getattr(self, field.name, None)
                if old_value != new_value:
                    if new_value:
                        modlist.append((ldap.MOD_REPLACE, field.db_column, field.get_db_prep_save(new_value, connection=connection)))
                    elif old_value:
                        modlist.append((ldap.MOD_DELETE, field.db_column, None))

            if len(modlist):
                # handle renaming
                new_dn = self.build_dn()
                if new_dn != self.dn:
                    logger.debug("Renaming LDAP entry %s to %s" % (self.dn, new_dn))
                    connection.rename_s(self.dn, self.build_rdn())
                    self.dn = new_dn

                logger.debug("Modifying existing LDAP entry %s" % self.dn)
                connection.modify_s(self.dn, modlist)
            else:
                logger.debug("No changes to be saved to LDAP entry %s" % self.dn)

        # done
        self.saved_pk = self.pk
        signals.post_save.send(sender=self.__class__, instance=self, created=(not record_exists))

    def exit(self):
        self._get_connection().unbind()

    @classmethod
    def scoped(base_class, base_dn):
        """
        Returns a copy of the current class with a different base_dn.
        """
        class Meta:
            proxy = True
        import re
        suffix = re.sub('[=,]', '_', base_dn)
        name = "%s_%s" % (base_class.__name__, str(suffix))
        new_class = type(name, (base_class,), {'base_dn': base_dn, '__module__': base_class.__module__, 'Meta': Meta})
        return new_class

    class Meta:
        abstract = True
