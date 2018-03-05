#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2015, Francesco "dfirfpi" Picasso <francesco.picasso@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Credits goes to Benjamin Delphy aka @gentilkiwi and his Mimikatz project:
# vault structs are a mix of my research and his research.
"""Windows Vaults Schema structures and helpers."""

from construct import *
import struct

#===============================================================================
#                   Adapters -  Make the output more human readable
#===============================================================================

# Construct adapters.

class GuidAdapter(Adapter):
    def _decode(self, guid, context, path):
        return '{data1:x}-{data2:x}-{data3:x}-{data4}-{data5}'.format(data1=guid.data1, data2=guid.data2, data3=guid.data3, data4=guid.data4.encode('hex')[:4], data5=guid.data4.encode('hex')[4:])

class BytesHexAdapter(Adapter):
    '''Hex encoding output.'''
    def _decode(self, obj, context, path):
        return obj.encode('hex')


class NumericPinAdapter(Adapter):
    '''Helper to pretty print the numeric PIN code.'''
    def _decode(self, obj, context, path):
        try:
            pin = int(''.join(reversed(
                [obj.data[i:i+2] for i in range(0, len(obj.data), 2)])), 16)
        except:
            return obj.data
        return pin


class UnicodeStringActiveSyncAdapter(Adapter):
    '''Helper to pretty print string/hex and remove trailing zeroes.'''
    def _decode(self, obj, context, path):
        try:
            decoded = obj.decode('utf16')
            decoded = decoded.rstrip('\00').encode('utf8')
            if len(obj) <= 8:
                decoded = '{0:s} [hex: {1:s}]'.format(
                    decoded, obj.encode('hex'))
        except UnicodeDecodeError:
            decoded = obj.encode('hex')
        return decoded


class UnicodeOrHexAdapter(Adapter):
    '''Helper to pretty print string/hex and remove trailing zeroes.'''
    def _decode(self, obj, context, path):
        try:
            decoded = obj.decode('utf16')
            decoded = decoded.rstrip('\00').encode('utf8')
        except UnicodeDecodeError:
            decoded = obj.encode('hex')
        return decoded


class UnicodeRstripZero(Adapter):
    '''Helper to remove trailing zeroes.'''
    def _decode(self, obj, context, path):
        return obj.rstrip('\x00\x00')


class  VaultSchemaActiveSyncAdapter(Adapter):
    def _decode(self, obj, context, path):
        return ('identity: {0:s}\nresource: {1:s}\nauthenticator: {2:s}'.format(
                        obj.identity.data, 
                        obj.resource.data, 
                        obj.authenticator.data
                    )
                )

class VaultSchemaPinAdapter(Adapter):
    def _decode(self, obj, context, path):
        return ('sid: {0:s}\nresource: {1:s}\npassword: {2:s}\npin: {3:d}'.format(
                        obj.sid, 
                        obj.resource.data, 
                        obj.password.data, obj.pin
                    )
                )

class VaultSchemaSimpleAdapter(Adapter):
    def _decode(self, obj, context, path):
        dataout = str(bytearray(obj.data))
        return 'hex: {0:s}'.format(dataout.encode('hex'))


class  VaultSchemaWebPasswordAdapter(Adapter):
    def _decode(self, obj, context, path):
        return ('identity: {0:s}\nresource: {1:s}\nauthenticator: {2:s}'.format(
                        obj.identity.data, 
                        obj.resource.data, 
                        obj.authenticator.data
                    )
                )

#===============================================================================
#                               Common structs.
#===============================================================================

# Common structs.

GUID = Struct(
    'data1' / Int32ul,
    'data2' / Int16ul,
    'data3' / Int16ul,
    'data4' / Bytes(8),
)

UNICODE_STRING_ACTIVESYNC = Struct(
    'length'    / Int32ul,
    'data'      / UnicodeStringActiveSyncAdapter(Bytes(this.length))
)

UNICODE_STRING_STRIP = Struct(
    'length'    / Int32ul,
    'data'      / UnicodeRstripZero(String(this.length, encoding='UTF_16_LE'))
)

UNICODE_STRING_HEX = Struct(
    'length'    / Int32ul,
    'data'      / UnicodeOrHexAdapter(Bytes(this.length))
)

SIZED_DATA = Struct(
    'size'  / Int32ul,
    'data'  / BytesHexAdapter(Bytes(this.size))
)

#===============================================================================
#                               VAULT schemas 
#===============================================================================


# Vault file partial parsing

VAULT_VSCH = Struct(
    'version'               / Int32ul,
    'schema_guid'           / GuidAdapter(GUID), 
    'vault_vsch_unknown_1'  / Int32ul,
    'count'                 / Int32ul,
    'schema_name'           / UNICODE_STRING_STRIP, 
)

# Generic Vault Schema

VAULT_ATTRIBUTE_ITEM = Struct(
    "id" / Enum(Int32ul,
        resource        = 1, 
        identity        = 2, 
        authenticator   = 3,
    ),
    'item'  / Switch(this.id,
        {
            'resource'      : UNICODE_STRING_HEX,
            'identity'      : UNICODE_STRING_HEX,
            'authenticator' : UNICODE_STRING_HEX,
        },
        default ='generic' / SIZED_DATA
    ), 
)

VAULT_SCHEMA_GENERIC = Struct(
    'version'                           / Int32ul,
    'count'                             / Int32ul,
    'vault_schema_generic_unknown1'     / Int32ul,
    'attribute_item'                    / Array(this.count, VAULT_ATTRIBUTE_ITEM) 
)

# Vault Simple Schema

VAULT_SCHEMA_SIMPLE = VaultSchemaSimpleAdapter(
    Struct(
        'data' / GreedyRange(Byte),
    )
)

# PIN Logon Vault Resource Schema

VAULT_SCHEMA_PIN = VaultSchemaPinAdapter(
    Struct(
        'version'                   / Int32ul,
        'count'                     / Int32ul,
        'vault_schema_pin_unknown1' / Int32ul,
        'id_sid'                    / Int32ul,
        'sid_len'                   / Int32ul, 
        'sid'                       / Bytes(this.sid_len),
        'id_resource'               / Int32ul,
        'resource'                  / UNICODE_STRING_STRIP, 
        'id_password'               / Int32ul,
        'password'                  / UNICODE_STRING_STRIP, 
        'id_pin'                    / NumericPinAdapter(Int32ul),
        'pin'                       / SIZED_DATA,
    )
)

# Windows Web Password Credential Schema

VAULT_SCHEMA_WEB_PASSWORD = VaultSchemaWebPasswordAdapter(
    Struct(
        'version'                               / Int32ul,
        'count'                                 / Int32ul,
        'vault_schema_web_password_unknown1'    / Int32ul,
        'id_identity'                           / Int32ul,
        'identity'                              / UNICODE_STRING_STRIP, 
        'id_resource'                           / Int32ul,
        'resource'                              / UNICODE_STRING_STRIP, 
        'id_authenticator'                      / Int32ul,
        'authenticator'                         / UNICODE_STRING_STRIP, 
    )
)

# Active Sync Credential Schema

VAULT_SCHEMA_ACTIVESYNC = VaultSchemaActiveSyncAdapter(
    Struct(
        'version'                           / Int32ul,
        'count'                             / Int32ul,
        'vault_schema_activesync_unknown1'  / Int32ul,
        'id_identity'                       / Int32ul,
        'identity'                          / UNICODE_STRING_STRIP, 
        'id_resource'                       / Int32ul,
        'resource'                          / UNICODE_STRING_STRIP, 
        'id_authenticator'                  / Int32ul,
        'authenticator'                     / UNICODE_STRING_ACTIVESYNC, 
    )
)

# Vault Schema Dict

vault_schemas = {
    u'ActiveSyncCredentialSchema'       : VAULT_SCHEMA_ACTIVESYNC,
    u'PIN Logon Vault Resource Schema'  : VAULT_SCHEMA_PIN,
    u'Windows Web Password Credential'  : VAULT_SCHEMA_WEB_PASSWORD,
}