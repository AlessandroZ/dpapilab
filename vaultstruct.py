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
"""Windows Vaults structures."""

from construct import *
import datetime
import pytz


#===============================================================================
#                   Adapters -  Make the output more human readable
#===============================================================================

class GuidAdapter(Adapter):
    def _decode(self, guid, context, path):
        return '{data1:x}-{data2:x}-{data3:x}-{data4}-{data5}'.format(data1=guid.data1, data2=guid.data2, data3=guid.data3, data4=guid.data4.encode('hex')[:4], data5=guid.data4.encode('hex')[4:])

class FileTimeAdapter(Adapter):
    '''Adapted from Rekall Memory Forensics code.'''
    def _decode(self, obj, context, path):
        unix_time = obj / 10000000 - 11644473600
        if unix_time < 0:
            unix_time = 0

        dt = datetime.datetime.utcfromtimestamp(unix_time)
        dt = dt.replace(tzinfo=pytz.UTC)

        return dt.isoformat()


#===============================================================================
#                               Common structs.
#===============================================================================

UNICODE_STRING = Struct(
    'length'    / Int32ul,
    'data'      / String(this.length, encoding='UTF_16_LE'),
)

SIZED_DATA = Struct(
    'size'  / Int32ul,
    'data'  / Bytes(this.size)
)

GUID = Struct(
    'data1' / Int32ul,
    'data2' / Int16ul,
    'data3' / Int16ul,
    'data4' / Bytes(8),
)

#===============================================================================
#                               DPAPI Blob
#===============================================================================

# DPAPI structs.

DPAPI_BLOB = Struct(
    'mkversion'     / Int32ul,
    'mkblob'        / GUID,
    'flags'         / Int32ul, 
    'description'   / UNICODE_STRING,
    'cipherAlgo'    / Int32ul, 
    'keyLen'        / Int32ul, 
    'salt'          / SIZED_DATA,
    'strong'        / SIZED_DATA,
    'hashAlgo'      / Int32ul, 
    'hashLen'       / Int32ul, 
    'hmac'          / SIZED_DATA,
    'cipherText'    / SIZED_DATA,
)

DPAPI_BLOB_STRUCT = Struct(
    'version'   / Int32ul,
    # 'provider'    / GuidAdapter(GUID),
    'provider'  / GUID,
    'blob'      / DPAPI_BLOB,
    'sign'      / SIZED_DATA,       # For HMAC computation
)

DPAPI_BLOB_STORE = Struct(
    'size'  / Int32ul,
    'raw'   / DPAPI_BLOB_STRUCT, 
)

#===============================================================================
#                           Credential Files structs.
#===============================================================================


# CREDENTIALS file structs.

CREDENTIAL_FILE = Struct(
    'unknown1'  / Int32ul, 
    'blob_size' / Int32ul, 
    'unknown2'  / Int32ul, 
    'blob'      / Bytes(this.blob_size),
)

CREDENTIAL_DEC_HEADER = Struct(
    'header_size'   / Int32ul,
    Embedded(
        Union(  
            this.header_size - 4,
            Embedded(
                Struct(
                    'total_size'    / Int32ul,
                    'unknown1'      / Int32ul,
                    'unknown2'      / Int32ul,
                    'unknown3'      / Int32ul,
                    'last_update'   / FileTimeAdapter(Int64ul),
                    'unknown4'      / Int32ul,
                    'unk_type'      / Int32ul,
                    'unk_blocks'    / Int32ul,
                    'unknown5'      / Int32ul,
                    'unknown6'      / Int32ul,
                )
            )
        )
    )
)

# Once the blob decrypted, we got a new structure

CREDENTIAL_DEC_MAIN = Struct(
    'domain'        / UNICODE_STRING, 
    'unk_string1'   / UNICODE_STRING, 
    'unk_string2'   / UNICODE_STRING, 
    'unk_string3'   / UNICODE_STRING, 
    'username'      / UNICODE_STRING, 
    'password'      / UNICODE_STRING, 
)

CREDENTIAL_DEC_BLOCK_ENC = Struct(
    'empty'         / Int32ul, 
    'block_name'    / UNICODE_STRING, 
    'size'          / Int32ul, 
    'raw_data'      / Bytes(this.size)
)

CREDENTIAL_DECRYPTED = Struct(
    'header'    / CREDENTIAL_DEC_HEADER, 
    'main'      / CREDENTIAL_DEC_MAIN, 
    # 'data'        / If(this.header.unk_type == 2, Array(this.header.unk_blocks, CREDENTIAL_DEC_BLOCK_ENC))
)


#===============================================================================
#                           VAULT POLICY file structs
#===============================================================================


# VAULT POLICY file structs.

VAULT_POL_STORE = Struct(
    'size' / Int32ul,
    Embedded(
        Union(  
            this.size, 
            Embedded(
                Struct(
                    'unknown1'      / GuidAdapter(GUID),
                    'unknown2'      / GuidAdapter(GUID),
                    'blob_store'    / DPAPI_BLOB_STORE, 
                )
            )
        )
    )
)

VAULT_POL = Struct(
    'version'       / Int32ul,
    'guid'          / GuidAdapter(GUID), 
    'description'   / UNICODE_STRING,
    'unknown1'      / Int32ul,
    'unknown2'      / Int32ul,
    'unknown3'      / Int32ul,
    'vpol_store'    / VAULT_POL_STORE,
)


# Key Data Blob Magic (KDBM).
BCRYPT_KEY_DATA_BLOB = Struct(
    'dwMagic'       / Const(0x4d42444b, Int32ul), 
    'dwVersion'     / Int32ul,
    'cbKeyData'     / Int32ul,
    'key'           / Bytes(this.cbKeyData)
)

BCRYPT_KEY_STORE = Struct(
    'size' / Int32ul,
    Embedded(
        Union(  
            this.size, 
            Embedded(
                Struct(
                        'unknown1'      / Int32ul,
                        'unknown2'      / Int32ul,
                        'bcrypt_blob'   / BCRYPT_KEY_DATA_BLOB, 
                )
            )
        )
    )
)

VAULT_POL_KEYS = Struct(
    'vpol_key1' / BCRYPT_KEY_STORE, 
    'vpol_key2' / BCRYPT_KEY_STORE,
)


#===============================================================================
#                               VAULT file structs 
#===============================================================================

# VAULT file structs.

VAULT_ATTRIBUTE_ENCRYPTED = Struct(
    'has_iv'    / Byte,
    'encrypted' / IfThenElse(this.has_iv == 1,
        Embedded(
            Struct( 
                'iv_size'   / Int32ul,
                'iv'        / Bytes(this.iv_size), 
                'data'      / Bytes(this._._.size - 1 - 4 - this.iv_size),
            ),
        ),
        Embedded(
            Struct( 
                'data'      / Bytes(this._._.size - 1),
            ),
        ),
    )
)

VAULT_ATTRIBUTE = Struct(
    'id'                    / Int32ul, 
    'attr_unknown_1'        / Int32ul, 
    'attr_unknown_2'        / Int32ul, 
    'attr_unknown_3'        / Int32ul, 
    # Ok, this is bad, but till now I have not understood how to distinguish
    # the different structs used. Actually the last ATTRIBUTE is different.
    # Usually we have 6 more bytes zeroed, not always aligned: otherwise,
    # if id >= 100, we have 4 more bytes: weird.
    'padding'               / Optional(Const('\x00'*6, Bytes(6))),
    'attr_unknown_4'        / If(this.id >= 100, Int32ul),
    'size'                  / Int32ul,
    'vault_attr_encrypted'  / If(this.size > 0, VAULT_ATTRIBUTE_ENCRYPTED),
    'stream_end'            / Tell,
)

VAULT_ATTRIBUTE_EXTRA = Struct(
    'id'                / Int32ul, 
    'attr_unknown_1'    / Int32ul, 
    'attr_unknown_2'    / Int32ul, 
    'data'              / SIZED_DATA,
)

VAULT_ATTRIBUTE_MAP_ENTRY = Struct(
    'id'                        / Int32ul, 
    'offset'                    / Int32ul, 
    'attr_map_entry_unknown_1'  / Int32ul,
    'pointer'                   / Pointer(this.offset, VAULT_ATTRIBUTE),
)

VAULT_VCRD = Struct(
    'schema_guid'           / GuidAdapter(GUID),
    'vcrd_unknown_1'        / Int32ul, 
    'last_update'           / FileTimeAdapter(Int64ul),
    'vcrd_unknown_2'        / Int32ul, 
    'vcrd_unknown_3'        / Int32ul, 
    'description'           / UNICODE_STRING, 
    'attributes_array_size' / Int32ul,
    # 12 is the size of the VAULT_ATTRIBUTE_MAP_ENTRY structure => VAULT_ATTRIBUTE_MAP_ENTRY.sizeof() fails because of the pointer field
    'attributes_num'        / Computed(this.attributes_array_size / 12),
    'attributes'            / Array(this.attributes_num,  VAULT_ATTRIBUTE_MAP_ENTRY),
    'extra_entry'           / Pointer(
                                lambda ctx: (ctx.attributes[ctx.attributes_num -1].pointer.stream_end), 
                                VAULT_ATTRIBUTE_EXTRA
                            ),
)
