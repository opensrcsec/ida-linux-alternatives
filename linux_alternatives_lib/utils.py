# BSD 3-Clause License
#
# Copyright (c) 2021, Open Source Security, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Author: Pawel Wieczorkiewicz <wipawel@grsecurity.net>
#
from ida_bytes import *
from ida_xref import *
from ida_ida import inf_get_indent, inf_is_64bit
from idautils import XrefsFrom
from ida_funcs import get_func, reanalyze_function
import ctypes

SIZE_TO_FLAG = {
  8: qword_flag(),
  4: dword_flag(),
  2: word_flag(),
  1: byte_flag(),
}


def get_pointer_size():
    return 8 if inf_is_64bit() else 4


PTR_SIZE = get_pointer_size()


def get_indent(off=0):
        return " " * (inf_get_indent() - 2 - off)


def get_ptr(ea):
    return get_qword(ea) if PTR_SIZE == 8 else get_dword(ea)


def is_code_ea(ea):
    return is_code(get_flags(ea))


def is_data_ea(ea):
    return is_data(get_flags(ea))


def is_defined_ea(ea):
    return is_code_ea(ea) or is_data_ea(ea)


def add_data_xref(_from, _to):
    if is_defined_ea(_from) and is_defined_ea(_to):
        add_dref(_from, _to, XREF_DATA)

def restore_xrefs(ea):
    # Remove stale code and data references
    for xref in XrefsFrom(ea):
        del_cref(xref.frm, xref.to, 0)
        del_dref(xref.frm, xref.to)

    # Reanalyze the function to get new references
    reanalyze_function(get_func(ea))

def uint64(value):
    return value % (1 << 64)


def get_sign_value_by_size(ea, size):
    if size == 8:
        return ctypes.c_long(get_qword(ea)).value
    elif size == 4:
        return ctypes.c_int(get_dword(ea)).value
    elif size == 2:
        return ctypes.c_short(get_word(ea)).value
    elif size == 1:
        return ctypes.c_byte(get_byte(ea)).value
    return None


def get_unsign_value_by_size(ea, size):
    if size == 8:
        return ctypes.c_ulong(get_qword(ea)).value
    elif size == 4:
        return ctypes.c_uint(get_dword(ea)).value
    elif size == 2:
        return ctypes.c_ushort(get_word(ea)).value
    elif size == 1:
        return ctypes.c_ubyte(get_byte(ea)).value
    return None
