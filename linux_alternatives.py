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
from ida_struct import *
from ida_bytes import *
from idaapi import *
from ida_segment import *
from ida_name import get_name_ea, get_name
from ida_ida import inf_get_indent, inf_is_64bit
from ida_xref import XREF_DATA, add_dref, del_cref, del_dref
from ida_nalt import STRTYPE_C
from ida_ua import create_insn
from ida_lines import generate_disasm_line, add_extra_cmt, delete_extra_cmts, E_PREV
from idautils import Segments, XrefsFrom
from ida_ida import inf_get_bin_prefix_size
import ida_kernwin
import ida_netnode
import ida_funcs
from PyQt5 import QtCore, QtGui, QtWidgets
import ctypes
import re
import os

PLUGIN_NAME = "Linux Alternatives"
WINDOW_NAME = "Alternatives"

ALT_INSTR_SECTION = ".altinstructions"
ALT_REPL_SECTION = ".altinstr_replacement"

SIZE_TO_FLAG = {
  8: qword_flag(),
  4: dword_flag(),
  2: word_flag(),
  1: byte_flag(),
}

PTR_SIZE = 4
if inf_is_64bit():
    PTR_SIZE = 8


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


class Alternatives_viewer_t(PluginForm):
    def __init__(self, alternatives, column_width=150):
        super(Alternatives_viewer_t, self).__init__()
        self.alternatives = alternatives
        self.column_width = column_width

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

    def PopulateForm(self):
        # Create layout
        layout = QtWidgets.QVBoxLayout()

        # Table View
        self.table = QtWidgets.QTableWidget()
        self.table.setSortingEnabled(True)
        self.table.setRowCount(len(self.alternatives["rows"]))
        self.table.setColumnCount(len(self.alternatives["header"]))
        for i in range(len(self.alternatives["header"])):
            self.table.setColumnWidth(i, self.column_width)

        self.table.setHorizontalHeaderLabels(self.alternatives["header"])
        for i, row in enumerate(self.alternatives["rows"]):
            for j, elem in enumerate(row):
                fmt = "%s" if isinstance(elem, str) else "0x%04x"
                self.table.setItem(i, j, QtWidgets.QTableWidgetItem(fmt % elem))

        self.table.cellDoubleClicked.connect(self.jumpto)

        layout.addWidget(self.table)
        self.parent.setLayout(layout)

    def jumpto(self, row, column):
        jumpto(int(self.table.item(row, max(column, 1)).text(), 16))

    def OnClose(self, form):
        self.alternatives = None


class Alt_instr_struct_t(object):
    name = 'alt_instr'

    sid = None
    size = None
    struct = None

    alt_instr_seg = None
    alt_repl_seg = None
    text_segs = []

    DEFAULT_STRUCT_SIZE = 12

    DEFAULT_INSTR_REPL_SIZE = 4
    LEN_MEMBER_SIZE = 1
    DEFAULT_INSTR_LEN_OFFSET = 10
    DEFAULT_REPL_LEN_OFFSET = 11

    FIELD_INSTR_NAME = 'instr_offset'
    FIELD_REPL_NAME = 'repl_offset'
    FIELD_CPUID_NAME = 'cpuid'
    FIELD_INSTR_LEN_NAME = 'instrlen'
    FIELD_REPL_LEN_NAME = 'replacementlen'

    def __init__(self):
        self.alt_instr_seg = get_segm_by_name(ALT_INSTR_SECTION)
        self.alt_repl_seg = get_segm_by_name(ALT_REPL_SECTION)

        # Collect CODE segments (except from ALT_REPL_SECTION)
        for segm_ea in Segments():
            segm = getseg(segm_ea)
            segm_class = get_segm_class(segm)
            segm_name = get_segm_name(segm)
            if segm_class == "CODE" and segm_name not in [get_segm_name(self.alt_repl_seg)]:
                self.text_segs.append(segm)

        # Try to find structure created from DWARF info
        sid = get_struc_id(self.name)
        if sid == BADADDR:
            sid = self._create_alt_instr_struct()

        self.sid = sid
        self.size = get_struc_size(sid)
        self.struct = get_struc(sid)

        if self.size == 0 or (self.alt_instr_seg.size() % self.size) != 0:
            ida_kernwin.warning("Incorrect layout of struct alt_instr detected!")
            return

        create_data(self.alt_instr_seg.start_ea, FF_STRUCT, self.alt_instr_seg.size(), sid)

    def _get_instr_repl_size(self, ea, segments):
        # Does 8-byte value (direct EA) belong to requested segments
        if any([get_sign_value_by_size(ea, 8) in range(segm.start_ea, segm.end_ea) for segm in segments]):
            return 8

        # Does 4-byte value (relative offset) belong to requested segments
        data = uint64(ea + get_sign_value_by_size(ea, 4))
        if any([data in range(segm.start_ea, segm.end_ea) for segm in segments]):
            return 4

        return self.DEFAULT_INSTR_REPL_SIZE

    def _get_alt_instr_struct_size(self, instr_size, repl_size):
        # Start the search after instruction and replacement fields
        for instr_ea in range(self.alt_instr_seg.start_ea + instr_size + repl_size, self.alt_instr_seg.end_ea):
            repl_ea = instr_ea + instr_size
            if repl_size == 4:
                data_instr = uint64(instr_ea + get_sign_value_by_size(instr_ea, instr_size))
                data_repl = uint64(repl_ea + get_sign_value_by_size(repl_ea, repl_size))
            elif repl_size == 8:
                data_instr = get_sign_value_by_size(instr_ea, instr_size)
                data_repl = get_sign_value_by_size(repl_ea, repl_size)
            else:
                ida_kernwin.warning("Unsupported instruction/replacement offset/address size: %u" % repl_size)
                return None

            # Replacement field value must point into .altinstr_replacement section
            if data_repl not in range(self.alt_repl_seg.start_ea, self.alt_repl_seg.end_ea):
                continue

            # Instruction field value must point into a text section, but not .altinstr_replacement
            if all([data_instr not in range(seg.start_ea, seg.end_ea) for seg in self.text_segs]):
                continue

            # Multiplied detected structure size must cover .altinstructions sections exactly
            size = instr_ea - self.alt_instr_seg.start_ea
            if (self.alt_instr_seg.size() % size) != 0:
                continue
            return size

        return self.DEFAULT_STRUCT_SIZE

    def _get_byte_value_sum(self, segm, offset):
        return sum([get_byte(ea + offset) for ea in range(segm.start_ea, segm.end_ea, self.size)])

    def _get_byte_value_set(self, segm, offset):
        return set([get_byte(ea + offset) for ea in range(segm.start_ea, segm.end_ea, self.size)])

    def _find_len_fields_offsets(self, cpuid_off):
        # Start the search after first byte of cpuid field
        for instrlen_offset in range(cpuid_off + 1, self.size):
            instrlen_set = self._get_byte_value_set(self.alt_instr_seg, instrlen_offset)
            # Instruction len field cannot have 0 value
            if 0 in instrlen_set:
                continue

            repllen_offset = instrlen_offset + self.LEN_MEMBER_SIZE

            sum = self._get_byte_value_sum(self.alt_instr_seg, repllen_offset)
            # Match if sum of all Replacement len fields is equal to
            # the size of entire .altinstr_replacement section
            if sum == self.alt_repl_seg.size():
                return instrlen_offset, repllen_offset
            # If the sum is smaller than the section size it cannot be
            # the Replacement len field
            elif sum < self.alt_repl_seg.size():
                continue

            repllen_set = self._get_byte_value_set(self.alt_instr_seg, repllen_offset)
            # Not a match if exists Replacement len value bigger
            # than any of the Instruction len value
            if max(repllen_set) > max(instrlen_set):
                continue

            return instrlen_offset, repllen_offset

        return self.DEFAULT_INSTR_LEN_OFFSET, self.DEFAULT_REPL_LEN_OFFSET

    def _create_alt_instr_struct(self):
        sid = add_struc(BADADDR, self.name)
        struct = get_struc(sid)

        instr_size = self._get_instr_repl_size(self.alt_instr_seg.start_ea, self.text_segs)
        repl_size = self._get_instr_repl_size(self.alt_instr_seg.start_ea + instr_size, [self.alt_repl_seg])

        self.size = self._get_alt_instr_struct_size(instr_size, repl_size)

        cpuid_off = instr_size + repl_size

        instr_len_off, repl_len_off = self._find_len_fields_offsets(cpuid_off)
        instr_len_size = repl_len_size = repl_len_off - instr_len_off

        cpuid_size = instr_len_off - cpuid_off

        add_struc_member(struct, self.FIELD_INSTR_NAME, BADADDR, SIZE_TO_FLAG[instr_size], None, instr_size)
        add_struc_member(struct, self.FIELD_REPL_NAME, BADADDR, SIZE_TO_FLAG[repl_size], None, repl_size)
        add_struc_member(struct, self.FIELD_CPUID_NAME, BADADDR, SIZE_TO_FLAG[cpuid_size], None, cpuid_size)
        add_struc_member(struct, self.FIELD_INSTR_LEN_NAME, BADADDR, SIZE_TO_FLAG[instr_len_size], None, instr_len_size)
        add_struc_member(struct, self.FIELD_REPL_LEN_NAME, BADADDR, SIZE_TO_FLAG[repl_len_size], None, repl_len_size)

        for i in range(self.size - get_struc_size(struct)):
            add_struc_member(struct, "padlen%u" % i, BADADDR, SIZE_TO_FLAG[1], None, 1)

        return sid

    def get_struct_metadata(self):
        return [(get_member_name(member.id), get_member_size(member), member.get_soff()) for member in self.struct.members]


class CPU_flags_t(object):
    CPU_FLAG_SYMBOLS = {
        'caps': { 'x86_cap_flags': None },
        'bugs': { 'x86_bug_flags': None },
    }

    NCAPINTS = 20
    ncapints = None

    NBUGINTS = 1
    nbugints = None

    cpufeatures = None

    ALT_INSTR_FLAG_INV = 1 << 15
    INV_PREFIX = "! "

    def __init__(self, cpufeat_node):
        for _, symbols in self.CPU_FLAG_SYMBOLS.items():
            for symbol, _ in symbols.items():
                symbols[symbol] = get_name_ea(BADADDR, symbol)

        # Try to find feature flag names in binary
        self.ncapints = self._analyze_flag_names('caps') // (PTR_SIZE * 32)
        if not self.ncapints:
            self.ncapints = self.NCAPINTS
        self.nbugints = self._analyze_flag_names('bugs') // (PTR_SIZE * 32)
        if not self.nbugints:
            self.nbugints = self.NBUGINTS

        # Parse cpufeatures.h file if specified
        filepath = cpufeat_node[0].supval(cpufeat_node[1])
        if filepath and os.path.exists(filepath):
            print("Parsing %s for flags" % filepath.decode("utf-8"))
            self.cpufeatures = self._parse_cpufeatures_file(filepath)

    def _analyze_flag_names(self, kind):
        def __analyze_flag_names(symbol, symbol_ea):
            if symbol_ea == BADADDR:
                return None

            print("Analyzing flags for symbol '%s' at %x..." % (symbol, symbol_ea))

            for ea in range(symbol_ea, BADADDR, PTR_SIZE):
                # Stop processing when new symbol begins
                if ea > symbol_ea and len(get_name(ea)):
                    return ea - symbol_ea # Array size

                (create_qword if PTR_SIZE == 8 else create_dword)(ea, PTR_SIZE, True)

                str_ea = get_qword(ea)
                del_items(str_ea)

                create_strlit(str_ea, 0, STRTYPE_C)
                add_data_xref(ea, str_ea)

        return sum([__analyze_flag_names(name, ea) for name, ea in self.CPU_FLAG_SYMBOLS[kind].items() if ea != BADADDR])

    def _parse_cpufeatures_file(self, filepath):
        features = {}
        with open(filepath, "r") as f:
            for line in f.readlines():
                line = line.lstrip()
                # Get NCAPINTS value
                match = re.search('^#define\s+NCAPINTS\s+([0-9]+)\s+', line)
                if match:
                    self.ncapints = int(match.group(1))
                    continue

                # Get NBUGINTS value
                match = re.search('^#define\s+NBUGINTS\s+([0-9]+)\s+', line)
                if match:
                    self.nbugints = int(match.group(1))
                    continue

                # Get X86_FEATURE_* value
                match = re.search('^#define\s+X86_FEATURE_([^\s]+)\s+\(([\s0-9]+?)\*32\+([\s0-9]+?)\)\s+', line)
                if match:
                    feature, word, bit = match.group(1), int(match.group(2)), int(match.group(3))
                    features[feature] = (word, bit)
                    continue

                # Get X86_BUG_* value
                match = re.search('^#define\s+X86_BUG_([^\s]+)\s+X86_BUG\(([\s0-9]+?)\)\s+', line)
                if match:
                    feature, word, bit = match.group(1), self.ncapints, int(match.group(2))
                    features[feature] = (word, bit)

        return dict((v, k) for k, v in features.items())

    def get_flag_name(self, cpuid, kind='caps'):
        def _get_feature_string(array_ea, _flag):
            ea = array_ea + _flag * PTR_SIZE
            return get_strlit_contents(get_ptr(ea), -1, STRTYPE_C)

        # Handle inverted alternatives
        if cpuid & self.ALT_INSTR_FLAG_INV:
            flag = cpuid & ~self.ALT_INSTR_FLAG_INV
            prefix = self.INV_PREFIX
        else:
            flag = cpuid
            prefix = ""

        word, bit = (flag >> 5, flag & 0b011111)

        # Try to take flag from the imported file
        if self.cpufeatures:
            flag_name = self.cpufeatures.get((word, bit), None)
            if flag_name:
                return prefix, flag_name

        # Try to take flag from symbols in binary
        for _, array_ea in self.CPU_FLAG_SYMBOLS[kind].items():
            if array_ea == BADADDR:
                continue

            flag_name = _get_feature_string(array_ea, flag)
            if flag_name:
                return prefix, flag_name.decode("utf-8").upper()

        # Default to (word, bit)
        return prefix, "%u, %u" % (word, bit)


class Alternative_generator_t(object):
    def __init__(self, cpu_flags, alt_instr_struct):
        self.view = None

        self.cpu_flags = cpu_flags
        self.alt_instr_struct = alt_instr_struct

    @staticmethod
    def create_replacement(repl_ea, repl_len):
        def create_instruction(ea):
            size = create_insn(ea)
            if size == 0:
                return get_item_size(ea)
            return size

        _len = 0
        while _len < repl_len:
            _len += create_instruction(repl_ea + _len)

    @staticmethod
    def get_replacement_lines(ea, repl_len, instr_len, indent):
        lines = []

        num_opcodes = inf_get_bin_prefix_size()
        max_opcodes = len(indent)

        _len = 0
        while _len < repl_len:
            line, size = generate_disasm_line(ea + _len), get_item_size(ea + _len)
            opcodes = " ".join(["%02x" % get_byte(ea + _len + i) for i in range(min(size, num_opcodes))])
            if num_opcodes > 0:
                if size > num_opcodes:
                    opcodes += "+"
                if len(opcodes) >= max_opcodes:
                    opcodes += " " * 3
            lines.append((opcodes, line))
            max_opcodes = max(max_opcodes, len(opcodes))
            _len += size

        if repl_len == 0:
            while _len < instr_len:
                line, size = "nop", 1
                opcodes = " ".join(["90" for i in range(min(size, num_opcodes))])
                lines.append((opcodes, line))
                max_opcodes = max(max_opcodes, len(opcodes))
                _len += size

        return ["%s%s%s" % (opcodes, " " * (max_opcodes - len(opcodes)), line) for opcodes, line in lines]

    def _gen_replacement_line(self, row, processed_alternatives, indent=1):
        index, instr_ea, repl_ea, flag_str, instr_len, repl_len = row[:6]
        line = []

        index_str = "[0x%04x]" % index
        indent_str = get_indent(4 + len(index_str)) * indent
        line.append("%s%sif feature: %s" % (index_str, indent_str, flag_str))

        # Not just NOPs
        if repl_len != 0:
            # Generate nested alternatives
            repl_rows = processed_alternatives.get(repl_ea, [])
            if len(repl_rows) > 0:
                for repl_row in repl_rows:
                    line += self._gen_replacement_line(repl_row, indent + 1)

                line.append("%s" % ("\n".join(self.get_replacement_lines(repl_ea, repl_len, instr_len, get_indent() * (indent + 1)))))
                line.append("%sendif" % (get_indent(4) * (indent + 1)))

        line.append("%s" % ("\n".join(self.get_replacement_lines(repl_ea, repl_len, instr_len, get_indent() * indent))))
        line.append("%selse" % (get_indent(4) * indent))

        return line

    def add_alternatives_cmts(self, row, processed_alternatives):
        ea, size = row[1], row[4]
        line = []

        if ea not in processed_alternatives:
            line.append("Alternatives:")

        line += self._gen_replacement_line(row, processed_alternatives)
        add_extra_cmt(ea, True, "\n".join(line))

        if ea not in processed_alternatives:
            add_extra_cmt(ea + size, True, '%sendif' % get_indent(4))

    def _get_alternative_row(self, ea, metadata):
        vinstr_ea = vrepl_ea = cpuid = instr_len = repl_len = 0
        padlens = []

        for name, size, offset in metadata:
            if name.startswith("instr") and not name.endswith("len"):
                instr_off = get_sign_value_by_size(ea + offset, size)
                vinstr_ea = uint64(instr_off + ea + offset) if size == 4 else instr_off
            elif name.startswith("repl") and not name.endswith('len'):
                repl_off = get_sign_value_by_size(ea + offset, size)
                vrepl_ea = uint64(repl_off + ea + offset) if size == 4 else repl_off
            elif name.startswith("cpuid"):
                cpuid = get_unsign_value_by_size(ea + offset, size)
            elif name.startswith("instr") and name.endswith("len"):
                instr_len = get_sign_value_by_size(ea + offset, size)
            elif name.startswith("repl") and name.endswith("len"):
                repl_len = get_sign_value_by_size(ea + offset, size)
            else:
                padlens.append(get_sign_value_by_size(ea + offset, size))

        return vinstr_ea, vrepl_ea, cpuid, instr_len, repl_len, padlens

    def gen_alternatives(self, cb, req_features=[]):
        alt_instr_seg = get_segm_by_name(ALT_INSTR_SECTION)

        metadata = self.alt_instr_struct.get_struct_metadata()

        index = 0
        processed_alternatives = {}
        for ea in range(alt_instr_seg.start_ea, alt_instr_seg.end_ea, self.alt_instr_struct.size):
            vinstr_ea, vrepl_ea, cpuid, instr_len, repl_len, padlens = self._get_alternative_row(ea, metadata)

            prefix, flag_name = self.cpu_flags.get_flag_name(cpuid)
            flag_str = "%s%s" % (prefix, flag_name)

            if len(req_features) > 0:
                if flag_str.startswith(self.cpu_flags.INV_PREFIX):
                    if flag_str[len(self.cpu_flags.INV_PREFIX):] in req_features:
                        continue
                elif flag_str not in req_features:
                    continue

            self.create_replacement(vrepl_ea, repl_len)
            if repl_len > 0:
                add_data_xref(vinstr_ea, vrepl_ea)

            row = [index, vinstr_ea, vrepl_ea, flag_str, instr_len, repl_len] + padlens
            index += 1

            cb(row, processed_alternatives)

            if vinstr_ea not in processed_alternatives:
                processed_alternatives[vinstr_ea] = []
            processed_alternatives[vinstr_ea].append(row)

        return processed_alternatives


class File_loader_t(ida_kernwin.action_handler_t):
    def __init__(self, action_name, node):
        ida_kernwin.action_handler_t.__init__(self)
        self.action_name = action_name
        self.node = node

    def activate(self, ctx):
        filepath = ida_kernwin.ask_file(False, None, self.action_name)
        self.node[0].supset(self.node[1], filepath)
        print("Loaded %s file" % filepath)

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class Remover_t(ida_kernwin.action_handler_t):
    def __init__(self, reset, action_name):
        ida_kernwin.action_handler_t.__init__(self)
        self.reset = reset
        self.action_name = action_name

    def activate(self, ctx):
        self.reset()

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class Patch_input_t(ida_kernwin.action_handler_t):
    def __init__(self, action_name, cpufeat_node):
        ida_kernwin.action_handler_t.__init__(self)
        self.action_name = action_name
        self.cpufeat_node = cpufeat_node
        self.current_flags = None

    def activate(self, ctx):
        prompt = "Enter comma-separated list of CPU features"
        defval = self.current_flags if self.current_flags else ""

        patch_features_str = ida_kernwin.ask_str(defval, 0, prompt)
        # Ignore when nothing has been specified
        if not patch_features_str:
            return

        self.current_flags = patch_features_str.upper()
        print("Patching alternatives for feature flags: %s" % patch_features_str)

        self.alt_instr_struct = Alt_instr_struct_t()
        self.cpu_flags = CPU_flags_t(self.cpufeat_node)

        patch_features = self._process_specified_features(self.current_flags)

        self.alt_gen = Alternative_generator_t(self.cpu_flags, self.alt_instr_struct)
        self.alt_gen.gen_alternatives(self.patch_rows, patch_features)

    def patch_rows(self, row, processed_alternatives):
        instr_ea, repl_ea, flag_str, instr_len, repl_len = row[1:6]

        repl_bytes = get_bytes(repl_ea, repl_len) if repl_len > 0 else  b''
        repl_bytes = self._recompute_branches(repl_bytes, instr_ea, repl_ea, instr_len, repl_len)

        # Save original disassembly
        orig_insns = self.alt_gen.get_replacement_lines(instr_ea, instr_len, instr_len, get_indent(-4))

        patch_bytes(instr_ea, repl_bytes)

        # Tell IDA to make code explicitely
        self.alt_gen.create_replacement(instr_ea, instr_len)

        # Remove stale code and data references
        for xref in XrefsFrom(instr_ea):
            del_cref(xref.frm, xref.to, 0)
            del_dref(xref.frm, xref.to)

        # Reanalyze the function to get new references
        ida_funcs.reanalyze_function(ida_funcs.get_func(instr_ea))

        cmt = ["%sAlternative %s applied" % (get_indent(), flag_str)]
        cmt.append("%sOriginal instructions:\n%s" % (get_indent(), "\n".join(orig_insns)))
        add_extra_cmt(instr_ea, True, "\n".join(cmt))

    def _recompute_branches(self, opcodes, instr_ea, repl_ea, instr_len, repl_len):
        def is_rel_call(opcodes, size):
            return size == 5 and opcodes[0] == 0xe8

        def is_jmp(opcodes, size):
            return size in [5, 6] and opcodes[0] in [0xeb, 0xe9] # 6 covers for SLS barrier

        def add_nops(opcodes, instr_len, repl_len):
            return opcodes + b'\x90' * (instr_len - repl_len)

        def two_byte_jmp(displ):
            displ -= 2
            return add_nops(b'\xeb' + displ.to_bytes(1), 5, 2)

        def five_byte_jmp(displ):
            displ -= 5
            return b'\xe9' + displ.to_bytes(4, 'little')

        new_opcodes = opcodes

        if is_rel_call(opcodes, repl_len):
            o_disp = ctypes.c_int(int.from_bytes(opcodes[1:], "little")).value
            new_opcodes = b'\xe8' + ctypes.c_long(o_disp + (repl_ea - instr_ea)).value.to_bytes(4, 'little')
        elif is_jmp(opcodes, repl_len):
            o_disp = ctypes.c_int(int.from_bytes(opcodes[1:], "little")).value
            next_rip = uint64(ctypes.c_long(repl_ea + 5).value)
            tgt_rip = uint64(ctypes.c_long(next_rip + o_disp).value)
            n_dspl = ctypes.c_int(tgt_rip - instr_ea).value

            if ctypes.c_long(tgt_rip - instr_ea).value >= 0:
                new_opcodes = two_byte_jmp(n_dspl) if n_dspl - 2 <= 127 else five_byte_jmp(n_dspl)
            else:
                new_opcodes = two_byte_jmp(n_dspl) if ((n_dspl - 2) & 0xff) == n_dspl - 2 else five_byte_jmp(n_dspl)
        elif instr_len > repl_len:
            new_opcodes = add_nops(opcodes, instr_len, repl_len)

        return new_opcodes

    def _process_specified_features(self, input_features):
        features = []

        for feature in input_features.split(','):
            feature = feature.strip()
            try:
                cpuid = int(feature, 0)
                _, name = self.cpu_flags.get_flag_name(cpuid)
                features.append(name)
            except:
                features.append(feature.upper())

        return features

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class Linux_alternatives_t(plugin_t):
    flags = 0
    comment = "Analyze and annotate linux kernel alternatives"
    help = ""
    wanted_name = PLUGIN_NAME
    wanted_hotkey = "Alt-F9"

    TOPMENU = "Edit"

    cpufeat_name = "cpufeatures.h"
    cpufeat_node = [None, 0]

    cpu_flags = None
    alt_instr_struct = None

    cpufeatures_action_name = None

    remove_action_name = "Remove alternative comments"

    patch_input_name = "patch_input"
    patch_input_action_name = "Patch selected alternatives"
    patch_input_node = [None, 0]

    def __init__(self):
        self.view = None
        self.alternatives = {}

        self.cpufeatures_action_name = "Import %s file" % self.cpufeat_name

    def init(self):
        ida_kernwin.create_menu(PLUGIN_NAME, PLUGIN_NAME, "%s/" % self.TOPMENU)

        self.cpufeat_node[0] = ida_netnode.netnode("$ %s" % self.cpufeat_name, self.cpufeat_node[1], True)
        self._register_cpufeatures_action()

        self.patch_input_node[0] = ida_netnode.netnode("$ %s" % self.patch_input_name, self.patch_input_node[1], True)
        self._register_patch_input_action()

        return PLUGIN_KEEP

    def run(self, arg):
        self.reset()
        print("Running %s plugin..." % PLUGIN_NAME)

        self.alt_instr_struct = Alt_instr_struct_t()
        self.cpu_flags = CPU_flags_t(self.cpufeat_node)
        alt_gen = Alternative_generator_t(self.cpu_flags, self.alt_instr_struct)

        alternatives = alt_gen.gen_alternatives(alt_gen.add_alternatives_cmts)
        self._register_remove_action()

        self.alternatives["header"] = ["index"]
        self.alternatives["header"] += [name for name, _, _ in self.alt_instr_struct.get_struct_metadata()]
        for _, rows in alternatives.items():
            for row in rows:
                self.alternatives["rows"].append(row)
        self.display_alternatives()

    def term(self):
        self._reset_alternatives()

        if self.view:
            self.view.Close(ida_kernwin.WCLS_DONT_SAVE_SIZE)

        ida_kernwin.unregister_action(self.remove_action_name)
        ida_kernwin.unregister_action(self.cpufeatures_action_name)

    def reset(self):
        self.term()
        self.init()

    def _reset_alternatives(self):
        # Remove applied alternatives comments
        for row in self.alternatives.get("rows", []):
            ea, size = row[1], row[4]

            delete_extra_cmts(ea, E_PREV)
            delete_extra_cmts(ea + size, E_PREV)

        self.alternatives["header"] = []
        self.alternatives["rows"] = []

    def _register_cpufeatures_action(self):
        action_name = self.cpufeatures_action_name
        desc = ida_kernwin.action_desc_t(action_name, action_name, File_loader_t(action_name, self.cpufeat_node))
        ida_kernwin.register_action(desc)
        ida_kernwin.attach_action_to_menu("%s/%s/" % (self.TOPMENU, PLUGIN_NAME), action_name, ida_kernwin.SETMENU_INS)

    def _register_patch_input_action(self):
        action_name = self.patch_input_action_name
        desc = ida_kernwin.action_desc_t(action_name, action_name, Patch_input_t(action_name, self.cpufeat_node))
        ida_kernwin.register_action(desc)
        ida_kernwin.attach_action_to_menu("%s/%s/" % (self.TOPMENU, PLUGIN_NAME), action_name, ida_kernwin.SETMENU_INS)

    def _register_remove_action(self):
        action_name = self.remove_action_name
        desc = ida_kernwin.action_desc_t(action_name, action_name, Remover_t(self.reset, action_name))
        ida_kernwin.register_action(desc)
        ida_kernwin.attach_action_to_menu("%s/%s/" % (self.TOPMENU, PLUGIN_NAME), action_name, ida_kernwin.SETMENU_INS)

    def display_alternatives(self):
        self.view = Alternatives_viewer_t(self.alternatives)
        self.view.Show("Alternatives")


def PLUGIN_ENTRY():
    return Linux_alternatives_t()
