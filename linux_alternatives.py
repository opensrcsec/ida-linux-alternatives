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
from ida_lines import delete_extra_cmts, E_PREV
from PyQt5 import QtWidgets
import ida_kernwin
import ida_netnode

from linux_alternatives_lib.lib import *

PLUGIN_NAME = "Linux Alternatives"
WINDOW_NAME = "Alternatives"


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
        try:
            jumpto(int(self.table.item(row, max(column, 1)).text(), 16))
        except:
            pass

    def OnClose(self, form):
        self.alternatives = None


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

        patch_features = self._process_specified_features(self.current_flags)

        self.alt_gen = Alternative_generator_t(self.cpufeat_node)
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
            return add_nops(b'\xeb' + displ.to_bytes(1, 'little', signed=True), 5, 2)

        def five_byte_jmp(displ):
            displ -= 5
            return b'\xe9' + displ.to_bytes(4, 'little', signed=True)

        new_opcodes = opcodes

        if is_rel_call(opcodes, repl_len):
            o_disp = ctypes.c_int(int.from_bytes(opcodes[1:], "little")).value
            new_opcodes = b'\xe8' + ctypes.c_long(o_disp + (repl_ea - instr_ea)).value.to_bytes(4, 'little', signed=True)
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

        alt_gen = Alternative_generator_t(self.cpufeat_node)
        struct_metadata = alt_gen.alt_instr_struct.get_struct_metadata()

        alternatives = alt_gen.gen_alternatives(alt_gen.add_alternatives_cmts)
        self._register_remove_action()

        self.alternatives["header"] = ["index"] + [name for name, _, _ in struct_metadata]
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
