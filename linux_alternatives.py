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

        patcher = Alternative_patcher_t(self.cpufeat_node)
        patcher.patch(self.current_flags)

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
