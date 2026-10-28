from itertools import chain

import idaapi
import ida_kernwin
import ida_funcs
import ida_strlist

from yarmaker.adapter import YaraExtractor
from yarmaker.types import String, Wildcard
from yarmaker.extractor import RangeExtractor, FunctionExtractor
from yarmaker.yara import RuleBuilder, RulesetBuilder
from yarmaker import ui
from yarmaker import utils


# rule parameters
WRAP_CURLY_BRACE = False        # wrap curly brace on a new line
INDENT_HEADERS = False          # indent for 'meta', 'strings', 'condition'

# editor default settings
DEFAULT_SHOW_COMMENTS = True    # show comments (checkbox)
DEFAULT_WILDCARD = (            # wildcarded instruction parts (dropdown)
    Wildcard.OFFSETS | Wildcard.DISPLACEMENTS
)
DEFAULT_ONELINER = False        # single line patterns without comments (checkbox)
DEFAULT_INDENT = 3              # default indent
DEFAULT_NAMED_VARIABLES = True  # use names for strings (variables)
DEFAULT_SHOW_TEMPLATE = False   # show full rule instead of strings only (checkbox)

# wildcard dropdown entries (label, mask), the default must be one of them
WILDCARD_MODES = [
    (
        'Exclude offsets + displacements + registers + constants',
        Wildcard.OFFSETS | Wildcard.DISPLACEMENTS | Wildcard.REGISTERS | Wildcard.CONSTANTS,
    ),
    (
        'Exclude offsets + displacements + constants',
        Wildcard.OFFSETS | Wildcard.DISPLACEMENTS | Wildcard.CONSTANTS,
    ),
    (
        'Exclude offsets + displacements + registers',
        Wildcard.OFFSETS | Wildcard.DISPLACEMENTS | Wildcard.REGISTERS,
    ),
    (
        'Exclude offsets + displacements',
        Wildcard.OFFSETS | Wildcard.DISPLACEMENTS,
    ),
    ('Exclude offsets', Wildcard.OFFSETS),
    ('Exclude nothing (strict)', Wildcard.NONE),
]

# values can be string or lambda
DEFAULT_META_FIELDS = {
    'description': '',
    'source': 'Internal research',
    'date': lambda: utils.get_current_time('%Y-%m-%d'),
    'hash': lambda: utils.get_file_md5(),
    # 'hash': lambda: utils.get_file_sha256(),
}

# values can be string or lambda (optional argument - strings count)
DEFAULT_CONDITIONS = [
    lambda: '(PE)' in idaapi.get_file_type_name() and 'uint16(0) == 0x5a4d',
    lambda: 'ELF' in idaapi.get_file_type_name() and 'uint32(0) == 0x464c457f',
    lambda count: f'{count // 2} of them' if count > 2 else 'all of them'
]


def generate_rule(name, entities) -> RuleBuilder:
    rule = RuleBuilder(
        name,
        indent_headers=INDENT_HEADERS,
        wrap_curly_brace=WRAP_CURLY_BRACE,
        wildcard=DEFAULT_WILDCARD,
        show_template=DEFAULT_SHOW_TEMPLATE,
        oneliner=DEFAULT_ONELINER,
    )

    for header, value in DEFAULT_META_FIELDS.items():
        rule.add_meta(header, value)
    
    existing = set()
    for i, entity in enumerate(entities, start=1):
        if str(entity) not in existing:
            rule.add_string(f'op{i}', entity)
            existing.add(str(entity))

    for condition in DEFAULT_CONDITIONS:
        rule.add_condition(condition)

    return rule


class YaraDialog(ui.ClosableDialog):
    def __init__(self, rule: RuleBuilder):
        self.rule = rule

        self.wildcard_combo = ui.ComboBox(
            items=[(label, int(mask)) for label, mask in WILDCARD_MODES],
            default=int(DEFAULT_WILDCARD),
            on_change=self.handle_wildcard_change,
        )
        self.comments_checkbox = ui.Checkbox(
            label='Show comments',
            default=DEFAULT_SHOW_COMMENTS,
            on_click=self.handle_comments_checkbox_click,
        )
        self.oneliner_checkbox = ui.Checkbox(
            label='One-liner',
            default=DEFAULT_ONELINER,
            on_click=self.handle_oneliner_click,
        )
        self.comments_checkbox.setEnabled(not DEFAULT_ONELINER)
        self.use_named_variables_checkbox = ui.Checkbox(
            label='Named variables',
            default=DEFAULT_NAMED_VARIABLES,
            on_click=self.handle_named_variables_click,
        )
        self.show_template_checkbox = ui.Checkbox(
            label='Show Yara Rule Template',
            default=DEFAULT_SHOW_TEMPLATE,
            on_click=self.handle_show_template_click,
        )
        self.indent_edit_label = ui.Label('Indentation')
        self.indent_edit = ui.NumberInput(
            default=DEFAULT_INDENT,
            min_value=2,
            max_value=8,
            step=1,
            on_change=self.handle_indent_change,
        )
        self.text_edit = ui.YaraTextEdit(rule.build())

        super().__init__(
            title = 'YarMaker - Generated Yara Rule',
            width=800,
            top_left_items=[
                self.wildcard_combo,
                self.comments_checkbox,
                self.oneliner_checkbox,
                self.use_named_variables_checkbox,
            ],
            top_right_items=[self.indent_edit_label, self.indent_edit],
            body_items=[self.text_edit],
            bottom_left_items=[self.show_template_checkbox],
        )

    def _rebuild_rule(self):
        content = self.rule.build()
        self.text_edit.set_content(content)

    def handle_wildcard_change(self):
        self.rule.wildcard = Wildcard(self.wildcard_combo.value())
        self._rebuild_rule()

    def handle_comments_checkbox_click(self):
        self.rule.show_comments = self.comments_checkbox.is_checked()
        self._rebuild_rule()

    def handle_oneliner_click(self):
        oneliner = self.oneliner_checkbox.is_checked()
        self.rule.oneliner = oneliner
        self.comments_checkbox.setEnabled(not oneliner)
        # comments are never shown in oneliner mode
        self.rule.show_comments = self.comments_checkbox.is_checked()
        self._rebuild_rule()

    def handle_named_variables_click(self):
        self.rule.use_named_variables = self.use_named_variables_checkbox.is_checked()
        self._rebuild_rule()

    def handle_show_template_click(self):
        self.rule.show_template = self.show_template_checkbox.is_checked()
        self._rebuild_rule()

    def handle_indent_change(self):
        self.rule.indent = self.indent_edit.value()
        self._rebuild_rule()


class YarMakerPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = 'YarMaker Plugin'
    help = 'YarMaker Plugin'
    wanted_name = 'YarMaker'
    wanted_hotkey = 'Ctrl+Alt+Y'
    banner = (
        r" __   __         __  __       _            " "\n"
        r" \ \ / /_ _ _ __|  \/  | __ _| | _____ _ __ " "\n"
        r"  \ V / _` | '__| |\/| |/ _` | |/ / _ \ '__|" "\n"
        r"   | | (_| | |  | |  | | (_| |   <  __/ |   " "\n"
        r"   |_|\__,_|_|  |_|  |_|\__,_|_|\_\___|_|   "
    )

    def init(self):
        self.ui_hooks = YarMakerUIHooks()
        self.ui_hooks.hook()

        label = 'YarMaker: Generate Rule'
        hotkey = 'Ctrl+Y'
        YarMakerRule.register(self, label, hotkey)
        YarMakerStrings.register(self, label, hotkey)
        YarMakerFunctions.register(self, label, hotkey)

        idaapi.msg(f'[{self.wanted_name}] loaded, hotkey - {self.wanted_hotkey}')
        return idaapi.PLUGIN_KEEP

    def term(self):
        self.ui_hooks.unhook()

    def run(self, arg):
        ida_kernwin.show_wait_box('Generating ruleset ...')

        ruleset = RulesetBuilder()
        functions = list(utils.get_custom_functions())
        for i, function in enumerate(functions, start=1):
            if ida_kernwin.user_cancelled():
                ida_kernwin.hide_wait_box()
                ida_kernwin.warning('YarMaker - ruleset generation canceled')
                return None

            ida_kernwin.replace_wait_box(f'Processing ({i}/{len(functions)})')

            try:
                name = ida_funcs.get_func_name(function.start_ea)
                entities = YaraExtractor(FunctionExtractor(function.start_ea))
                rule = generate_rule(name=name, entities=list(entities))
                if not rule.is_empty():
                    ruleset.append(rule)
            except Exception as e:
                ida_kernwin.warning(f'YarMaker - unexpected error {e}')

        ida_kernwin.replace_wait_box('Building ruleset ...')

        self.dialog = YaraDialog(ruleset)
        self.dialog.show()
        ida_kernwin.hide_wait_box()


class YarMakerRule(ui.ActionHandler):
    __windows__ = [idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE]

    def activate(self, ctx):
        start, end = utils.get_selection()
        name = f'{utils.get_file_name()}_0x{start:08X}'
        entities = YaraExtractor(RangeExtractor(start, end))
        rule = generate_rule(name=name, entities=entities)

        self.dialog = YaraDialog(rule)
        self.dialog.show()


class YarMakerStrings(ui.ActionHandler):
    __windows__ = [idaapi.BWN_STRINGS]

    def activate(self, ctx):
        strings = []
        for idx in ctx.chooser_selection:
            si = ida_strlist.string_info_t()
            if not ida_strlist.get_strlist_item(si, idx):
                continue

            string_gen = YaraExtractor([String.from_string_info(si)])
            strings.append(string_gen)
        
        name = f'{utils.get_file_name()}_strings'
        entities = chain.from_iterable(strings)
        rule = generate_rule(name=name, entities=entities)

        self.dialog = YaraDialog(rule)
        self.dialog.show()


class YarMakerFunctions(ui.ActionHandler):
    __windows__ = [idaapi.BWN_FUNCS]

    def activate(self, ctx):
        ruleset = RulesetBuilder()
        for idx in ctx.chooser_selection:
            _, _, location, *_ = ida_kernwin.get_chooser_data(ctx.widget_title, idx)
            address = int(location.lstrip('0'), 16)

            name = ida_funcs.get_func_name(address)
            if not name:
                continue

            entities = YaraExtractor(FunctionExtractor(address))
            rule = generate_rule(name=name, entities=list(entities))
            if not rule.is_empty():
                ruleset.append(rule)

        self.dialog = YaraDialog(ruleset)
        self.dialog.show()


class YarMakerUIHooks(idaapi.UI_Hooks):
    def populating_widget_popup(self, form, popup):
        pass

    def finish_populating_widget_popup(self, form, popup):
        YarMakerRule.attach_ctx_menu(form, popup, 'YarMaker')
        YarMakerStrings.attach_ctx_menu(form, popup, 'YarMaker')
        YarMakerFunctions.attach_ctx_menu(form, popup, 'YarMaker')


plugin = YarMakerPlugin()


def PLUGIN_ENTRY():
    global plugin
    return plugin
