import idaapi

# in the future, maybe change for
# ida_idp.IDP_INTERFACE_VERSION >= 700
if idaapi.IDA_SDK_VERSION >= 700:
    import ida_bytes
    import ida_dbg
    import ida_ida
    import ida_kernwin
    import ida_name
    import idautils
    import json
    import traceback
    from idc import *
else:
    print("Use version 1.0")


def MinEA(): return get_inf_attr(ida_ida.INF_MIN_EA)


def MaxEA(): return get_inf_attr(ida_ida.INF_MAX_EA)


def Comment(ea): return ida_bytes.get_cmt(ea, 0)


def RptCmt(ea): return ida_bytes.get_cmt(ea, 1)


initialized = False
BPNORMAL = 0
BPHARDWARE = 1
UE_HARDWARE_EXECUTE = 4
UE_HARDWARE_WRITE = 5
UE_HARDWARE_READWRITE = 6
UE_HARDWARE_SIZE_1 = 7
UE_HARDWARE_SIZE_2 = 8
UE_HARDWARE_SIZE_4 = 9
UE_HARDWARE_SIZE_8 = 10
LAST_EXPORT_FILE_NAME = None


def Comments():
    lastea = 0
    lastcmt = ""
    for ea in range(MinEA(), MaxEA()):
        cmt1 = Comment(ea)
        cmt2 = RptCmt(ea)
        cmt = ""
        if cmt1:
            cmt += cmt1
        if cmt2:
            cmt += cmt2
        if not cmt:
            continue
        skip = ea == lastea + 1 and cmt == lastcmt
        lastea = ea
        lastcmt = cmt
        if not skip:
            yield ea, cmt


def Breakpoints():
    count = ida_dbg.get_bpt_qty()
    for i in range(0, count):
        ea = get_bpt_ea(i)
        bpt = idaapi.bpt_t()
        if not idaapi.get_bpt(ea, bpt):
            continue
        if bpt.type & BPT_SOFT != 0:
            yield ea, BPNORMAL, 0, ida_bytes.get_wide_word(ea)
            continue
        bptype = BPNORMAL if bpt.type == BPT_DEFAULT else BPHARDWARE
        hwtype = {
            BPT_WRITE: UE_HARDWARE_WRITE,
            BPT_RDWR: UE_HARDWARE_READWRITE,
            BPT_EXEC: UE_HARDWARE_EXECUTE
        }[bpt.type]
        hwsize = {
            1: UE_HARDWARE_SIZE_1,
            2: UE_HARDWARE_SIZE_2,
            4: UE_HARDWARE_SIZE_4,
            8: UE_HARDWARE_SIZE_8,
        }[bpt.size]
        yield ea, bptype, (hwtype << 4 | hwsize), 0


def get_file_mask():
    return "*.dd64" if idaapi.get_inf_structure().is_64bit() else "*.dd32"


def do_import():
    module = idaapi.get_root_filename().lower()
    base = idaapi.get_imagebase()

    file = ida_kernwin.ask_file(0, "x64dbg database|{}".format(get_file_mask()), "Import database")
    if not file:
        return
    print("Importing database {}".format(file))

    with open(file) as dbdata:
        db = json.load(dbdata)

    count = 0
    labels = db.get("labels", [])
    for label in labels:
        try:
            if label["module"] != module:
                continue
            ea = int(label["address"], 16) + base
            name = label["text"]
            ida_name.set_name(ea, str(name), 0)
            count += 1
        except:
            pass
    print("{:d}/{:d} label(s) imported".format(count, len(labels)))

    count = 0
    comments = db.get("comments", [])
    for comment in comments:
        try:
            if comment["module"] != module:
                continue
            ea = int(comment["address"], 16) + base
            name = comment["text"]
            ida_bytes.set_cmt(ea, str(name), 1)
            count += 1
        except:
            pass
    print("{:d}/{:d} comment(s) imported".format(count, len(comments)))

    count = 0
    breakpoints = db.get("breakpoints", [])
    for breakpoint in breakpoints:
        try:
            if breakpoint["module"] != module:
                continue
            ea = int(breakpoint["address"], 16) + base
            bptype = breakpoint["type"]
            if bptype == BPNORMAL:
                count += 1
                ida_dbg.add_bpt(ea, 1, BPT_DEFAULT)
            elif bptype == BPHARDWARE:
                titantype = int(breakpoint["titantype"], 16)
                hwtype = (titantype >> 4) & 0xF
                if hwtype == UE_HARDWARE_EXECUTE:
                    hwtype = BPT_EXEC
                elif hwtype == UE_HARDWARE_WRITE:
                    hwtype = BPT_WRITE
                elif hwtype == UE_HARDWARE_READWRITE:
                    hwtype = BPT_RDWR
                else:
                    continue
                hwsize = titantype & 0xF
                if hwsize == UE_HARDWARE_SIZE_1:
                    hwsize = 1
                elif hwsize == UE_HARDWARE_SIZE_2:
                    hwsize = 2
                elif hwsize == UE_HARDWARE_SIZE_4:
                    hwsize = 4
                elif hwsize == UE_HARDWARE_SIZE_8:
                    hwsize = 8
                else:
                    continue
                count += 1
                ida_dbg.add_bpt(ea, hwsize, hwtype)
        except:
            pass
    print("{:d}/{:d} breakpoint(s) imported".format(count, len(breakpoints)))

    print("Done!")


def do_export(re_export=False):
    global LAST_EXPORT_FILE_NAME
    db = {}
    module = idaapi.get_root_filename().lower()
    base = idaapi.get_imagebase()

    if re_export and LAST_EXPORT_FILE_NAME is not None:
        file = LAST_EXPORT_FILE_NAME
    else:
        file = ida_kernwin.ask_file(1, "x64dbg database|{}".format(get_file_mask()), "Export database")
    if not file:
        return
    print("Exporting database {}".format(file))
    LAST_EXPORT_FILE_NAME = file

    db["labels"] = [{
        "text": name,
        "manual": False,
        "module": module,
        "address": "{:#x}".format(ea - base)
    } for (ea, name) in idautils.Names()]
    print("{:d} label(s) exported".format(len(db["labels"])))

    db["comments"] = [{
        "text": comment.replace("{", "{{").replace("}", "}}"),
        "manual": False,
        "module": module,
        "address": "{:#x}".format((ea - base))
    } for (ea, comment) in Comments()]
    print("{:d} comment(s) exported".format(len(db["comments"])))

    db["breakpoints"] = [{
        "address": "{:#x}".format(ea - base),
        "enabled": True,
        "type": bptype,
        "titantype": "{:#x}".format(titantype),
        "oldbytes": "{:#x}".format(oldbytes),
        "module": module,
    } for (ea, bptype, titantype, oldbytes) in Breakpoints()]
    print("{:d} breakpoint(s) exported".format(len(db["breakpoints"])))

    with open(file, "w") as outfile:
        json.dump(db, outfile, indent=1)
    print("Done!")


try:  # we try because of ida versions below 6.8, and write action handlers below
    class AboutHandler(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        def activate(self, ctx):
            a = x64dbg_plugin_t()
            a.about()
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS
except AttributeError:
    pass

try:
    class EksportHandler(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        def activate(self, ctx):
            b = x64dbg_plugin_t()
            b.exportdb(False)
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

except AttributeError:
    pass


class ReeksportHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        b = x64dbg_plugin_t()
        b.exportdb(True)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


try:
    class ImportHandler(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        # Say hello when invoked.
        def activate(self, ctx):
            c = x64dbg_plugin_t()
            c.importdb()
            return 1

        # This action is always available.
        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS
except AttributeError:
    pass


class x64dbg_plugin_t(idaapi.plugin_t):
    comment = "Official x64dbg plugin for IDA Pro"
    version = "v2.0"
    website = "https://github.com/x64dbg/x64dbgida"
    help = ""
    wanted_name = "x64dbgida"
    wanted_hotkey = ""
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        global initialized

        if initialized is False:
            initialized = True
            self._initialize()

        return idaapi.PLUGIN_KEEP

    def _initialize(self):
        if idaapi.IDA_SDK_VERSION < 700:
            print("Use version 1.0")
            return

        menu_path = 'Edit/x64dbgida/'

        # populating action menus
        action = 'my:aboutaction'
        action_desc = idaapi.action_desc_t(
            action,  # The action name. This acts like an ID and must be unique
            'About!',  # The action text.
            AboutHandler(),  # The action handler.
            '',  # Optional: the action shortcut
            'About X64dbg ida',  # Optional: the action tooltip (available in menus/toolbar)
        )  # Optional: the action icon (shows when in menus/toolbars) use numbers 1-255
        idaapi.register_action(action_desc)
        idaapi.attach_action_to_menu(menu_path, action, idaapi.SETMENU_APP)

        label = 'Export x64dbg database'
        action = 'my:eksportaction'
        action_desc = idaapi.action_desc_t(action, label, EksportHandler(), '', label)
        idaapi.register_action(action_desc)
        idaapi.attach_action_to_menu(menu_path, action, idaapi.SETMENU_APP)

        label = 'Re-Export database'
        action = 'my:reeksportaction'
        action_desc = idaapi.action_desc_t(action, label, ReeksportHandler(), 'Ctrl+Alt+Shift+q', label)
        idaapi.register_action(action_desc)
        idaapi.attach_action_to_menu(menu_path, action, idaapi.SETMENU_APP)

        label = 'Import (uncompressed) database'
        action = 'my:importaction'
        action_desc = idaapi.action_desc_t(action, label, ImportHandler(), '', label)
        idaapi.register_action(action_desc)
        idaapi.attach_action_to_menu(menu_path, action, idaapi.SETMENU_APP)

    def run(self, arg):
        self.about()
        pass

    def term(self):
        return

    def importdb(self):
        try:
            do_import()
        except:
            traceback.print_exc()
            print("Error importing database...")

    def exportdb(self, re_export):
        try:
            do_export(re_export)
        except:
            traceback.print_exc()
            print("Error exporting database...")

    def about(self):
        print("{} {}".format(self.wanted_name, self.version))
        print(self.comment)
        print(self.website)


def PLUGIN_ENTRY():
    return x64dbg_plugin_t()
