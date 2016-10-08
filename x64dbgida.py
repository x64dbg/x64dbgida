import idaapi, idautils, json

initialized = False


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
        if (cmt):
            skip = ea == lastea + 1 and cmt == lastcmt
            lastea = ea
            lastcmt = cmt
            if not skip:
                yield (ea, cmt)


def get_file_mask():
    mask = "*.dd32"
    if idaapi.get_inf_structure().is_64bit():
        mask = "*.dd64"
    return mask


def do_import():
    db = {}
    module = idaapi.get_root_filename()
    base = idaapi.get_imagebase()

    file = AskFile(0, "x64dbg database|%s" % get_file_mask(),
                   "Import database")
    if not file:
        return
    print "Importing database %s" % file

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
            MakeNameEx(ea, str(name), 0)
            count += 1
        except:
            pass
    print "%d/%d labels imported" % (count, len(labels))

    count = 0
    comments = db.get("comments", [])
    for comment in comments:
        try:
            if comment["module"] != module:
                continue
            ea = int(comment["address"], 16) + base
            name = comment["text"]
            MakeRptCmt(ea, str(name))
            count += 1
        except:
            pass
    print "%d/%d comments imported" % (count, len(comments))
    print "Done!"

    count = 0
    breakpoints = db.get("breakpoints")

    for breakpoint in breakpoints:
        types = int(breakpoint["type"])
        print types
        if types == 0:
            cond = BPT_DEFAULT
            ea = int(breakpoint["address"], 16) + base
            AddBptEx(ea, 0x1, cond)
            count += 1
        elif types == 1:
            cond = BPT_BRK
            ea = int(breakpoint["address"], 16) + base
            AddBptEx(ea, 0x1, cond)
            count += 1
        elif types == 2:
            cond = BPT_MSGS
            ea = int(breakpoint["address"], 16) + base
            AddBptEx(ea, 0x1, cond)
            count += 1
        else:
            pass

    print "%d/%d Breakpoints imported" % (count, len(breakpoints))





def do_export():
    db = {}
    module = idaapi.get_root_filename()
    base = idaapi.get_imagebase()

    file = AskFile(1, "x64dbg database|%s" % get_file_mask(),
                   "Export database")
    if not file:
        return
    print "Exporting database %s" % file

    db["labels"] = [{
        "text": name,
        "manual": False,
        "module": module,
        "address": "0x%X" % (ea - base)
    } for (ea, name) in Names()]

    db["breakpoints"] = [{
        "text": name,
        "manual": False,
        "module": module,
        "address": "0x%X" % (ea - base)
    } for (ea, name) in Names()]

    db["comments"] = [{
        "text": comment.replace("{", "{{").replace("}", "}}"),
        "manual": False,
        "module": module,
        "address": "0x%X" % (ea - base)
    } for (ea, comment) in Comments()]

    with open(file, "w") as outfile:
        json.dump(db, outfile, indent=1)
    print "Done!"


class x64dbg_plugin_t(idaapi.plugin_t):
    comment = "Official x64dbg plugin for IDA Pro"
    version = "v1.0"
    website = "https://github.com/x64dbg/x64dbgida"
    help = ""
    wanted_name = "x64dbgida"
    wanted_hotkey = ""
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        global initialized

        if initialized == False:
            initialized = True
            idaapi.add_menu_item("Edit/x64dbgida/", "About", "", 0, self.about,
                                 None)
            idaapi.add_menu_item("Edit/x64dbgida/", "Export database", "", 0,
                                 self.exportdb, None)
            idaapi.add_menu_item("Edit/x64dbgida/",
                                 "Import (uncompressed) database", "", 0,
                                 self.importdb, None)


        return idaapi.PLUGIN_OK

    def run(self, arg):
        self.about()

    def term(self):
        return

    def importdb(self):
        try:
            do_import()
        except:
            print "Error importing database..."

    def exportdb(self):
        try:
            do_export()
        except:
            print "Error exporting database..."

    def about(self):
        print self.wanted_name + " " + self.version
        print self.comment
        print self.website


def PLUGIN_ENTRY():
    return x64dbg_plugin_t()
