import os
import struct
import sys

CODED = {
    "ResolutionScope": (2, [0, 26, 35, 1]),
    "TypeDefOrRef": (2, [2, 1, 27]),
    "MemberRefParent": (3, [2, 1, 26, 6, 27]),
    "HasConstant": (2, [4, 8, 23]),
    "HasCustomAttribute": (5, [6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43]),
    "HasFieldMarshal": (1, [4, 8]),
    "HasDeclSecurity": (2, [2, 6, 32]),
    "MemberForwarded": (1, [4, 6]),
    "HasSemantics": (1, [20, 23]),
    "MethodDefOrRef": (1, [6, 10]),
    "TypeOrMethodDef": (1, [2, 6]),
    "CustomAttributeType": (3, [6, 10]),
    "Implementation": (2, [38, 35, 39]),
}

SCHEMA = {
    0: [("u16", 0), ("str", 0), ("guid", 0), ("guid", 0), ("guid", 0)],
    1: [("coded", "ResolutionScope"), ("str", 0), ("str", 0)],
    2: [("u32", 0), ("str", 0), ("str", 0), ("coded", "TypeDefOrRef"), ("idx", 4), ("idx", 6)],
    3: [("idx", 4)],
    4: [("u16", 0), ("str", 0), ("blob", 0)],
    5: [("idx", 6)],
    6: [("u32", 0), ("u16", 0), ("u16", 0), ("str", 0), ("blob", 0), ("idx", 8)],
    7: [("idx", 8)],
    8: [("u16", 0), ("u16", 0), ("str", 0)],
    9: [("idx", 2), ("coded", "TypeDefOrRef")],
    10: [("coded", "MemberRefParent"), ("str", 0), ("blob", 0)],
    11: [("u8", 0), ("u8", 0), ("coded", "HasConstant"), ("blob", 0)],
    12: [("coded", "HasCustomAttribute"), ("coded", "CustomAttributeType"), ("blob", 0)],
    13: [("coded", "HasFieldMarshal"), ("blob", 0)],
    14: [("u16", 0), ("coded", "HasDeclSecurity"), ("blob", 0)],
    15: [("u16", 0), ("u32", 0), ("idx", 2)],
    16: [("u32", 0), ("idx", 4)],
    17: [("blob", 0)],
    18: [("idx", 2), ("idx", 20)],
    19: [("idx", 20)],
    20: [("u16", 0), ("str", 0), ("coded", "TypeDefOrRef")],
    21: [("idx", 2), ("idx", 23)],
    22: [("idx", 23)],
    23: [("u16", 0), ("str", 0), ("blob", 0)],
    24: [("u16", 0), ("idx", 6), ("coded", "HasSemantics")],
    25: [("idx", 2), ("coded", "MethodDefOrRef"), ("coded", "MethodDefOrRef")],
    26: [("str", 0)],
    27: [("blob", 0)],
    28: [("u16", 0), ("coded", "MemberForwarded"), ("str", 0), ("idx", 26)],
    29: [("u32", 0), ("idx", 4)],
    30: [("u32", 0), ("u32", 0)],
    31: [("u32", 0)],
    32: [("u32", 0), ("u16", 0), ("u16", 0), ("u16", 0), ("u16", 0), ("u32", 0), ("blob", 0), ("str", 0), ("str", 0)],
    33: [("u32", 0)],
    34: [("u32", 0), ("u32", 0), ("u32", 0)],
    35: [("u16", 0), ("u16", 0), ("u16", 0), ("u16", 0), ("u32", 0), ("blob", 0), ("str", 0), ("str", 0), ("blob", 0)],
    36: [("u32", 0), ("idx", 35)],
    37: [("u32", 0), ("u32", 0), ("u32", 0), ("idx", 35)],
    38: [("u32", 0), ("str", 0), ("blob", 0)],
    39: [("u32", 0), ("u32", 0), ("str", 0), ("str", 0), ("coded", "Implementation")],
    40: [("u32", 0), ("u32", 0), ("str", 0), ("coded", "Implementation")],
    41: [("idx", 2), ("idx", 2)],
    42: [("u16", 0), ("u16", 0), ("coded", "TypeOrMethodDef"), ("str", 0)],
    43: [("coded", "MethodDefOrRef"), ("blob", 0)],
    44: [("idx", 42), ("coded", "TypeDefOrRef")],
}

def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]

def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]

def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]

def align4(n):
    return (n + 3) & ~3

class VersionError(Exception):
    pass

class PE:
    def __init__(self, data):
        self.data = data
        self.nt = u32(data, 0x3C)
        if data[self.nt:self.nt + 4] != b"PE\0\0":
            raise ValueError("not a PE file")
        coff = self.nt + 4
        self.nsec = u16(data, coff + 2)
        opt_size = u16(data, coff + 16)
        opt = coff + 20
        self.magic = u16(data, opt)
        dd = opt + (96 if self.magic == 0x10B else 112)
        self.clr_rva = u32(data, dd + 14 * 8)
        self.clr_size = u32(data, dd + 14 * 8 + 4)
        self.sections = []
        sec = opt + opt_size
        for _ in range(self.nsec):
            vsize = u32(data, sec + 8)
            va = u32(data, sec + 12)
            rawsize = u32(data, sec + 16)
            rawptr = u32(data, sec + 20)
            self.sections.append((va, max(vsize, rawsize), rawptr, rawsize))
            sec += 40

    def off(self, rva):
        for va, size, rawptr, rawsize in self.sections:
            if va <= rva < va + size:
                delta = rva - va
                if delta >= rawsize:
                    raise ValueError("RVA points outside file data")
                return rawptr + delta
        raise ValueError(f"unmapped RVA 0x{rva:X}")

class Metadata:
    def __init__(self, data, pe):
        self.data = data
        self.pe = pe
        if not pe.clr_rva:
            raise ValueError("not a .NET assembly")
        clr = pe.off(pe.clr_rva)
        md_rva = u32(data, clr + 8)
        md_off = pe.off(md_rva)
        if u32(data, md_off) != 0x424A5342:
            raise ValueError("bad metadata signature")
        ver_len = u32(data, md_off + 12)
        p = align4(md_off + 16 + ver_len)
        nstreams = u16(data, p + 2)
        p += 4
        self.streams = {}
        for _ in range(nstreams):
            off = u32(data, p)
            size = u32(data, p + 4)
            end = data.index(0, p + 8)
            name = data[p + 8:end].decode("ascii")
            self.streams[name] = (md_off + off, size)
            p = align4(end + 1)
        self.strings = self.streams.get("#Strings")
        self.us = self.streams.get("#US")
        self.blob = self.streams.get("#Blob")
        t = self.streams.get("#~") or self.streams.get("#-")
        if not t:
            raise ValueError("no metadata tables")
        toff = t[0]
        self.heap_sizes = data[toff + 6]
        valid = u64(data, toff + 8)
        p = toff + 24
        self.rows = {}
        for i in range(64):
            if (valid >> i) & 1:
                self.rows[i] = u32(data, p)
                p += 4
        self.row_size = {}
        self.table_off = {}
        for i in range(64):
            if i not in self.rows:
                continue
            if i not in SCHEMA:
                raise ValueError(f"unsupported metadata table {i}")
            self.row_size[i] = self._size(SCHEMA[i])
            self.table_off[i] = p
            p += self.row_size[i] * self.rows[i]

    def _size(self, cols):
        total = 0
        for kind, arg in cols:
            if kind == "u8":
                total += 1
            elif kind == "u16":
                total += 2
            elif kind == "u32":
                total += 4
            elif kind == "str":
                total += 4 if self.heap_sizes & 1 else 2
            elif kind == "guid":
                total += 4 if self.heap_sizes & 2 else 2
            elif kind == "blob":
                total += 4 if self.heap_sizes & 4 else 2
            elif kind == "idx":
                total += 4 if self.rows.get(arg, 0) >= 0x10000 else 2
            elif kind == "coded":
                bits, tables = CODED[arg]
                total += 4 if max(self.rows.get(t, 0) for t in tables) >= (1 << (16 - bits)) else 2
        return total

    def _read_index(self, kind):
        size = 4 if self.heap_sizes & {"str": 1, "guid": 2, "blob": 4}[kind] else 2
        return size

    def row(self, table, rid):
        if rid < 1 or rid > self.rows.get(table, 0):
            raise IndexError(f"table {table} row {rid}")
        cols = SCHEMA[table]
        p = self.table_off[table] + (rid - 1) * self.row_size[table]
        out = []
        for kind, arg in cols:
            if kind == "u8":
                out.append(self.data[p]); p += 1
            elif kind == "u16":
                out.append(u16(self.data, p)); p += 2
            elif kind == "u32":
                out.append(u32(self.data, p)); p += 4
            elif kind == "str":
                n = self._read_index("str")
                idx = u32(self.data, p) if n == 4 else u16(self.data, p)
                out.append(self.str_at(idx)); p += n
            elif kind == "guid":
                n = self._read_index("guid")
                out.append(self.data[p:p + n]); p += n
            elif kind == "blob":
                n = self._read_index("blob")
                idx = u32(self.data, p) if n == 4 else u16(self.data, p)
                out.append(self.blob_at(idx)); p += n
            elif kind == "idx":
                n = 4 if self.rows.get(arg, 0) >= 0x10000 else 2
                out.append(u32(self.data, p) if n == 4 else u16(self.data, p)); p += n
            elif kind == "coded":
                bits, tables = CODED[arg]
                n = 4 if max(self.rows.get(t, 0) for t in tables) >= (1 << (16 - bits)) else 2
                out.append(u32(self.data, p) if n == 4 else u16(self.data, p)); p += n
        return out

    def str_at(self, idx):
        if not idx:
            return ""
        start = self.strings[0] + idx
        end = self.data.index(0, start)
        return self.data[start:end].decode("utf-8", "replace")

    def blob_at(self, idx):
        if not idx:
            return b""
        start = self.blob[0] + idx
        length, p = self.compressed(start)
        return self.data[p:p + length]

    def us_at(self, idx):
        if not idx:
            return ""
        start = self.us[0] + idx
        length, p = self.compressed(start)
        raw = self.data[p:p + length]
        if length % 2:
            raw = raw[:-1]
        return raw.decode("utf-16-le", "replace")

    def compressed(self, off):
        b = self.data[off]
        if b & 0x80 == 0:
            return b, off + 1
        if b & 0xC0 == 0x80:
            return ((b & 0x3F) << 8) | self.data[off + 1], off + 2
        if b & 0xE0 == 0xC0:
            return ((b & 0x1F) << 24) | (self.data[off + 1] << 16) | (self.data[off + 2] << 8) | self.data[off + 3], off + 4
        raise ValueError("bad compressed integer")

    def type_name(self, rid):
        _, name, ns = self.row(2, rid)[:3]
        return f"{ns}.{name}" if ns else name

    def type_methods(self, rid):
        start = self.row(2, rid)[5]
        end = self.rows[6] + 1
        if rid < self.rows[2]:
            end = self.row(2, rid + 1)[5]
        return range(start, end)

    def type_fields(self, rid):
        start = self.row(2, rid)[4]
        end = self.rows[4] + 1
        if rid < self.rows[2]:
            end = self.row(2, rid + 1)[4]
        return range(start, end)

    def find_type(self, full):
        for rid in range(1, self.rows[2] + 1):
            if self.type_name(rid) == full:
                return rid
        return None

    def find_method(self, type_rid, name):
        for rid in self.type_methods(type_rid):
            if self.row(6, rid)[3] == name:
                return rid
        return None

    def assembly_version(self):
        if not self.rows.get(32):
            return None
        r = self.row(32, 1)
        return f"{r[1]}.{r[2]}.{r[3]}.{r[4]}"

    def int_const(self, type_name, field_name):
        t = self.find_type(type_name)
        if not t:
            return None
        for f in self.type_fields(t):
            if self.row(4, f)[1] != field_name:
                continue
            for c in range(1, self.rows[11] + 1):
                typ, _, parent, value = self.row(11, c)
                if typ == 8 and parent & 3 == 0 and parent >> 2 == f:
                    return int.from_bytes(value, "little", signed=True)
        return None

    def body(self, method_rid):
        rva = self.row(6, method_rid)[0]
        if not rva:
            return None, None
        off = self.pe.off(rva)
        head = self.data[off]
        if head & 3 == 2:
            size = head >> 2
            code = off + 1
        elif head & 3 == 3:
            size = u32(self.data, off + 4)
            code = off + 12
        else:
            raise ValueError(f"bad method header at 0x{off:X}")
        return self.data[code:code + size], code

    def method_token(self, rid):
        return 0x06000000 | rid

    def field_token(self, rid):
        return 0x04000000 | rid

def parse_args(argv):
    if not argv:
        raise SystemExit("usage: Patch-PCL-McDownload.py <PCL.exe> [-o OUT]")
    src = argv[0]
    out = None
    if "-o" in argv:
        out = argv[argv.index("-o") + 1]
    if not out:
        root, ext = os.path.splitext(src)
        out = root + "-patched" + ext
    return src, out

def patch(data):
    pe = PE(data)
    md = Metadata(data, pe)
    version = md.assembly_version()
    code = md.int_const("PCL.ModBase", "VersionCode")
    if version != "2.99.0.0" or code not in (413, 414):
        raise VersionError(
            f"unsupported PCL version {version} (VersionCode {code}); only 2.99.0.0 (413/414) is supported"
        )
    if not md.find_type("PCL.PageDownloadInstall"):
        raise VersionError("not a PCL 2 assembly with the download page")
    out = bytearray(data)
    applied = []

    t = md.find_type("PCL.PageDownloadInstall")
    m = md.find_method(t, "LoaderInit")
    if m:
        code, code_off = md.body(m)
        pos = None
        for i in range(len(code) - 4):
            if code[i] == 0x72 and code[i + 4] == 0x70:
                if "关闭下载" in md.us_at(u32(code, i + 1) & 0xFFFFFF):
                    pos = i
                    break
        if pos is not None:
            end = code.find(b"\x02\xfe\x06", pos + 5, pos + 160)
            if end < 0 or end + 7 >= len(code) or code[end + 7] != 0x73:
                raise SystemExit("loader pattern not recognized")
            field_rid = None
            dt = md.find_type("PCL.ModDownload")
            if dt:
                for f in md.type_fields(dt):
                    if md.row(4, f)[1] == "DlClientListLoader":
                        field_rid = f
                        break
            if not field_rid:
                for tid in range(1, md.rows[2] + 1):
                    for f in md.type_fields(tid):
                        if md.row(4, f)[1] == "DlClientListLoader":
                            field_rid = f
                            break
                    if field_rid:
                        break
            if not field_rid:
                raise SystemExit("DlClientListLoader field not found")
            tok = md.field_token(field_rid)
            out[code_off + pos:code_off + pos + 5] = b"\x7e" + struct.pack("<I", tok)
            out[code_off + pos + 5:code_off + end] = b"\x00" * (end - pos - 5)
            applied.append("loader")

    t = md.find_type("PCL.PageDownloadModify")
    if t:
        stoks = [0x0A000000 | mr for mr in range(1, md.rows[10] + 1) if md.row(10, mr)[1] == "set_Visibility"]
        getters = [rid for rid in range(1, md.rows[6] + 1) if md.row(6, rid)[3] == "get_CardMinecraft"]
        for m in md.type_methods(t):
            code, code_off = md.body(m)
            if not code:
                continue
            for gtok in (md.method_token(g) for g in getters):
                for stok in stoks:
                    needle = b"\x6f" + struct.pack("<I", gtok) + b"\x18\x6f" + struct.pack("<I", stok)
                    hit = code.find(needle)
                    if hit >= 0:
                        out[code_off + hit + 5] = 0x16
                        applied.append("visibility")
                        break
                if "visibility" in applied:
                    break
            if "visibility" in applied:
                break

    field_rid = None
    for f in range(1, md.rows[4] + 1):
        if md.row(4, f)[1] == "RestrictMcDownload":
            field_rid = f
            break
    if field_rid:
        const_rid = None
        old = None
        for c in range(1, md.rows[11] + 1):
            typ, _, parent, value = md.row(11, c)
            if parent & 3 == 0 and parent >> 2 == field_rid:
                const_rid = c
                if value == b"\x00":
                    const_rid = None
                break
        if const_rid:
            false_rid = None
            for c in range(1, md.rows[11] + 1):
                typ, _, _, value = md.row(11, c)
                if typ == 2 and value == b"\x00":
                    false_rid = c
                    break
            if false_rid:
                bits, tables = CODED["HasConstant"]
                coded_size = 4 if max(md.rows.get(t, 0) for t in tables) >= (1 << (16 - bits)) else 2
                size = 4 if md.heap_sizes & 4 else 2
                fmt = "<I" if size == 4 else "<H"
                false_off = md.table_off[11] + (false_rid - 1) * md.row_size[11] + 2 + coded_size
                false_blob = struct.unpack_from(fmt, data, false_off)[0]
                value_off = md.table_off[11] + (const_rid - 1) * md.row_size[11] + 2 + coded_size
                struct.pack_into(fmt, out, value_off, false_blob)
                applied.append("constant")

    return bytes(out), applied

def main():
    src, out = parse_args(sys.argv[1:])
    try:
        with open(src, "rb") as f:
            data = f.read()
    except OSError as e:
        print(f"cannot read {src}: {e}")
        return 1
    try:
        patched, applied = patch(data)
    except VersionError as e:
        print(f"cannot patch {src}: {e}")
        return 1
    except (ValueError, IndexError, KeyError) as e:
        print(f"cannot patch {src}: {e}")
        return 1
    if not applied:
        print("Nothing to patch; this build is already unrestricted or the pattern changed.")
        return 0
    missing = {"loader", "visibility", "constant"} - set(applied)
    if missing:
        print(f"unsupported build: missing {', '.join(sorted(missing))}; refusing to write")
        return 1
    try:
        with open(out, "wb") as f:
            f.write(patched)
    except OSError as e:
        print(f"cannot write {out}: {e}")
        print("Close PCL and try again.")
        return 1
    print(f"patched: {', '.join(applied)}")
    print(f"output: {out}")
    print("WARNING: modpack import is NOT restored by this patch")
    return 0

if __name__ == "__main__":
    sys.exit(main())
