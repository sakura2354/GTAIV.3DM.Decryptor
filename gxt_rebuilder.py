#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
------------------------------------------------------------------------------
用法

    python gxt_rebuilder.py verify  american.gxt                  # 校验GXT
    python gxt_rebuilder.py decode  american.gxt -o out.txt       # 导出可读文本
    python gxt_rebuilder.py convert american.gxt -o chinese.gxt        # 内联中文
    python gxt_rebuilder.py convert american.gxt -o chinese.gxt --font <path_to_font.dat>
"""
from __future__ import annotations

import argparse
import json
import os
import re
import struct
import sys

CLUSTER = re.compile(rb"\(-([0-9A-Fa-f]{4})(?:[ (]*\))?[ (]*")
HEX4 = re.compile(rb"\(([0-9A-Fa-f]{4})\)")


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _unesc(s: str) -> str:
    out, i = [], 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            n = s[i + 1]
            out.append({"r": "\r", "n": "\n", "t": "\t", "\\": "\\"}.get(n, n))
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def _from_txt(path):
    d = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            if "\t" not in line:
                raise ValueError(f"txt 第 {line[:20]!r} 行缺少制表符")
            k, v = line.rstrip("\n").split("\t", 1)
            d[int(k, 16)] = _unesc(v)
    return [d.get(i, "") for i in range(max(d) + 1)] if d else []


def _from_json(path):
    obj = json.load(open(path, encoding="utf-8"))
    mx = max(int(k, 16) for k in obj)
    return [obj.get("%04X" % i, obj.get("%04x" % i, "")) for i in range(mx + 1)]


def _from_bin(path):
    plain = open(path, "rb").read()
    if len(plain) < 4:
        raise ValueError("明文 bin 过短")
    count = int.from_bytes(plain[:4], "little")
    if count == 0 or count > 0x100000:
        raise ValueError(f"明文 bin count={count} 不合理"
                         f"（是不是直接传了加密的 font.dat？先用工具一解密）")
    pos, out = 4, []
    for _ in range(count):
        if pos + 2 > len(plain):
            raise ValueError("明文 bin 长度字段越界")
        blen = int.from_bytes(plain[pos:pos + 2], "little")
        pos += 2
        if blen & 1 or pos + blen > len(plain):
            raise ValueError("明文 bin 条目越界")
        out.append("".join(chr(c) for c in
                           (int.from_bytes(plain[pos + k:pos + k + 2], "little")
                            for k in range(0, blen, 2))))
        pos += blen
    return out


def load_font(path):
    """读取工具一已解密的文本表，返回 list[str]，下标即 (-NNNN) 索引。

    只接受解密后的产物（.txt / .json / .bin），不处理原始 font.dat。
    """
    ext = os.path.splitext(path)[1].lower()
    if ext == ".txt":
        entries = _from_txt(path)
    elif ext == ".json":
        entries = _from_json(path)
    elif ext == ".bin":
        entries = _from_bin(path)
    else:
        raise ValueError(
            f"不支持的文本表格式：{ext or '(无扩展名)'}\n"
            "本工具只读工具一解密后的产物，请先执行：\n"
            "    python fontdat_edit.py decode font.dat -o font_out/\n"
            "然后 --font font_out/font_dec.txt（或 .json / .bin）")
    if not entries:
        raise ValueError(f"{path} 中没有任何条目")
    return entries


# ── GXT 解析 ────────────────────────────────────────────────────────────────
def parse(data: bytes) -> dict:
    if data[4:8] != b"TABL":
        raise ValueError("不是 GXT：缺少 TABL")
    tabl_size = u32(data, 8)
    first_chunk = u32(data, 12 + 8)
    n_entries = (first_chunk - 12) // 12
    entries, p = [], 12
    for _ in range(n_entries):
        entries.append((data[p:p + 8].decode("ascii", "replace").rstrip("\x00"),
                        u32(data, p + 8)))
        p += 12
    tables = []
    for i, (name, off) in enumerate(entries):
        pre = b""
        if data[off:off + 4] != b"TKEY":
            pre = data[off:off + 8]
            off += 8
        if data[off:off + 4] != b"TKEY":
            raise ValueError(f"{name}: 在 {off:#x} 找不到 TKEY")
        n = u32(data, off + 4) // 8
        ents = [(u32(data, off + 8 + k * 8), u32(data, off + 12 + k * 8))
                for k in range(n)]
        tdat = off + 8 + n * 8
        if data[tdat:tdat + 4] != b"TDAT":
            raise ValueError(f"{name}: 在 {tdat:#x} 找不到 TDAT")
        psize = u32(data, tdat + 4)
        pool_start = tdat + 8
        nxt = entries[i + 1][1] if i + 1 < len(entries) else len(data)
        tables.append(dict(name=name, pre=pre, ents=ents, psize=psize,
                           pool_start=pool_start,
                           pool=data[pool_start:pool_start + psize],
                           tail=data[pool_start + psize:nxt]))
    return dict(tabl_size=tabl_size, entries=entries, tables=tables)


def rebuild(g: dict) -> bytes:
    entries, tables = g["entries"], g["tables"]
    body, offs = bytearray(), []
    base = 12 + len(entries) * 12
    pos = base
    for t in tables:
        offs.append(pos)
        body += t["pre"] + b"TKEY" + struct.pack("<I", len(t["ents"]) * 8)
        for o, h in t["ents"]:
            body += struct.pack("<II", o, h)
        body += b"TDAT" + struct.pack("<I", len(t["pool"])) + t["pool"] + t["tail"]
        pos = base + len(body)
    out = bytearray(struct.pack("<HH", 4, 8) + b"TABL"
                    + struct.pack("<I", g["tabl_size"]))
    for (name, _), o in zip(entries, offs):
        out += name.encode("ascii")[:8].ljust(8, b"\x00") + struct.pack("<I", o)
    out += body
    return bytes(out)


def strings(t: dict, data: bytes):
    for o, h in t["ents"]:
        s = data[t["pool_start"] + o:]
        e = s.find(b"\x00")
        yield o, h, s[:e if e >= 0 else 0]


def survey(g: dict, data: bytes) -> dict:
    cl = hx = 0
    for t in g["tables"]:
        for _, _, s in strings(t, data):
            cl += len(CLUSTER.findall(s))
            hx += len(HEX4.findall(s))
    return dict(tables=len(g["tables"]),
                entries=sum(len(t["ents"]) for t in g["tables"]),
                cluster=cl, codepoint=hx,
                tail=sum(len(t["tail"]) for t in g["tables"]))


# ── 转换 ────────────────────────────────────────────────────────────────────
def convert(g: dict, font) -> tuple:
    subs = hx_subs = 0
    for t in g["tables"]:
        uniq = sorted({o for o, _ in t["ents"]})
        pool, remap = bytearray(), {}
        for o in uniq:
            e = t["pool"].find(b"\x00", o)
            raw = t["pool"][o:e if e >= 0 else len(t["pool"])]
            # CODEC SAFETY：只有确实含标记的串才重新编码，其余保留原字节，
            # 避免破坏 SIXAXIS\\x99 这类非 UTF-8 内容。
            if not (CLUSTER.search(raw) or HEX4.search(raw)):
                blob = raw
            else:
                pieces, pos = [], 0
                for mo in CLUSTER.finditer(raw):
                    pieces.append(raw[pos:mo.start()])
                    idx = int(mo.group(1), 16)
                    pieces.append(font[idx].encode("utf-8")
                                  if idx < len(font) else mo.group(0))
                    pos = mo.end()
                    subs += 1
                pieces.append(raw[pos:])
                blob = b"".join(pieces)

                def _hex(m):
                    nonlocal hx_subs
                    hx_subs += 1
                    return chr(int(m.group(1), 16)).encode("utf-8")

                blob = HEX4.sub(_hex, blob)
            remap[o] = len(pool)
            pool += blob + b"\x00"
        t["ents"] = [(remap[o], h) for o, h in t["ents"]]
        t["pool"] = bytes(pool)
        t["tail"] = b""                  # 旧填充来自旧池布局，已无意义
    return g, subs, hx_subs


def dump_text(g: dict, data: bytes, path: str) -> int:
    n = 0
    if os.path.dirname(os.path.abspath(path)):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("# %d tables, %d entries\n"
                % (len(g["tables"]), sum(len(t["ents"]) for t in g["tables"])))
        for t in g["tables"]:
            f.write("[%s]\n" % t["name"])
            for _, h, s in strings(t, data):
                f.write("%08X=%s\n" % (h, s.decode("utf-8", "replace")))
                n += 1
    return n


# ── CLI ─────────────────────────────────────────────────────────────────────
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="GXT 解析 / 重组工具")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, hlp in (("verify", "回环校验（必须与原文逐字节一致）+ 统计"),
                      ("decode", "导出可读文本"),
                      ("convert", "把两类中文标记内联为真中文")):
        p = sub.add_parser(name, help=hlp)
        p.add_argument("input")
        p.add_argument("-o", "--output")
        if name == "convert":
            p.add_argument("--font", default="font.dat", help="font.dat 路径")
    a = ap.parse_args(argv)

    data = open(a.input, "rb").read()
    g = parse(data)
    st = survey(g, data)
    print(f"输入        : {a.input} ({len(data)} 字节)")
    print(f"表 / 条目   : {st['tables']} / {st['entries']}")
    print(f"(-NNNN 簇   : {st['cluster']} 处")
    print(f"(XXXX) 码点 : {st['codepoint']} 处")
    print(f"表间填充    : {st['tail']} 字节")

    if a.cmd == "verify":
        rt = rebuild(g)
        ok = rt == data
        print()
        print("回环重建逐字节一致:", "是" if ok else f"否（{len(rt)} vs {len(data)}）")
        return 0 if ok else 1

    if a.cmd == "decode":
        out = a.output or "gxt_dump.txt"
        n = dump_text(g, data, out)
        print(f"\n写出        : {out} ({n} 条)")
        return 0

    try:
        font = load_font(a.font)
    except ValueError as e:
        print(f"\n无法读取文本表：{e}", file=sys.stderr)
        return 2
    g2, subs, hx = convert(g, font)
    out = a.output or "converted.gxt"
    blob = rebuild(g2)
    if os.path.dirname(os.path.abspath(out)):
        os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "wb") as f:
        f.write(blob)
    print(f"\nfont.dat    : {a.font} ({len(font)} 条)")
    print(f"簇已替换    : {subs} 处")
    print(f"码点已替换  : {hx} 处")
    print(f"写出        : {out} ({len(blob)} 字节, {len(blob)-len(data):+})")

    d2 = open(out, "rb").read()
    rest = survey(parse(d2), d2)
    ok = (rest["tables"] == st["tables"] and rest["entries"] == st["entries"]
          and rest["cluster"] == 0 and rest["codepoint"] == 0)
    print(f"残留标记    : 簇 {rest['cluster']} / 码点 {rest['codepoint']}")
    print("自检        :", "通过" if ok else "失败")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
