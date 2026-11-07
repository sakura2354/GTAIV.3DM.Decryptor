#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
用法

    python dat_convert.py info    font.dat
    python dat_convert.py decode  font.dat -o font_out/          # 明文bin + json + txt
    python dat_convert.py verify  font.dat                       # 自检 + 回环
    python dat_convert.py encode  font_dat_decrypted.json -o new_font.dat
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import sys
from typing import Iterable, List, Sequence

# ── 1. 密钥表原始常量（d3d9.dll 0x1000AE70 就地展开，160 字节）───────────────
_RAW160 = bytes([
    0x00, 0x24, 0x00, 0x00, 0x04, 0x80, 0x00, 0x00, 0x94, 0x00, 0x00, 0x00,
    0x06, 0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x52, 0x53, 0x41, 0x31,
    0x00, 0x04, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
    0xd1, 0xda, 0x02, 0xe1, 0x8d, 0x94, 0xbb, 0xcd, 0x45, 0xee, 0x93, 0x24,
    0x37, 0x4a, 0xc9, 0xeb, 0xd5, 0xa4, 0xec, 0xe3, 0x7e, 0x93, 0x7a, 0x71,
    0x11, 0x2c, 0xd7, 0x6c, 0x42, 0xf4, 0x78, 0x8f, 0x4b, 0x38, 0x19, 0xc4,
    0xf4, 0x0c, 0xdc, 0xc9, 0x2a, 0xa0, 0x04, 0xe6, 0xa9, 0x94, 0xed, 0x75,
    0x47, 0x1a, 0xd8, 0x93, 0x85, 0xbe, 0xf9, 0x9e, 0x16, 0xd0, 0x46, 0x58,
    0x3b, 0xbf, 0xe3, 0x7c, 0xd1, 0x7b, 0xc8, 0x38, 0x05, 0xcd, 0xf0, 0xb1,
    0x1e, 0x97, 0xa0, 0x4e, 0x76, 0xc0, 0xfb, 0x73, 0x86, 0x8c, 0xce, 0xcb,
    0xa4, 0xbe, 0xfa, 0x68, 0xd1, 0x5f, 0xf6, 0x11, 0x89, 0x01, 0xf6, 0x6d,
    0x08, 0x91, 0x28, 0xfa, 0xb3, 0xa1, 0x95, 0x11, 0x1e, 0xc5, 0x53, 0x95,
    0x07, 0xed, 0xa2, 0x05, 0x6d, 0x26, 0x1e, 0x52, 0xbd, 0xd9, 0xa8, 0x2d,
    0x3c, 0xab, 0x69, 0xd1, 0x13, 0x46, 0x41, 0xf7,
])

M0 = 0x972D98DF           # 取余模数
MA = 0x49D7B1DD           # 乘数
MB = 0x6FAD133D           # 加数
XOR_CONST = 0xC3


def build_keytable() -> bytes:
    """还原 FUN_1000ae70 的 256 字节密钥表。"""
    raw = bytearray(256)
    raw[:len(_RAW160)] = _RAW160
    kt = bytearray(256)
    for i in range(256):
        s = i if i < 128 else i - 256          # 按 8 位有符号解释 i
        kt[i] = raw[i] ^ ((s * -0x53 + 0x1D) & 0xFF)
    return bytes(kt)


KEYTABLE = build_keytable()


def _key_at(pos: int) -> int:
    return ((pos * MA + MB) % M0) & 0xFF


def crypt(data: bytes) -> bytes:
    """异或流变换，加解密同一实现。"""
    kt, n = KEYTABLE, len(data)
    return bytes(b ^ kt[_key_at(i)] ^ XOR_CONST for i, b in enumerate(data))


# ── 2. 明文结构解析/构造 ─────────────────────────────────────────────────────
class FontDatError(Exception):
    pass


def parse_plain(plain: bytes) -> List[str]:
    """u32 count + [u16 len + u16[] UTF-16LE] × count  →  字符串列表"""
    if len(plain) < 4:
        raise FontDatError("明文过短，缺少 count 字段")
    count = struct.unpack_from("<I", plain, 0)[0]
    if count == 0 or count > 0x100000:
        raise FontDatError(f"count={count} 不合理，密钥表或输入文件可能有误")
    pos, out = 4, []
    for i in range(count):
        if pos + 2 > len(plain):
            raise FontDatError(f"第 {i} 条越界读取长度字段")
        blen = struct.unpack_from("<H", plain, pos)[0]
        pos += 2
        if blen & 1:
            raise FontDatError(f"第 {i} 条长度 {blen} 不是偶数")
        if pos + blen > len(plain):
            raise FontDatError(f"第 {i} 条越界：需要 {blen} 字节，剩余 {len(plain)-pos}")
        codes = struct.unpack_from("<%dH" % (blen // 2), plain, pos)
        pos += blen
        out.append("".join(map(chr, codes)))
    if pos != len(plain):
        raise FontDatError(f"解析后剩余 {len(plain)-pos} 字节未消费")
    return out


def build_plain(entries: Sequence[str]) -> bytes:
    buf = bytearray(struct.pack("<I", len(entries)))
    for s in entries:
        codes = [ord(ch) for ch in s]
        if any(c > 0xFFFF for c in codes):
            raise FontDatError("存在 BMP 之外的字符，该格式只支持 UTF-16LE 码元")
        blen = len(codes) * 2
        if blen > 0xFFFF:
            raise FontDatError(f"单条过长（{blen} 字节）")
        buf += struct.pack("<H", blen)
        buf += struct.pack("<%dH" % len(codes), *codes)
    return bytes(buf)


# ── 3. 顶层读写 ─────────────────────────────────────────────────────────────
def is_plain(blob: bytes) -> bool:
    """用结构合理性判断是明文还是密文（密文的 count 字段几乎必然离谱）。"""
    try:
        parse_plain(blob)
        return True
    except Exception:
        return False


def decrypt_blob(blob: bytes) -> bytes:
    if is_plain(blob):
        return blob                       # 已经是明文，直接透传
    plain = crypt(blob)
    parse_plain(plain)                    # 解不开就抛错，避免静默出错
    return plain


def read_fontdat(path: str) -> List[str]:
    """读 font.dat（明文或密文皆可），返回字符串列表。"""
    with open(path, "rb") as f:
        return parse_plain(decrypt_blob(f.read()))


def write_fontdat(path: str, entries: Sequence[str]) -> None:
    with open(path, "wb") as f:
        f.write(crypt(build_plain(entries)))


# ── 4. 自检统计 ─────────────────────────────────────────────────────────────
def stats(entries: Sequence[str]) -> dict:
    total_cp = sum(len(s) for s in entries)
    cjk = sum(1 for s in entries for ch in s if "\u4e00" <= ch <= "\u9fff")
    ascii_ = sum(1 for s in entries for ch in s if ord(ch) < 0x80)
    other = total_cp - cjk - ascii_
    return {
        "entries": len(entries),
        "codepoints": total_cp,
        "cjk": cjk,
        "ascii": ascii_,
        "other": other,
        "cjk_ratio": round(cjk / total_cp * 100, 2) if total_cp else 0.0,
        "longest": max((len(s) for s in entries), default=0),
        "unique_chars": len({ch for s in entries for ch in s}),
    }


def _dump_json(entries: Sequence[str], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"%04X" % i: s for i, s in enumerate(entries)},
                  f, ensure_ascii=False, indent=0)


def _dump_txt(entries: Sequence[str], path: str) -> None:
    # 文本导出对换行/制表符做字面转义，避免破坏行结构
    with open(path, "w", encoding="utf-8") as f:
        f.write("# font.dat decrypted — %d entries\n" % len(entries))
        for i, s in enumerate(entries):
            esc = (s.replace("\\", "\\\\").replace("\r", "\\r")
                    .replace("\n", "\\n").replace("\t", "\\t"))
            f.write("%04X\t%s\n" % (i, esc))


# ── 5. CLI ─────────────────────────────────────────────────────────────────
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="GTA IV 3DM 汉化补丁 font.dat 加解密工具",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    for name, help_ in (("info", "只报告统计，不写文件"),
                        ("decode", "解密并导出明文"),
                        ("verify", "自检 + 加解密回环校验"),
                        ("encode", "把 JSON 明文重新加密成 font.dat")):
        p = sub.add_parser(name, help=help_)
        p.add_argument("input")
        p.add_argument("-o", "--output", default=None,
                       help="输出文件或目录（decode 用目录）")

    args = ap.parse_args(argv)

    if args.cmd == "encode":
        with open(args.input, encoding="utf-8") as f:
            obj = json.load(f)
        entries = [obj[k] for k in sorted(obj, key=lambda k: int(k, 16))]
        out = args.output or "font.dat"
        write_fontdat(out, entries)
        back = read_fontdat(out)
        ok = back == entries
        print(f"已写出 {out}（{os.path.getsize(out)} 字节，{len(entries)} 条）")
        print("回读校验:", "通过" if ok else "失败")
        return 0 if ok else 1

    with open(args.input, "rb") as f:
        blob = f.read()

    encrypted = not is_plain(blob)
    plain = decrypt_blob(blob)
    entries = parse_plain(plain)
    st = stats(entries)

    print(f"输入      : {args.input}  ({len(blob)} 字节)")
    print(f"状态      : {'密文（已解密）' if encrypted else '明文'}")
    for k in ("entries", "codepoints", "cjk", "ascii", "other",
              "cjk_ratio", "longest", "unique_chars"):
        print(f"{k:<12}: {st[k]}")
    print("前 5 条   :")
    for i, s in enumerate(entries[:5]):
        print(f"  {i:04X}  {s}")

    if args.cmd == "verify":
        # 回环：明文 -> 加密 -> 再解密，必须与原文一致
        re_enc = crypt(plain)
        back = parse_plain(decrypt_blob(re_enc))
        same = back == entries
        # 与原始密文逐字节比对（仅当输入是密文）
        byte_ok = (crypt(plain) == blob) if encrypted else None
        print()
        print("回环（明文→加密→解密）:", "通过" if same else "失败")
        if byte_ok is not None:
            print("重加密与原始密文逐字节一致:", "是" if byte_ok else "否")
        return 0 if same and (byte_ok is not False) else 1

    if args.cmd == "decode":
        outdir = args.output or "font_out"
        os.makedirs(outdir, exist_ok=True)
        base = os.path.splitext(os.path.basename(args.input))[0]
        p_bin = os.path.join(outdir, base + "_dec.bin")
        p_js = os.path.join(outdir, base + "_dec.json")
        p_tx = os.path.join(outdir, base + "_dec.txt")
        with open(p_bin, "wb") as f:
            f.write(plain)
        _dump_json(entries, p_js)
        _dump_txt(entries, p_tx)
        for p in (p_bin, p_js, p_tx):
            print(f"写出      : {p}  ({os.path.getsize(p)} 字节)")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
