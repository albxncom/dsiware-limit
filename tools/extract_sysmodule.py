#!/usr/bin/env python3
"""Extract a CTRNAND sysmodule (default: NS, 0004013000008002 and the N3DS variant 0004013020008002)
from a GodMode9 SysNAND backup as decrypted exheader + decompressed .code.

Run: uv run --no-project --with pyctr -- python -I tools/extract_sysmodule.py --nand <sysnand.bin> --boot9 <boot9.bin> --out <dir> [--title 00040130/00008002 ...]
Keys come from the boot9.bin you supply (pyctr); nothing secret is stored here.
Copy <out>/0004013000008002/code.dec.bin to dumps/0004013000008002.dec.code.
"""
import argparse
import hashlib
import struct
import sys
from pathlib import Path

from pyctr.crypto import CryptoEngine
from pyctr.type.nand import NAND
from pyctr.type.ncch import NCCHReader, NCCHSection


def blz_decompress(data: bytes) -> bytes:
    """3DS .code reverse-LZ77 ("BLZ") decompression, as used by ctrtool/Luma for compressed CXI code."""
    footer = struct.unpack_from('<II', data, len(data) - 8)
    buf_top_and_bottom, additional = footer
    comp_size = buf_top_and_bottom & 0xFFFFFF
    header_len = buf_top_and_bottom >> 24
    out_len = len(data) + additional
    out = bytearray(out_len)
    out[:len(data)] = data
    index = len(data) - header_len
    stop = len(data) - comp_size
    out_index = out_len
    # mirrors ctrtool lzss_decompress: segment word is little-endian, offset is relative to the current out position + 2
    while index > stop:
        index -= 1
        control = out[index]
        for _ in range(8):
            if index <= stop or out_index <= 0:
                break
            if control & 0x80:
                index -= 2
                segment = out[index] | (out[index + 1] << 8)
                seg_len = ((segment >> 12) & 0xF) + 3
                seg_off = (segment & 0x0FFF) + 2
                for _ in range(seg_len):
                    data = out[out_index + seg_off]
                    out_index -= 1
                    out[out_index] = data
            else:
                index -= 1
                out_index -= 1
                out[out_index] = out[index]
            control = (control << 1) & 0xFF
    return bytes(out)


class Fat16:
    """Minimal read-only FAT16 walker over a file-like object positioned at the FAT volume start."""

    def __init__(self, fh, base: int):
        self.fh = fh
        self.base = base
        fh.seek(base)
        bs = fh.read(0x200)
        (self.bytes_per_sector, self.sectors_per_cluster, self.reserved, self.num_fats,
         self.root_entries, total16, _media, self.fat_size16) = struct.unpack_from('<HBHBHHBH', bs, 0x0B)
        total32 = struct.unpack_from('<I', bs, 0x20)[0]
        self.total_sectors = total16 or total32
        self.fat_off = self.reserved * self.bytes_per_sector
        self.root_off = self.fat_off + self.num_fats * self.fat_size16 * self.bytes_per_sector
        self.root_size = self.root_entries * 32
        self.data_off = self.root_off + self.root_size
        self.cluster_size = self.sectors_per_cluster * self.bytes_per_sector
        fh.seek(base + self.fat_off)
        self.fat = fh.read(self.fat_size16 * self.bytes_per_sector)
        fs_type = bs[0x36:0x3E]
        print(f'FAT volume: type={fs_type!r} bps={self.bytes_per_sector} spc={self.sectors_per_cluster} '
              f'sectors={self.total_sectors} root_entries={self.root_entries} cluster={self.cluster_size:#x}')

    def chain(self, cluster: int):
        while 2 <= cluster < 0xFFF8:
            yield cluster
            cluster = struct.unpack_from('<H', self.fat, cluster * 2)[0]

    def read_chain(self, cluster: int, size: int = None) -> bytes:
        out = bytearray()
        for c in self.chain(cluster):
            self.fh.seek(self.base + self.data_off + (c - 2) * self.cluster_size)
            out += self.fh.read(self.cluster_size)
            if size is not None and len(out) >= size:
                break
        return bytes(out[:size]) if size is not None else bytes(out)

    def list_dir(self, cluster: int = 0):
        if cluster == 0:
            self.fh.seek(self.base + self.root_off)
            raw = self.fh.read(self.root_size)
        else:
            raw = self.read_chain(cluster)
        lfn = []
        for i in range(0, len(raw), 32):
            e = raw[i:i + 32]
            if e[0] == 0:
                break
            if e[0] == 0xE5:
                lfn = []
                continue
            attr = e[11]
            if attr == 0x0F:
                part = e[1:11] + e[14:26] + e[28:32]
                lfn.insert(0, part.decode('utf-16-le', 'replace').split('\0')[0])
                continue
            name = e[:8].decode('ascii', 'replace').rstrip()
            ext = e[8:11].decode('ascii', 'replace').rstrip()
            short = f'{name}.{ext}' if ext else name
            long = ''.join(lfn) if lfn else short
            lfn = []
            start = struct.unpack_from('<H', e, 26)[0] | (struct.unpack_from('<H', e, 20)[0] << 16)
            size = struct.unpack_from('<I', e, 28)[0]
            yield long, short, attr, start, size

    def walk(self, path: str):
        cluster = 0
        parts = [p for p in path.strip('/').split('/') if p]
        for p in parts:
            for long, short, attr, start, size in self.list_dir(cluster):
                if long.lower() == p.lower() or short.lower() == p.lower():
                    if not attr & 0x10:
                        return self.read_chain(start, size)
                    cluster = start
                    break
            else:
                raise FileNotFoundError(path)
        return list(self.list_dir(cluster))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--nand', required=True)
    ap.add_argument('--boot9', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--title', nargs='+', default=['00040130/00008002', '00040130/20008002'])
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    nand = NAND(a.nand, crypto=CryptoEngine(boot9=a.boot9))
    fh = nand.open_ctr_partition(0)
    fat = Fat16(fh, 0)
    for title in a.title:
        tid = title.replace('/', '')
        content_dir = f'/title/{title}/content'
        try:
            entries = fat.walk(content_dir)
        except FileNotFoundError:
            print(f'{tid}: {content_dir} not present')
            continue
        print(f'{tid}: {content_dir} ->', [(e[0], e[4]) for e in entries])
        active = None
        for t in (e for e in entries if e[0].lower().endswith('.tmd')):
            tmd = fat.read_chain(t[3], t[4])
            sig_type = struct.unpack_from('>I', tmd, 0)[0]
            hdr = {0x10003: 0x240, 0x10004: 0x140, 0x10005: 0x80}[sig_type]
            title_id = tmd[hdr + 0x4C:hdr + 0x54].hex()
            version = struct.unpack_from('>H', tmd, hdr + 0x9C)[0]
            ncount = struct.unpack_from('>H', tmd, hdr + 0x9E)[0]
            cid = tmd[hdr + 0x9C4:hdr + 0x9C8].hex()
            print(f'  tmd {t[0]}: title {title_id} version {version} ({version >> 10}.{(version >> 4) & 0x3F}.{version & 0xF}) '
                  f'contents={ncount} content0 id={cid}')
            active = cid
        for name, short, attr, start, size in entries:
            if not name.lower().endswith('.app'):
                continue
            if active and name.lower()[:8] != active.lower():
                print(f'  skipping {name} (not the tmd content)')
                continue
            app = fat.read_chain(start, size)
            d = out / tid
            d.mkdir(exist_ok=True)
            (d / name).write_bytes(app)
            print(f'  {name}: {size:#x} bytes sha256 {hashlib.sha256(app).hexdigest()}')
            assert app[0x100:0x104] == b'NCCH'
            r = NCCHReader(d / name, crypto=nand._crypto)
            with r.open_raw_section(NCCHSection.ExtendedHeader) as f:
                raw_exh = f.read(0x800)
            (d / 'exheader.bin').write_bytes(raw_exh)
            print(f'  exheader.bin: {len(raw_exh):#x} bytes sha256 {hashlib.sha256(raw_exh).hexdigest()}')
            flags = raw_exh[0xD]
            text_addr, text_pages, text_size = struct.unpack_from('<III', raw_exh, 0x10)
            ro_addr, ro_pages, ro_size = struct.unpack_from('<III', raw_exh, 0x20)
            data_addr, data_pages, data_size = struct.unpack_from('<III', raw_exh, 0x30)
            bss = struct.unpack_from('<I', raw_exh, 0x3C)[0]
            stack = struct.unpack_from('<I', raw_exh, 0x1C)[0]
            print(f'  name={raw_exh[:8]!r} flags={flags:#x} text={text_addr:#x}/{text_size:#x} ro={ro_addr:#x}/{ro_size:#x} '
                  f'data={data_addr:#x}/{data_size:#x} bss={bss:#x} stack={stack:#x}')
            with r.exefs.open('.code') as f:
                code = f.read()
            if flags & 1:
                code = blz_decompress(code)
            (d / 'code.dec.bin').write_bytes(code)
            print(f'  code.dec.bin: compressed={bool(flags & 1)} -> {len(code):#x} bytes sha256 {hashlib.sha256(code).hexdigest()}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
