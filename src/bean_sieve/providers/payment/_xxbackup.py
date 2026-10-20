"""Xiaoxing .lch backup low-level readers. See docs/xxjz-backup-format.md."""

from __future__ import annotations

import struct
import zlib
from hashlib import pbkdf2_hmac

PASSWORD = "EuIDl^FFs29x1sw@"
PBKDF2_ROUNDS = 1000
KEY_LEN = 64
PAGE_HDR = 16
PAGE_BRANCH = 0x01
PAGE_LEAF = 0x02
PAGE_OVERFLOW = 0x04
NODE_BIGDATA = 0x01
_INT_TYPES = {1: "<B", 2: "<b", 3: "<h", 4: "<H", 5: "<i", 6: "<q", 10: "<q", 11: "<Q"}
_FLOAT_TYPES = {7: "<f", 8: "<d"}
OBX_STRING = 9


def _ctr(key, data):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    out = bytearray()
    for i in range(0, len(data), 16):
        block = bytearray(16)
        block[0:4] = (i // 16 + 1).to_bytes(4, "little")
        keystream = enc.update(bytes(block))
        chunk = data[i : i + 16]
        out += bytes(a ^ b for a, b in zip(chunk, keystream))
    return bytes(out)


def decrypt_lch(data):
    """Decrypt a .lch backup; returns the inner LMDB database image."""
    if data[:4] != b"PK\x03\x04":
        raise ValueError("not a xiaoxing backup (missing local file header)")
    name_len, extra_len = struct.unpack_from("<HH", data, 26)
    comp_size = struct.unpack_from("<I", data, 18)[0]
    pos = 30 + name_len + extra_len
    salt = data[pos : pos + 16]
    verifier = data[pos + 16 : pos + 18]
    ct_len = comp_size - 28
    ciphertext = data[pos + 18 : pos + 18 + ct_len]
    auth = data[pos + 18 + ct_len : pos + 28 + ct_len]
    derived = pbkdf2_hmac(
        "sha1", PASSWORD.encode(), salt, PBKDF2_ROUNDS, dklen=KEY_LEN + 2
    )
    if derived[KEY_LEN : KEY_LEN + 2] != verifier:
        raise ValueError("password verifier mismatch - unsupported app version?")
    import hmac

    if hmac.new(derived[32:KEY_LEN], ciphertext, "sha1").digest()[:10] != auth:
        raise ValueError("HMAC mismatch - archive corrupt?")
    return zlib.decompress(_ctr(derived[:32], ciphertext), -15)


class Lmdb:
    """Read-only view of one unnamed LMDB database, held fully in memory."""

    def __init__(self, data):
        self._data = data
        page_size = struct.unpack_from("<I", data, 40)[0]
        self.page_size = page_size if page_size in (1024, 4096, 8192) else 4096
        self._pairs = {}
        best_txn = -1
        root = 0
        for meta in (0, 1):
            base = meta * self.page_size
            if base + 0x98 > len(data):
                continue
            txn = struct.unpack_from("<Q", data, base + 0x90)[0]
            cand = struct.unpack_from("<Q", data, base + 0x80)[0]
            if txn > best_txn:
                best_txn, root = txn, cand
        self.txn_id = best_txn
        self._walk(root, set())

    def _walk(self, pgno, seen):
        if pgno in seen or (pgno + 1) * self.page_size > len(self._data):
            return
        seen.add(pgno)
        base = pgno * self.page_size
        flags = struct.unpack_from("<H", self._data, base + 10)[0]
        if flags & PAGE_OVERFLOW:
            return
        lower = struct.unpack_from("<H", self._data, base + 12)[0]
        count = (lower - PAGE_HDR) // 2
        for i in range(count):
            off = (
                base + struct.unpack_from("<H", self._data, base + PAGE_HDR + 2 * i)[0]
            )
            lo, hi, node_flags, key_size = struct.unpack_from("<HHHH", self._data, off)
            key = self._data[off + 8 : off + 8 + key_size]
            size = lo | (hi << 16)
            data_off = off + 8 + key_size
            if node_flags & NODE_BIGDATA:
                first = struct.unpack_from("<Q", self._data, data_off)[0]
                npages = (size - 1) // self.page_size + 1
                chunks = []
                for j in range(npages):
                    pb = (first + j) * self.page_size
                    chunks.append(self._data[pb + PAGE_HDR : pb + self.page_size])
                value = b"".join(chunks)[:size]
            else:
                value = self._data[data_off : data_off + size]
            self._pairs[key] = value
        if flags & PAGE_BRANCH:
            for i in range(count):
                off = (
                    base
                    + struct.unpack_from("<H", self._data, base + PAGE_HDR + 2 * i)[0]
                )
                lo, hi = struct.unpack_from("<HH", self._data, off)
                self._walk(lo | (hi << 16), seen)

    def items(self):
        return self._pairs

    def objects(self, entity_id):
        """Object rows of one entity: row id -> raw FlatBuffer.

        The 4th key byte is ``entity_id << 2 | width``, where ``width`` is 0
        for a 4-byte object id and 1 for an 8-byte one. Ids from
        timestamp-style generators (books, cycles) exceed 2**32 and so use
        12-byte keys; matching only 8-byte keys silently drops those entities.
        """
        out = {}
        for key, value in self._pairs.items():
            if len(key) < 8 or key[0] != 0x18 or key[1] or key[2]:
                continue
            if (key[3] >> 2) != entity_id:
                continue
            out[int.from_bytes(key[4:], "big")] = value
        return out


def _fb_header(blob):
    """Return (table_pos, vtable_pos, field_count) of the root table."""
    table = struct.unpack_from("<I", blob, 0)[0]
    vtable = table - struct.unpack_from("<i", blob, table)[0]
    vtable_size = struct.unpack_from("<H", blob, vtable)[0]
    return table, vtable, (vtable_size - 4) // 2


def decode_object(blob, props):
    """Decode one ObjectBox row; props maps property id -> (name, obx type)."""
    table, vtable, nfields = _fb_header(blob)
    out = {}
    for pid, (name, typ) in props.items():
        slot = pid - 1
        if slot >= nfields:
            continue
        off = struct.unpack_from("<H", blob, vtable + 4 + 2 * slot)[0]
        if off == 0:
            continue
        pos = table + off
        if typ in _INT_TYPES:
            out[name] = struct.unpack_from(_INT_TYPES[typ], blob, pos)[0]
        elif typ in _FLOAT_TYPES:
            value = float(struct.unpack_from(_FLOAT_TYPES[typ], blob, pos)[0])
            out[name] = round(value, 6)
        elif typ == OBX_STRING:
            sptr = pos + struct.unpack_from("<I", blob, pos)[0]
            length = struct.unpack_from("<I", blob, sptr)[0]
            out[name] = blob[sptr + 4 : sptr + 4 + length].decode("utf-8", "replace")
    return out
