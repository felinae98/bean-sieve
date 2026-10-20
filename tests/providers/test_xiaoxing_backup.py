"""Tests for the xiaoxing (.lch backup) provider."""

import os
import struct
from decimal import Decimal
from pathlib import Path

import pytest

from bean_sieve.providers import auto_detect_provider, get_provider
from bean_sieve.providers.payment import _xxbackup as xb
from bean_sieve.providers.payment.xiaoxing_backup import XiaoxingBackupProvider

PS = 4096
PAGE_HDR = 16
TIME = 1739000000000
KEY_ACCOUNT = bytes([0x18, 0, 0, 3 << 2])
KEY_BOOK = bytes([0x18, 0, 0, 2 << 2])
KEY_CURRENCY = bytes([0x18, 0, 0, 31 << 2])


def _record(fields):
    """FlatBuffer row; keys are property ids -> (kind, value)."""
    fields = {pid - 1: v for pid, v in fields.items()}
    slots = list(fields)
    max_slot = max(slots)
    vt_size = 4 + 2 * (max_slot + 1)
    table_pos = 4 + vt_size
    sizes = {"i": 8, "f": 8, "b": 1, "s": 4}
    positions = {}
    pos = table_pos + 4
    for slot in slots:
        positions[slot] = pos
        pos += sizes[fields[slot][0]]
    strings = {s: fields[s][1] for s in slots if fields[s][0] == "s"}
    str_base = pos
    str_off = {}
    for s in sorted(strings):
        str_off[s] = pos - positions[s]
        pos += 4 + len(strings[s].encode())
    total = pos
    vt = [0] * (max_slot + 1)
    for s in slots:
        vt[s] = positions[s] - table_pos
    vtable = struct.pack("<HH", vt_size, total - table_pos)
    vtable += b"".join(struct.pack("<H", o) for o in vt)
    out = bytearray(total)
    struct.pack_into("<I", out, 0, table_pos)
    out[4 : 4 + vt_size] = vtable
    struct.pack_into("<i", out, table_pos, table_pos - 4)
    str_pos = {}
    run = str_base
    for s in sorted(strings):
        str_pos[s] = run
        run += 4 + len(strings[s].encode())
    for s in slots:
        kind, value = fields[s]
        p = positions[s]
        if kind == "i":
            struct.pack_into("<q", out, p, value)
        elif kind == "f":
            struct.pack_into("<d", out, p, float(value))
        elif kind == "b":
            out[p] = 1 if value else 0
        else:
            struct.pack_into("<I", out, p, str_pos[s] - p)
            sp = str_pos[s]
            data = value.encode()
            struct.pack_into("<I", out, sp, len(data))
            out[sp + 4 : sp + 4 + len(data)] = data
    return bytes(out)


def _obj_key(entity_id, row_id):
    return bytes([0x18, 0, 0, (entity_id << 2) & 0xFF]) + row_id.to_bytes(4, "big")


def _obj_key8(entity_id, row_id):
    """Object key for an id > 2**32: 12 bytes, width bit set on the prefix."""
    return bytes([0x18, 0, 0, ((entity_id << 2) | 1) & 0xFF]) + row_id.to_bytes(
        8, "big"
    )


def _leaf_page(entries):
    nodes = []
    offset = PS
    for key, value in entries:
        node = struct.pack("<HHHH", len(value) & 0xFFFF, len(value) >> 16, 0, len(key))
        node += key + value
        offset -= len(node)
        nodes.append((offset, node))
    page = bytearray(PS)
    struct.pack_into("<H", page, 10, 2)  # leaf
    lower = PAGE_HDR + 2 * len(entries)
    struct.pack_into("<H", page, 12, lower)
    for i, (off, node) in enumerate(nodes):
        struct.pack_into("<H", page, PAGE_HDR + 2 * i, off)
        page[off : off + len(node)] = node
    return bytes(page)


def _backup(rows):
    entries = list(zip(rows[::2], rows[1::2]))
    page = _leaf_page(entries)
    meta = bytearray(PS)
    struct.pack_into("<I", meta, 16, 0xBEEFC0DE)
    struct.pack_into("<I", meta, 40, PS)
    struct.pack_into("<Q", meta, 0x80, 2)  # root page
    struct.pack_into("<Q", meta, 0x90, 1)  # txn id
    meta_old = bytearray(meta)
    struct.pack_into("<Q", meta_old, 0x90, 0)
    return bytes(meta) + bytes(meta_old) + page


def pbkdf2(salt):
    from hashlib import pbkdf2_hmac

    from bean_sieve.providers.payment._xxbackup import KEY_LEN, PASSWORD, PBKDF2_ROUNDS

    return pbkdf2_hmac(
        "sha1", PASSWORD.encode(), salt, PBKDF2_ROUNDS, dklen=KEY_LEN + 2
    )


def _encrypt(image):
    import hmac
    import os
    import zlib

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    salt = os.urandom(16)
    derived = pbkdf2(salt)
    aes_key, mac_key = derived[:32], derived[32:64]
    deflated = zlib.compress(image)[2:-4]  # strip zlib header/adler for raw
    ct = bytearray()
    enc = Cipher(algorithms.AES(aes_key), modes.ECB()).encryptor()
    for i in range(0, len(deflated), 16):
        block = bytearray(16)
        block[0:4] = (i // 16 + 1).to_bytes(4, "little")
        ks = enc.update(bytes(block))
        chunk = deflated[i : i + 16]
        ct += bytes(a ^ b for a, b in zip(chunk, ks))
    ct = bytes(ct)
    extra = b"\x01\x99\x07\x00\x02\x00AE\x03\x08\x00"
    header = struct.pack(
        "<IHHHHHIII", 0x04034B50, 20, 0, 0x0801, 0, 0x21, 0, len(ct) + 28, len(image)
    )
    name = b"v9.9.9_db2"
    header += struct.pack("<HH", len(name), len(extra))
    tail = derived[64:66] + ct + hmac.new(mac_key, ct, "sha1").digest()[:10]
    return header + name + extra + salt + tail


def _expense(row_id, amount, account_id, **kw):
    fields = {
        1: ("i", row_id),
        2: ("i", TIME),
        4: ("f", amount),
        5: ("i", 0),
        11: ("i", account_id),
        13: ("i", 0),
        12: ("i", 1),
        20: ("s", kw.get("item", "午餐")),
        21: ("s", kw.get("type", "餐饮")),
        22: ("i", 0),
    }
    fields.update(kw.get("extra", {}))
    return _record(fields)


def _income(row_id, amount, account_id):
    return _record(
        {
            1: ("i", row_id),
            2: ("i", TIME),
            4: ("f", amount),
            5: ("i", 0),
            11: ("i", account_id),
            13: ("i", 1),
            12: ("i", 1),
            20: ("s", "奖金"),
            21: ("s", "收入"),
            22: ("i", 0),
        }
    )


def _transfer(row_id, account_a, account_b, amount):
    return _record(
        {
            1: ("i", row_id),
            2: ("i", TIME),
            4: ("f", amount),
            5: ("i", 0),
            11: ("i", account_a),
            17: ("i", account_b),
            13: ("i", 2),
            12: ("i", 1),
            20: ("s", "账户互转"),
            21: ("s", "转账"),
            22: ("i", 0),
        }
    )


def _refund_leg(parent_id, row_id, account_id, amount):
    return _record(
        {
            1: ("i", row_id),
            2: ("i", TIME),
            4: ("f", amount),
            5: ("i", 0),
            11: ("i", account_id),
            13: ("i", 4),
            22: ("i", 5),
            24: ("i", parent_id),
            20: ("s", "退款"),
            21: ("s", "系统"),
        }
    )


def _meta_rows():
    rows = [
        _obj_key(3, 1),
        _record({1: ("i", 1), 2: ("s", "银行卡甲")}),
        _obj_key(3, 2),
        _record({1: ("i", 2), 2: ("s", "钱包乙")}),
        _obj_key(2, 1),
        _record({1: ("i", 1), 2: ("s", "日常")}),
        _obj_key(31, 0),
        _record({1: ("i", 0), 2: ("s", "人民币"), 3: ("s", "CNY")}),
        _obj_key(31, 1),
        _record({1: ("i", 1), 2: ("s", "美元"), 3: ("s", "USD")}),
        _obj_key(53, 1),
        _record({1: ("i", 1), 2: ("s", "link-a")}),
    ]
    return rows


@pytest.fixture
def backup_file(tmp_path: Path) -> Path:
    rows = _meta_rows()
    rows += [
        _obj_key(6, 100),
        _expense(100, 25.0, 1),
        _obj_key(6, 101),
        _income(101, 3000.0, 2),
        _obj_key(6, 102),
        _transfer(102, 1, 2, 500.0),
        _obj_key(6, 103),
        _expense(103, 30.0, 1, extra={25: ("f", 5.0)}),
        _obj_key(6, 104),
        _refund_leg(103, 104, 2, 5.0),
        _obj_key(6, 105),
        _expense(105, 0.0, 1),
    ]
    path = tmp_path / "backup.lch"
    path.write_bytes(_encrypt(_backup(rows)))
    return path


def test_registration():
    provider = get_provider("xiaoxing_backup")
    assert isinstance(provider, XiaoxingBackupProvider)


def test_parse_expense_income_transfer(backup_file):
    txs = XiaoxingBackupProvider().parse(backup_file)
    by_id = {}
    for t in txs:
        by_id.setdefault(t.source_line, []).append(t)
    expense = by_id[100][0]
    assert expense.amount == Decimal("25")
    assert expense.currency == "CNY"
    assert expense.description == "餐饮:午餐"
    assert expense.metadata["method"] == "银行卡甲"
    assert expense.metadata["book"] == "日常"
    assert expense.original_amount is None
    assert "link" not in expense.metadata
    income = by_id[101][0]
    assert income.amount == Decimal("-3000")
    assert income.metadata["method"] == "钱包乙"
    out_leg, in_leg = sorted(by_id[102], key=lambda t: -t.amount)
    assert out_leg.amount == Decimal("500")
    assert out_leg.metadata["method"] == "银行卡甲"
    assert in_leg.amount == Decimal("-500")
    assert in_leg.metadata["transfer_peer"] == "银行卡甲"


def test_refund_nets_and_meta(backup_file):
    txs = XiaoxingBackupProvider().parse(backup_file)
    refunded = next(t for t in txs if t.source_line == 103)
    assert refunded.amount == Decimal("25")
    assert refunded.metadata["refund"] == "5.0"
    assert refunded.metadata["refund_account"] == "钱包乙"


def test_zero_amount_dropped(backup_file):
    txs = XiaoxingBackupProvider().parse(backup_file)
    assert 105 not in {t.source_line for t in txs}


def test_decrypt_roundtrip():
    image = _backup(_meta_rows())
    assert xb.Lmdb(image).items()


def test_objects_includes_8byte_ids():
    """Ids beyond 2**32 (timestamp-generated) live in 12-byte keys."""
    big = 1688215324611
    rows = [
        _obj_key8(2, big),
        _record({1: ("i", big), 2: ("s", "共同账户"), 4: ("b", False)}),
    ]
    assert big in xb.Lmdb(_backup(rows)).objects(2)


def test_timestamp_id_book_resolves(tmp_path):
    """A book whose id is a timestamp must resolve via the width bit."""
    big_book = 1688215324611
    rows = [
        _obj_key(3, 1),
        _record({1: ("i", 1), 2: ("s", "银行卡甲")}),
        _obj_key8(2, big_book),
        _record({1: ("i", big_book), 2: ("s", "共同账户"), 4: ("b", False)}),
        _obj_key(6, 100),
        _expense(100, 25.0, 1, extra={12: ("i", big_book)}),
    ]
    path = tmp_path / "backup8.lch"
    path.write_bytes(_encrypt(_backup(rows)))
    txs = XiaoxingBackupProvider().parse(path)
    assert txs[0].metadata["book"] == "共同账户"


def test_full_pipe(tmp_path):
    rows = _meta_rows()
    rows += [_obj_key(6, 200), _expense(200, 10.0, 1, extra={36: ("f", 1.5)})]
    path = tmp_path / "b.lch"
    path.write_bytes(_encrypt(_backup(rows)))
    txs = get_provider("xiaoxing_backup").parse(path)
    assert txs[0].metadata["rebate"] == "1.5"


def test_foreign_row_uses_book_currency(tmp_path):
    """A foreign row reports the book amount; the pre-conversion amount moves
    to original_amount/original_currency."""
    rows = _meta_rows()
    rows += [
        _obj_key(6, 300),
        _expense(300, 70.0, 1, extra={5: ("i", 1), 33: ("f", 10.0)}),
    ]
    path = tmp_path / "fx.lch"
    path.write_bytes(_encrypt(_backup(rows)))
    (tx,) = XiaoxingBackupProvider().parse(path)
    assert tx.amount == Decimal("70")
    assert tx.currency == "CNY"
    assert tx.original_amount == Decimal("10.0")
    assert tx.original_currency == "USD"


def test_link_metadata(tmp_path):
    rows = _meta_rows()
    rows += [_obj_key(6, 301), _expense(301, 12.0, 1, extra={50: ("i", 1)})]
    path = tmp_path / "link.lch"
    path.write_bytes(_encrypt(_backup(rows)))
    (tx,) = XiaoxingBackupProvider().parse(path)
    assert tx.metadata["link"] == "link-a"


def _write_expense_backup(path: Path, amount: float) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = _meta_rows() + [_obj_key(6, 200), _expense(200, amount, 1)]
    path.write_bytes(_encrypt(_backup(rows)))
    return path


def test_directory_uses_newest_named_backup(tmp_path):
    older = _write_expense_backup(
        tmp_path / "v9.9.9_DEVICE_2030-01-02_030405_d1b2.lch", 10.0
    )
    newer = _write_expense_backup(
        tmp_path / "v9.9.9_DEVICE_2031-02-03_040506_d1b2.lch", 20.0
    )
    # Modification time says the opposite; the name timestamp must win.
    os.utime(older, (2_000_000, 2_000_000))
    os.utime(newer, (1_000_000, 1_000_000))
    (tx,) = XiaoxingBackupProvider().parse(tmp_path)
    assert tx.amount == Decimal("20")
    assert tx.source_file == newer


def test_directory_falls_back_to_mtime(tmp_path):
    older = _write_expense_backup(tmp_path / "old.lch", 10.0)
    newer = _write_expense_backup(tmp_path / "new.lch", 20.0)
    os.utime(older, (1_000_000, 1_000_000))
    os.utime(newer, (2_000_000, 2_000_000))
    (tx,) = XiaoxingBackupProvider().parse(tmp_path)
    assert tx.amount == Decimal("20")


def test_directory_searches_subdirectories(tmp_path):
    _write_expense_backup(
        tmp_path / "nested" / "v9.9.9_DEVICE_2030-01-02_030405_d1b2.lch", 30.0
    )
    (tx,) = XiaoxingBackupProvider().parse(tmp_path)
    assert tx.amount == Decimal("30")


def test_directory_detected(tmp_path):
    _write_expense_backup(tmp_path / "backup.lch", 10.0)
    assert isinstance(auto_detect_provider(tmp_path), XiaoxingBackupProvider)


def test_directory_without_backup_not_detected(tmp_path):
    (tmp_path / "notes.txt").write_text("x")
    assert auto_detect_provider(tmp_path) is None


def test_directory_without_backup_raises(tmp_path):
    with pytest.raises(ValueError, match="No .lch backup"):
        XiaoxingBackupProvider().parse(tmp_path)
