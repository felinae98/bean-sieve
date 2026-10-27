"""Provider for xiaoxing bookkeeping (com.cxincx.xxjz) .lch backups.

A .lch file is the app encrypted backup (WinZip AES, hard-coded password)
wrapping an ObjectBox/LMDB database; _xxbackup peels those layers.
Transactions mirror the XLS provider semantics: expense positive, income
negative; transfers become two one-sided rows. A refunded payment keeps its
gross amount and each refund leg (``detailType`` 4 / ``from`` 5) becomes its
own opposite-sign row dated when the refund happened, so both the original
payment and the refund stay matchable against statement rows.
Foreign-currency rows carry the book-currency amount as the transaction amount
and the pre-conversion amount in ``original_amount`` / ``original_currency``.
"""

from __future__ import annotations

import re
from datetime import datetime
from decimal import Decimal
from pathlib import Path

from ...core.metadata_keys import ORIGINAL_AMOUNT, ORIGINAL_CURRENCY
from ...core.types import Transaction
from .. import register_provider
from ..base import BaseProvider
from . import _xxbackup as xb

# Entity ids, schema of app 4.0.8.
DETAIL_ENTITY = 6
ACCOUNT_ENTITY = 3
BOOK_ENTITY = 2
CURRENCY_ENTITY = 31
LINK_ENTITY = 53
DETAIL_PROPS = {
    1: ("id", 6),
    2: ("time", 10),
    4: ("amount", 8),
    5: ("currency", 5),
    6: ("isReimbursement", 1),
    7: ("remark", 9),
    11: ("accountId", 11),
    12: ("accountBookId", 11),
    13: ("detailType", 5),
    14: ("typeId", 11),
    15: ("itemTypeId", 11),
    16: ("isDelete", 1),
    17: ("account2Id", 11),
    20: ("itemTypeName", 9),
    21: ("typeName", 9),
    22: ("from", 5),
    23: ("bx", 5),
    24: ("cycleId", 6),
    25: ("refundAmount", 8),
    32: ("isPre", 1),
    33: ("currencyAmount", 8),
    35: ("isNotInclude", 1),
    29: ("tagName", 9),
    36: ("preferentialAmount", 8),
    37: ("shopId", 11),
    38: ("shopName", 9),
    50: ("linkId", 11),
}
ACCOUNT_PROPS = {1: ("id", 6), 2: ("name", 9), 13: ("isDelete", 1)}
# isDelete's property id differs per entity (4 for books, 13 for accounts).
BOOK_PROPS = {1: ("id", 6), 2: ("name", 9), 4: ("isDelete", 1)}
CURRENCY_PROPS = {1: ("id", 6), 2: ("name", 9), 3: ("code", 9), 9: ("isDelete", 1)}
LINK_PROPS = {1: ("id", 6), 2: ("name", 9)}

TYPE_EXPENSE = 0
TYPE_INCOME = 1
TYPE_TRANSFER = 2
TYPE_SYSTEM = 4
FROM_REFUND = 5

# Backups are named v<appVersion>_<device>_<yyyy-MM-dd_HHmmss>_d<ver>b<ver>.lch.
_BACKUP_STAMP = re.compile(r"(\d{4}-\d{2}-\d{2}_\d{6})")


def _iter_backups(directory: Path):
    """Yield every ``.lch`` backup under ``directory``, including subdirectories."""
    for path in directory.rglob("*"):
        if path.is_file() and path.suffix.lower() == ".lch":
            yield path


def _backup_sort_key(path: Path) -> tuple[datetime, float]:
    """Order backups by the timestamp in the name, falling back to mtime."""
    mtime = path.stat().st_mtime
    match = _BACKUP_STAMP.search(path.name)
    if match:
        return datetime.strptime(match.group(1), "%Y-%m-%d_%H%M%S"), mtime
    return datetime.fromtimestamp(mtime), mtime


def _latest_backup(directory: Path) -> Path:
    """Newest backup in ``directory``, or ValueError if there is none."""
    backups = list(_iter_backups(directory))
    if not backups:
        raise ValueError(f"No .lch backup found in: {directory}")
    return max(backups, key=_backup_sort_key)


def _join_category(category, subcategory):
    return f"{category}:{subcategory}" if subcategory else category


@register_provider
class XiaoxingBackupProvider(BaseProvider):
    """Parser for xiaoxing bookkeeping encrypted backups (.lch).

    Pass it a single backup file or a backup directory; a directory resolves
    to the newest ``.lch`` in it (by the timestamp in the file name, falling
    back to the modification time).
    """

    provider_id = "xiaoxing_backup"
    provider_name = "小星记账备份"
    supported_formats = [".lch"]
    filename_keywords: list[str] = []
    content_keywords: list[str] = []

    @classmethod
    def can_handle(cls, file_path: Path) -> bool:
        if file_path.is_dir():
            return next(_iter_backups(file_path), None) is not None
        return super().can_handle(file_path)

    def parse(self, file_path: Path) -> list[Transaction]:
        if file_path.is_dir():
            file_path = _latest_backup(file_path)
        self._source = file_path
        blob = xb.decrypt_lch(file_path.read_bytes())
        db = xb.Lmdb(blob)
        accounts = self._name_map(db, ACCOUNT_ENTITY, ACCOUNT_PROPS)
        books = self._name_map(db, BOOK_ENTITY, BOOK_PROPS)
        currencies = self._currency_map(db)
        self._links = self._name_map(db, LINK_ENTITY, LINK_PROPS)
        details = {
            row_id: xb.decode_object(raw, DETAIL_PROPS)
            for row_id, raw in db.objects(DETAIL_ENTITY).items()
        }
        refund_legs: dict[int, list[tuple[int, dict]]] = {}
        for leg_id, row in details.items():
            if self._is_refund_leg(row):
                refund_legs.setdefault(row.get("cycleId") or 0, []).append(
                    (leg_id, row)
                )
        transactions = []
        for row_id, row in sorted(details.items()):
            if row.get("isDelete") or row.get("isPre"):
                continue
            kind = row.get("detailType")
            if kind == TYPE_EXPENSE:
                sign = 1
            elif kind == TYPE_INCOME:
                sign = -1
            else:
                sign = 0
            if sign:
                legs = refund_legs.get(row_id, [])
                tx = self._expense_like(
                    row, row_id, sign, accounts, books, currencies, legs
                )
                if tx is not None:
                    transactions.append(tx)
                transactions.extend(
                    self._refund_leg_txs(
                        row, row_id, sign, legs, accounts, books, currencies
                    )
                )
            elif kind == TYPE_TRANSFER:
                transactions.extend(
                    self._transfer_legs(row, row_id, accounts, books, currencies)
                )
        return transactions

    @staticmethod
    def _is_refund_leg(row) -> bool:
        return (
            row.get("detailType") == TYPE_SYSTEM
            and row.get("from") == FROM_REFUND
            and not row.get("isDelete")
            and not row.get("isPre")
        )

    @staticmethod
    def _name_map(db, entity_id, props):
        out = {}
        for row_id, raw in db.objects(entity_id).items():
            row = xb.decode_object(raw, props)
            if not row.get("isDelete") and row.get("name"):
                out[row_id] = row["name"]
        return out

    @staticmethod
    def _currency_map(db):
        out = {}
        for row_id, raw in db.objects(CURRENCY_ENTITY).items():
            row = xb.decode_object(raw, CURRENCY_PROPS)
            if not row.get("isDelete") and row.get("code"):
                out[row_id] = row["code"]
        return out

    def _expense_like(self, row, row_id, sign, accounts, books, currencies, legs):
        amount = self._dec(row.get("amount"))
        if amount is None or amount == 0:
            return None
        book_currency = self._book_currency(row, currencies)
        foreign = self._foreign_original(row, currencies, book_currency)
        refund = self._dec(row.get("refundAmount"))
        net = amount
        if sign < 0:
            net = -net
        account = accounts.get(row.get("accountId"), "")
        description = _join_category(
            row.get("typeName") or "", row.get("itemTypeName") or ""
        )
        metadata = {}
        book = books.get(row.get("accountBookId"))
        if book:
            metadata["book"] = book
        if description:
            metadata["category"] = description
        if account:
            metadata["method"] = account
        if remark := row.get("remark"):
            metadata["remark"] = remark
        if tags := row.get("tagName"):
            metadata["tags"] = tags
        if link := self._links.get(row.get("linkId")):
            metadata["link"] = link
        if row.get("isReimbursement"):
            metadata["reimburse"] = "报销"
        if row.get("isNotInclude"):
            metadata["include"] = "不计入收支"
        if row.get("preferentialAmount"):
            metadata["rebate"] = str(self._dec(row["preferentialAmount"]))
            metadata["rebate_currency"] = book_currency
        if foreign is not None:
            metadata[ORIGINAL_AMOUNT] = foreign
            metadata[ORIGINAL_CURRENCY] = self._currency_of(row, currencies)
        if refund:
            metadata["refund"] = str(refund)
            leg_accounts = [
                accounts.get(leg.get("accountId"), "") for _leg_id, leg in legs
            ]
            leg_accounts = [a for a in leg_accounts if a]
            if leg_accounts:
                metadata["refund_account"] = leg_accounts[0]
        dt = self._row_time(row)
        return Transaction(
            date=dt.date(),
            time=dt.time(),
            payee=row.get("shopName") or None,
            amount=net,
            currency=book_currency,
            description=description or "",
            provider=self.provider_id,
            source_file=self._source,
            source_line=row_id,
            metadata=metadata,
        )

    def _refund_leg_txs(self, row, row_id, sign, legs, accounts, books, currencies):
        """Emit one opposite-sign row per refund leg.

        The refund carries its own date and receiving account; the original
        category is reused so the existing rules classify it as a reduction of
        the same expense. The parent keeps its gross amount, so the pair nets
        to the refunded total while both statement rows stay matchable.
        """
        if not legs:
            return []
        book_currency = self._book_currency(row, currencies)
        description = _join_category(
            row.get("typeName") or "", row.get("itemTypeName") or ""
        )
        book = books.get(row.get("accountBookId"))
        payee = row.get("shopName") or None
        result = []
        for leg_id, leg in legs:
            amount = self._dec(leg.get("amount"))
            if amount is None or amount == 0:
                continue
            account = accounts.get(leg.get("accountId"), "")
            if not account:
                continue
            dt = self._row_time(leg)
            metadata = {"method": account, "refund_of": str(row_id)}
            if description:
                metadata["category"] = description
            if book:
                metadata["book"] = book
            if remark := leg.get("remark"):
                metadata["remark"] = remark
            if link := self._links.get(leg.get("linkId")):
                metadata["link"] = link
            result.append(
                Transaction(
                    date=dt.date(),
                    time=dt.time(),
                    payee=payee,
                    amount=-sign * amount,
                    currency=book_currency,
                    description=description or "退款",
                    provider=self.provider_id,
                    source_file=self._source,
                    source_line=leg_id,
                    metadata=metadata,
                )
            )
        return result

    def _transfer_legs(self, row, row_id, accounts, books, currencies):
        amount = self._dec(row.get("amount"))
        if amount is None or amount == 0:
            return []
        book_currency = self._book_currency(row, currencies)
        foreign = self._foreign_original(row, currencies, book_currency)
        from_account = accounts.get(row.get("accountId"), "")
        to_account = accounts.get(row.get("account2Id"), "")
        if not from_account or not to_account:
            return []
        label = row.get("itemTypeName") or "转账"
        book = books.get(row.get("accountBookId"))
        link = self._links.get(row.get("linkId"))
        dt = self._row_time(row)
        legs = []
        for sign, peer, account in (
            (1, to_account, from_account),
            (-1, from_account, to_account),
        ):
            metadata = {
                "method": account,
                "transfer_type": label,
                "transfer_peer": peer,
            }
            if book:
                metadata["book"] = book
            if link:
                metadata["link"] = link
            if foreign is not None:
                metadata[ORIGINAL_AMOUNT] = foreign
                metadata[ORIGINAL_CURRENCY] = self._currency_of(row, currencies)
            legs.append(
                Transaction(
                    date=dt.date(),
                    time=dt.time(),
                    amount=sign * amount,
                    currency=book_currency,
                    description=label,
                    provider=self.provider_id,
                    source_file=self._source,
                    source_line=row_id,
                    metadata=metadata,
                )
            )
        return legs

    @staticmethod
    def _dec(value):
        if value is None:
            return None
        return Decimal(str(value))

    def _book_currency(self, row, currencies):
        return currencies.get(row.get("baseCurrency") or 0, "CNY")

    def _foreign_original(self, row, currencies, book_currency):
        """Pre-conversion amount when the row's currency is not the book currency."""
        if self._currency_of(row, currencies) == book_currency:
            return None
        return self._dec(row.get("currencyAmount"))

    def _currency_of(self, row, currencies):
        return currencies.get(row.get("currency") or 0, "CNY")

    @staticmethod
    def _row_time(row):
        millis = row.get("time") or 0
        return datetime.fromtimestamp(millis / 1000)
