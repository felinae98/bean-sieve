"""小星记账 (XingXing Bookkeeping) ledger export provider."""

from __future__ import annotations

import logging
import re
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path

import xlrd

from ...core.types import Transaction
from .. import register_provider
from .._tabular import join_description
from ..base import BaseProvider

logger = logging.getLogger(__name__)


# Direction sign by sheet: expense positive, income negative.
_EXPENSE_SHEET = "支出"
_INCOME_SHEET = "收入"
_TRANSFER_SHEET = "转账"

# Per-sheet column layout (0-based), from the export header row.
# expense/income share: 0账本 1日期 2大类 3小类 4金额 5账户 6优惠 7退款
#   8退款账户 9币种 10商家/收入无 11角色 12报销 ... 15标签 16备注 18关联标记
EXPENSE_COLUMNS = {
    "book": 0,
    "time": 1,
    "category": 2,
    "subcategory": 3,
    "amount": 4,
    "account": 5,
    "discount": 6,
    "refund": 7,
    "refund_account": 8,
    "currency": 9,
    "merchant": 10,
    "reimburse": 12,
    "tags": 15,
    "remark": 16,
    "link": 18,
}
INCOME_COLUMNS = {
    "book": 0,
    "time": 1,
    "category": 2,
    "subcategory": 3,
    "amount": 4,
    "currency": 5,
    "account": 6,
    "refund": 7,
    "refund_account": 8,
    "merchant": 9,
    "reimburse": 11,
    "tags": 14,
    "remark": 15,
    "link": 17,
}
TRANSFER_COLUMNS = {
    "book": 0,
    "time": 1,
    "transfer_type": 2,
    "amount": 3,
    "currency": 4,
    "from_account": 5,
    "to_account": 6,
    "tags": 7,
    "remark": 8,
    "link": 10,
}

HEADER_KEYWORDS = ("账本", "币种")

# Refund entry inside 退款账户: "账户:金额(日期时间);" repeated
REFUND_ENTRY = re.compile(r"(?P<account>[^:：]+)[:：](?P<amount>[\d.]+)")

# Chinese currency name -> ISO code
_CURRENCY_CODES = {
    "人民币": "CNY",
    "美元": "USD",
    "港币": "HKD",
    "澳门元": "MOP",
    "新台币": "TWD",
    "欧元": "EUR",
    "英镑": "GBP",
    "日元": "JPY",
    "韩元": "KRW",
    "新加坡元": "SGD",
}


def _to_decimal(value: object) -> Decimal | None:
    """Parse a decimal cell; empty/placeholder/unparsable cells give None."""
    if value is None:
        return None
    if isinstance(value, float):
        return Decimal(str(value))
    text = str(value).strip()
    if not text or text in {"-", "/"}:
        return None
    try:
        return Decimal(text.replace(",", ""))
    except InvalidOperation:
        return None


def _cell_text(sheet, rowx: int, colx: int) -> str:
    """Cell as stripped text; integral floats lose the trailing .0."""
    if colx >= sheet.ncols:
        return ""
    value = sheet.cell_value(rowx, colx)
    if isinstance(value, float) and value == int(value):
        return str(int(value))
    return str(value).strip()


def _parse_datetime(value: str) -> tuple[date, datetime] | None:
    try:
        dt = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    return dt.date(), dt


@register_provider
class XiaoxingProvider(BaseProvider):
    """Provider for 小星记账 full-ledger XLS exports.

    File format (sheet per direction):
    - 支出 / 收入 / 转账 sheets, one header row then data rows
    - Amounts keep the statement sign here: expense positive, income negative
    - 优惠 is a rebate (expense reduced); 退款 partially or fully refunds a row
    - Currency by Chinese name (人民币/美元/...); foreign-currency expenses
      carry no CNY amount, so the row stays in its own currency
    """

    provider_id = "xiaoxing"
    provider_name = "小星记账"
    supported_formats = [".xls"]
    filename_keywords = ["小星记账"]
    content_keywords: list[str] = []  # Binary XLS, content detection not possible

    def parse(self, file_path: Path) -> list[Transaction]:
        wb = xlrd.open_workbook(str(file_path))

        names = wb.sheet_names()
        transactions: list[Transaction] = []

        for name, columns, sign in (
            (_EXPENSE_SHEET, EXPENSE_COLUMNS, 1),
            (_INCOME_SHEET, INCOME_COLUMNS, -1),
        ):
            if name in names:
                sheet = wb.sheet_by_name(name)
                transactions.extend(
                    self._parse_expense_like(sheet, columns, sign, file_path)
                )

        if _TRANSFER_SHEET in names:
            sheet = wb.sheet_by_name(_TRANSFER_SHEET)
            transactions.extend(self._parse_transfers(sheet, file_path))

        return transactions

    # === Expense / income sheets ===

    def _parse_expense_like(
        self,
        sheet,
        columns: dict[str, int],
        sign: int,
        file_path: Path,
    ) -> list[Transaction]:
        transactions: list[Transaction] = []
        if sheet.nrows < 2 or not self._header_matches(sheet):
            return transactions

        for row_idx in range(1, sheet.nrows):
            parsed = self._parse_expense_row(sheet, row_idx, columns, sign, file_path)
            if parsed is not None:
                transactions.append(parsed)
        return transactions

    @staticmethod
    def _header_matches(sheet) -> bool:
        for col in range(min(3, sheet.ncols)):
            if _cell_text(sheet, 0, col) == "账本":
                return True
        return False

    def _parse_expense_row(
        self,
        sheet,
        row_idx: int,
        columns: dict[str, int],
        sign: int,
        file_path: Path,
    ) -> Transaction | None:
        def cell(key: str) -> str:
            return _cell_text(sheet, row_idx, columns[key])

        parsed = _parse_datetime(cell("time"))
        if parsed is None:
            return None
        tx_date, tx_time = parsed

        amount = _to_decimal(sheet.cell_value(row_idx, columns["amount"]))
        if amount is None or amount == 0:
            return None

        currency = self._map_currency(cell("currency"))
        discount = (
            _to_decimal(sheet.cell_value(row_idx, columns["discount"]))
            if "discount" in columns
            else None
        )
        refund = _to_decimal(sheet.cell_value(row_idx, columns["refund"]))

        net = amount - (refund or Decimal(0))
        if net == 0:
            # Fully refunded: nothing left to reconcile, keep as metadata only
            return None
        if sign < 0:
            net = -net  # income rows: negate to bean-sieve sign

        account = cell("account")
        description = join_description(cell("category"), cell("subcategory"))
        merchant = cell("merchant")

        metadata: dict[str, object] = {
            "category": join_category(cell("category"), cell("subcategory")),
            "book": cell("book"),
        }
        if discount:
            # Rebate lowers the expense; recorded for the rebate posting path.
            metadata["rebate"] = str(discount)
            metadata["rebate_currency"] = currency
        if refund:
            metadata["refund"] = str(refund)
            refund_account = cell("refund_account")
            if refund_account:
                metadata["refund_account"] = self._first_refund_account(refund_account)
        if account:
            # The funding account doubles as the method for account_mappings.
            metadata["method"] = account
        if remark := cell("remark"):
            metadata["remark"] = remark
        if tags := cell("tags"):
            metadata["tags"] = tags
        if link := cell("link"):
            metadata["link"] = link
        if merchant:
            metadata["merchant"] = merchant
        reimburse = cell("reimburse")
        if reimburse and reimburse != "非报销":
            metadata["reimburse"] = reimburse

        payee = merchant or None

        return Transaction(
            date=tx_date,
            time=tx_time.time(),
            amount=net,
            currency=currency,
            description=description,
            payee=payee,
            provider=self.provider_id,
            source_file=file_path,
            source_line=row_idx + 1,
            metadata=metadata,
        )

    # === Transfer sheet ===

    def _parse_transfers(self, sheet, file_path: Path) -> list[Transaction]:
        """Transfers become two one-sided rows: out positive, in negative.

        Each half carries the opposite account in ``transfer_peer`` so a
        transfer rule can set both sides; the out leg also carries
        ``withdrawal_target`` for account-resolution symmetry with wechat.
        """
        transactions: list[Transaction] = []
        if sheet.nrows < 2:
            return transactions

        for row_idx in range(1, sheet.nrows):
            tx_time_str = _cell_text(sheet, row_idx, TRANSFER_COLUMNS["time"])
            parsed = _parse_datetime(tx_time_str)
            if parsed is None:
                continue
            tx_date, tx_time = parsed

            amount = _to_decimal(sheet.cell_value(row_idx, TRANSFER_COLUMNS["amount"]))
            if amount is None or amount == 0:
                continue

            currency = self._map_currency(
                _cell_text(sheet, row_idx, TRANSFER_COLUMNS["currency"])
            )
            from_account = _cell_text(sheet, row_idx, TRANSFER_COLUMNS["from_account"])
            to_account = _cell_text(sheet, row_idx, TRANSFER_COLUMNS["to_account"])
            transfer_type = _cell_text(
                sheet, row_idx, TRANSFER_COLUMNS["transfer_type"]
            )
            book = _cell_text(sheet, row_idx, TRANSFER_COLUMNS["book"])
            tags = _cell_text(sheet, row_idx, TRANSFER_COLUMNS["tags"])
            remark = _cell_text(sheet, row_idx, TRANSFER_COLUMNS["remark"])
            link = _cell_text(sheet, row_idx, TRANSFER_COLUMNS["link"])

            for leg_sign, peer, leg_account in (
                (1, to_account, from_account),
                (-1, from_account, to_account),
            ):
                if not leg_account:
                    continue
                metadata: dict[str, object] = {"method": leg_account, "book": book}
                if transfer_type:
                    metadata["transfer_type"] = transfer_type
                    metadata["transfer_peer"] = peer
                if tags:
                    metadata["tags"] = tags
                if link:
                    metadata["link"] = link
                transactions.append(
                    Transaction(
                        date=tx_date,
                        time=tx_time.time(),
                        amount=leg_sign * amount,
                        currency=currency,
                        description=transfer_type or "转账",
                        provider=self.provider_id,
                        source_file=file_path,
                        source_line=row_idx + 1,
                        metadata=metadata,
                    )
                )
            _ = remark  # transfer remark kept out: same text on both legs

        return transactions

    @staticmethod
    def _first_refund_account(refund_cell: str) -> str:
        match = REFUND_ENTRY.search(refund_cell)
        return match.group("account").strip() if match else refund_cell

    @staticmethod
    def _map_currency(name: str) -> str:
        return _CURRENCY_CODES.get(name, name)


def join_category(category: str, subcategory: str) -> str:
    return f"{category}:{subcategory}" if subcategory else category
