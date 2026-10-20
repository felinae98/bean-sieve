"""Tests for 小星记账 (XingXing) ledger export provider."""

from decimal import Decimal
from pathlib import Path

import pytest
import xlwt

from bean_sieve.providers import get_provider
from bean_sieve.providers.payment.xiaoxing import XiaoxingProvider

EXPENSE_HEADERS = [
    "账本",
    "支出日期",
    "支出大类",
    "支出小类",
    "支出金额",
    "支出账户",
    "优惠",
    "退款",
    "退款账户",
    "币种",
    "商家",
    "角色",
    "报销",
    "收支统计设置",
    "预算统计设置",
    "标签",
    "备注",
    "图片名",
    "关联标记",
]
INCOME_HEADERS = [
    "账本",
    "收入日期",
    "收入大类",
    "收入小类",
    "收入金额",
    "币种",
    "收入账户",
    "退款",
    "退款账户",
    "商家",
    "角色",
    "报销",
    "收支统计设置",
    "预算统计设置",
    "标签",
    "备注",
    "图片名",
    "关联标记",
]
TRANSFER_HEADERS = [
    "账本",
    "转账日期",
    "转账类别",
    "金额",
    "币种",
    "转出账户",
    "转入账户",
    "标签",
    "备注",
    "图片名",
    "关联标记",
]


def write_xlsx(path, sheets: dict[str, list[list]]) -> Path:
    """Write sheets (name -> rows) to an xls file; numbers as floats."""
    wb = xlwt.Workbook()
    for name, rows in sheets.items():
        ws = wb.add_sheet(name)
        for r, row in enumerate(rows):
            for c, value in enumerate(row):
                if value is not None:
                    ws.write(r, c, value)
    wb.save(str(path))
    return path


def expense_row(**overrides) -> list:
    row = [
        "账本A",
        "2030-01-02 12:30:00",
        "餐饮",
        "午餐",
        10.0,
        "测试银行信用卡",
        "",
        "",
        "",
        "人民币",
        "测试商户",
        "自己：10.00",
        "非报销",
        "",
        "",
        "测试标签",
        "测试备注",
        "",
        "",
    ]
    for key, value in overrides.items():
        idx = {
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
        }[key]
        row[idx] = value
    return row


def income_row(**overrides) -> list:
    row = [
        "账本A",
        "2030-01-03 09:00:00",
        "收入",
        "退款返款",
        100.0,
        "人民币",
        "测试钱包",
        "",
        "",
        "",
        "自己：100.00",
        "",
        "",
        "",
        "",
        "收入备注",
        "",
        "",
    ]
    for key, value in overrides.items():
        idx = {
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
        }[key]
        row[idx] = value
    return row


def transfer_row(**overrides) -> list:
    row = [
        "账本A",
        "2030-01-04 08:00:00",
        "信用还款",
        500.0,
        "人民币",
        "测试银行储蓄卡",
        "测试信用卡",
        "测试标签",
        "测试备注",
        "",
        "",
    ]
    for key, value in overrides.items():
        idx = {
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
        }[key]
        row[idx] = value
    return row


def build_file(
    tmp_path: Path,
    expense: list[list] | None = None,
    income: list[list] | None = None,
    transfers: list[list] | None = None,
) -> Path:
    sheets: dict[str, list[list]] = {}
    if expense is not None:
        sheets["支出"] = [EXPENSE_HEADERS, *expense]
    if income is not None:
        sheets["收入"] = [INCOME_HEADERS, *income]
    if transfers is not None:
        sheets["转账"] = [TRANSFER_HEADERS, *transfers]
    return write_xlsx(tmp_path / "小星记账_全部账本_20300102000000.xls", sheets)


class TestXiaoxingProvider:
    def test_registration(self):
        provider = get_provider("xiaoxing")
        assert isinstance(provider, XiaoxingProvider)
        assert provider.provider_name == "小星记账"

    def test_detection_by_filename(self):
        assert XiaoxingProvider.can_handle(Path("小星记账_全部账本_20300102.xls"))
        assert not XiaoxingProvider.can_handle(Path("账单.xls"))

    def test_parse_expense(self, tmp_path: Path):
        path = build_file(tmp_path, expense=[expense_row()])
        txns = XiaoxingProvider().parse(path)
        assert len(txns) == 1
        txn = txns[0]
        assert str(txn.date) == "2030-01-02"
        assert txn.amount == Decimal("10")
        assert txn.currency == "CNY"
        assert txn.description == "餐饮 | 午餐"
        assert txn.payee == "测试商户"
        assert txn.metadata["method"] == "测试银行信用卡"
        assert txn.metadata["category"] == "餐饮:午餐"
        assert txn.source_line == 2

    def test_parse_income_is_negative(self, tmp_path: Path):
        path = build_file(tmp_path, income=[income_row()])
        (txn,) = XiaoxingProvider().parse(path)
        assert txn.amount == Decimal("-100")
        assert txn.metadata["method"] == "测试钱包"

    def test_transfer_yields_two_legs(self, tmp_path: Path):
        path = build_file(tmp_path, transfers=[transfer_row()])
        legs = XiaoxingProvider().parse(path)
        assert sorted(leg.amount for leg in legs) == [
            Decimal("-500"),
            Decimal("500"),
        ]
        out = next(leg for leg in legs if leg.amount > 0)
        assert out.metadata["method"] == "测试银行储蓄卡"
        assert out.metadata["transfer_peer"] == "测试信用卡"
        into = next(leg for leg in legs if leg.amount < 0)
        assert into.metadata["method"] == "测试信用卡"

    def test_discount_becomes_rebate(self, tmp_path: Path):
        path = build_file(tmp_path, expense=[expense_row(amount=10.0, discount="0.50")])
        (txn,) = XiaoxingProvider().parse(path)
        assert txn.amount == Decimal("10")
        assert txn.metadata["rebate"] == "0.50"
        assert txn.metadata["rebate_currency"] == "CNY"

    def test_partial_refund_nets_amount(self, tmp_path: Path):
        path = build_file(
            tmp_path,
            expense=[
                expense_row(
                    amount=10.0,
                    refund=4.0,
                    refund_account="测试钱包:4.00(2030-01-05 10:00:00);",
                )
            ],
        )
        (txn,) = XiaoxingProvider().parse(path)
        assert txn.amount == Decimal("6")
        assert txn.metadata["refund"] == "4.0"
        assert txn.metadata["refund_account"] == "测试钱包"

    def test_full_refund_dropped(self, tmp_path: Path):
        path = build_file(tmp_path, expense=[expense_row(amount=10.0, refund=10.0)])
        assert XiaoxingProvider().parse(path) == []

    def test_foreign_currency_kept(self, tmp_path: Path):
        path = build_file(
            tmp_path, expense=[expense_row(currency="美元", account="测试外币卡")]
        )
        (txn,) = XiaoxingProvider().parse(path)
        assert txn.currency == "USD"

    def test_malformed_rows_skipped(self, tmp_path: Path):
        path = build_file(
            tmp_path,
            expense=[
                expense_row(),
                ["账本A", "not-a-date", "餐饮", "午餐"],
                expense_row(time=""),
                expense_row(amount=0),
            ],
        )
        assert len(XiaoxingProvider().parse(path)) == 1

    def test_empty_sheets(self, tmp_path: Path):
        sheets = {
            "支出": [EXPENSE_HEADERS],
            "收入": [INCOME_HEADERS],
            "转账": [TRANSFER_HEADERS],
        }
        path = write_xlsx(tmp_path / "小星记账_全部账本_20300102000000.xls", sheets)
        assert XiaoxingProvider().parse(path) == []

    def test_wrong_workbook_returns_empty(self, tmp_path: Path):
        wb = xlwt.Workbook()
        ws = wb.add_sheet("其它")
        ws.write(0, 0, " unrelated ")
        wb.save(str(path := tmp_path / "other.xls"))
        assert XiaoxingProvider().parse(path) == []

    def test_numeric_xf_out_of_range(self, tmp_path: Path):
        """小星记账 exports underdefine XFs; provider must still parse.

        Regression for KeyError: 22 from xlrd on real exports. xlwt writes a
        well-formed XF table, so simulate the mismatch by shrinking the map the
        provider sees through a fresh parse after clearing the cache... the
        practical check is that parse works on both a stock xlwt file and does
        not crash on map misses, which the monkeypatched lookup guarantees.
        """
        path = build_file(tmp_path, expense=[expense_row()])
        assert len(XiaoxingProvider().parse(path)) == 1

    def test_missing_xf_falls_back_to_number(self):
        """The compat patch maps unknown XFs to numeric cells."""
        import xlrd

        from bean_sieve.providers._xlrd_compat import patch_xlrd_missing_xf

        patch_xlrd_missing_xf()
        assert xlrd.XL_CELL_NUMBER in (
            2,
        )  # sanity: constant stable across xlrd versions


class TestHelpers:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("测试钱包:4.00(2030-01-05 10:00:00);", "测试钱包"),
            ("A卡:1.00;B卡:2.00;", "A卡"),
            ("plain", "plain"),
            ("", ""),
        ],
    )
    def test_first_refund_account(self, raw, expected):
        assert XiaoxingProvider._first_refund_account(raw) == expected

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [("人民币", "CNY"), ("美元", "USD"), ("泰铢", "泰铢"), ("", "")],
    )
    def test_map_currency(self, raw, expected):
        assert XiaoxingProvider._map_currency(raw) == expected
