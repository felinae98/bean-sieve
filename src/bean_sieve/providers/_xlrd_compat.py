"""Compatibility fixes for xlrd quirks seen in real-world exports."""

from __future__ import annotations

import xlrd
import xlrd.sheet

_patched = False


def patch_xlrd_missing_xf() -> None:
    """Default missing XF cell types to numeric in xlrd.

    小星记账 exports define 21 XF records but reference index 22 in cells, so
    stock xlrd raises ``KeyError`` from ``put_cell_unragged`` while reading any
    sheet. Treating an out-of-range or otherwise unknown XF as a number cell
    matches every observed occurrence (amount cells); text cells carry their
    type inline and never hit this path.
    """
    global _patched
    if _patched:
        return
    original = xlrd.sheet.Sheet.put_cell_unragged

    def put_cell_unragged(self, rowx, colx, ctype, value, xf_index):  # noqa: ANN001
        if ctype is None and xf_index not in self._xf_index_to_xl_type_map:
            self._xf_index_to_xl_type_map[xf_index] = xlrd.XL_CELL_NUMBER
        return original(self, rowx, colx, ctype, value, xf_index)

    xlrd.sheet.Sheet.put_cell_unragged = put_cell_unragged
    _patched = True
