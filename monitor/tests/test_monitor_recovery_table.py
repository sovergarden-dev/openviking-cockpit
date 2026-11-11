"""Offline regression: exercise the real Tk checkbox, not its variable."""
import sys
import tkinter as tk
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from reserve_table import ReserveTable


class RecoveryTableTests(unittest.TestCase):
    def test_status_failure_overrides_successful_audit_level(self):
        root = tk.Tk()
        root.withdraw()
        try:
            table = ReserveTable(root, preferences={})
            item = {
                "model": "fixture",
                "api_base": "https://fixture.invalid/v1",
                "last_probe": {"ok": False, "text": "HTTP 401", "at": 0},
                "audit_level": 4,
            }
            table.render([item])
            row = table.tree.get_children()[0]
            tags = set(table.tree.item(row, "tags"))
            self.assertIn("status_bad", tags)
            self.assertNotIn("audit_4", tags)
        finally:
            root.destroy()

    def test_note_checkbox_controls_visible_column(self):
        root = tk.Tk()
        root.withdraw()
        try:
            table = ReserveTable(root)
            table.render([dict(model='fixture', api_base='https://fixture.invalid/v1')])
            self.assertNotIn('note', table.tree.cget('displaycolumns'))
            table.optional_btn.invoke()
            self.assertIn('note', table.tree.cget('displaycolumns'))
            self.assertTrue(table.optional.get())
            table.optional_btn.invoke()
            self.assertNotIn('note', table.tree.cget('displaycolumns'))
            self.assertFalse(table.preferences['show_note'])
        finally:
            root.destroy()


if __name__ == '__main__':
    unittest.main(verbosity=2)
