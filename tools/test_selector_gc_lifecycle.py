import gc
import unittest
from pathlib import Path
import sys
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent))
import selector


class SelectorGCLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.was_enabled = gc.isenabled()

    def tearDown(self):
        if self.was_enabled:
            gc.enable()
        else:
            gc.disable()

    def test_normal_return_restores_enabled_state(self):
        gc.enable()
        with mock.patch.object(selector, "_main") as body:
            selector.main()
        body.assert_called_once_with()
        self.assertTrue(gc.isenabled())

    def test_normal_return_preserves_initially_disabled_state(self):
        gc.disable()
        with mock.patch.object(selector, "_main") as body:
            selector.main()
        body.assert_called_once_with()
        self.assertFalse(gc.isenabled())

    def test_exception_restores_enabled_state(self):
        gc.enable()
        with (
            mock.patch.object(selector, "_main", side_effect=RuntimeError("boom")),
            self.assertRaisesRegex(RuntimeError, "boom"),
        ):
            selector.main()
        self.assertTrue(gc.isenabled())

    def test_system_exit_restores_enabled_state(self):
        gc.enable()
        with (
            mock.patch.object(selector, "_main", side_effect=SystemExit(7)),
            self.assertRaises(SystemExit) as raised,
        ):
            selector.main()
        self.assertEqual(raised.exception.code, 7)
        self.assertTrue(gc.isenabled())

    def test_keyboard_interrupt_restores_enabled_state(self):
        gc.enable()
        with (
            mock.patch.object(selector, "_main", side_effect=KeyboardInterrupt),
            self.assertRaises(KeyboardInterrupt),
        ):
            selector.main()
        self.assertTrue(gc.isenabled())

    def test_repeated_call_after_error_uses_clean_lifecycle(self):
        gc.enable()
        body = mock.Mock(side_effect=(ValueError("first"), None))
        with mock.patch.object(selector, "_main", body):
            with self.assertRaisesRegex(ValueError, "first"):
                selector.main()
            self.assertTrue(gc.isenabled())
            selector.main()
        self.assertEqual(body.call_count, 2)
        self.assertTrue(gc.isenabled())


if __name__ == "__main__":
    unittest.main()
