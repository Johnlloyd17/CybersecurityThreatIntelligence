from __future__ import annotations

import unittest

from python.cti_engine.events import ScanEvent


class ScanEventTests(unittest.TestCase):
    def test_event_id_is_stable_for_same_inputs(self) -> None:
        left = ScanEvent(
            event_type="domain",
            value="example.com",
            source_module="seed",
            root_target="example.com",
        )
        right = ScanEvent(
            event_type="domain",
            value="example.com",
            source_module="seed",
            root_target="example.com",
        )
        self.assertEqual(left.event_id, right.event_id)

    def test_blank_value_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ScanEvent(
                event_type="domain",
                value="",
                source_module="seed",
                root_target="example.com",
            )


if __name__ == "__main__":
    unittest.main()

