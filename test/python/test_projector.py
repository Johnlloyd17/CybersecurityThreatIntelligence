from __future__ import annotations

import unittest

from python.cti_engine.events import ScanEvent
from python.cti_engine.projector import project_scan


class ProjectorTests(unittest.TestCase):
    def test_domain_seed_is_projected_as_internet_name(self) -> None:
        seed = ScanEvent(
            event_type="domain",
            value="elms.sti.edu",
            source_module="seed",
            root_target="elms.sti.edu",
        )
        child = ScanEvent(
            event_type="linked_url_internal",
            value="https://elms.sti.edu/login",
            source_module="alienvault",
            root_target="elms.sti.edu",
            parent_event_id=seed.event_id,
        )

        projected = project_scan(
            scan_id=1,
            scan_name="OTX parity",
            root_target="elms.sti.edu",
            status="finished",
            events=[seed, child],
            logs=[],
            correlations=[],
        ).to_dict()

        event_types = [row["event_type"] for row in projected["events"]]
        data_types = [row["data_type"] for row in projected["results"]]

        self.assertIn("internet_name", event_types)
        self.assertIn("Internet Name", data_types)
        self.assertIn("Linked Url Internal", data_types)


if __name__ == "__main__":
    unittest.main()
