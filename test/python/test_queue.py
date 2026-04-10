from __future__ import annotations

import asyncio
from threading import Event
import unittest

from python.cti_engine.context import ScanContext, ScanRequest
from python.cti_engine.events import ScanEvent
from python.cti_engine.module_base import BaseModule
from python.cti_engine.queue import ScanQueueEngine
from python.cti_engine.registry import ModuleRegistry
from python.cti_engine.settings import SettingsSnapshot
from python.cti_engine.targets import normalize_target


class ChildModule(BaseModule):
    slug = "child"
    watched_types = {"domain"}
    produced_types = {"note"}

    async def handle(self, event: ScanEvent, ctx):
        yield ScanEvent(
            event_type="note",
            value=f"seen:{event.value}",
            source_module=self.slug,
            root_target=ctx.root_target,
            parent_event_id=event.event_id,
        )


class QueueTests(unittest.TestCase):
    def test_queue_runs_and_emits_child_event(self) -> None:
        registry = ModuleRegistry()
        registry.register(ChildModule)
        request = ScanRequest(
            scan_id=1,
            user_id=1,
            scan_name="Queue Test",
            target=normalize_target("example.com", "domain"),
            selected_modules=["child"],
            settings=SettingsSnapshot(),
        )
        ctx = ScanContext(request=request)
        engine = ScanQueueEngine(registry)
        result = asyncio.run(engine.run(ctx))

        event_types = [event.event_type for event in result.events]
        self.assertIn("domain", event_types)
        self.assertIn("note", event_types)
        self.assertEqual(result.status, "finished")

    def test_queue_stops_when_cancelled(self) -> None:
        registry = ModuleRegistry()
        registry.register(ChildModule)
        request = ScanRequest(
            scan_id=2,
            user_id=1,
            scan_name="Queue Cancel Test",
            target=normalize_target("example.com", "domain"),
            selected_modules=["child"],
            settings=SettingsSnapshot(),
        )
        cancel_event = Event()
        cancel_event.set()
        ctx = ScanContext(request=request, cancel_event=cancel_event)
        engine = ScanQueueEngine(registry)
        result = asyncio.run(engine.run(ctx))

        self.assertEqual(result.status, "aborted")
        self.assertEqual([event.event_type for event in result.events], ["domain"])
        self.assertTrue(any("Termination requested" in entry["message"] for entry in result.logs))


if __name__ == "__main__":
    unittest.main()
