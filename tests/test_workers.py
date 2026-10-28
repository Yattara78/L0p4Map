"""Regression tests for the Qt workers (P0: STOP must kill the child process)."""

import sys
import time

import pytest

pytest.importorskip("PyQt6")

try:
    from PyQt6.QtCore import QCoreApplication

    from ui.app import ActionWorker, TrafficWorker
except ImportError as exc:  # pragma: no cover - Qt runtime missing on CI
    pytest.skip(f"Qt runtime unavailable: {exc}", allow_module_level=True)


@pytest.fixture(scope="module")
def qt_app():
    app = QCoreApplication.instance() or QCoreApplication(sys.argv[:1])
    yield app


def _wait_until(predicate, timeout=5.0, interval=0.02):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def test_cancel_terminates_child_process(qt_app):
    worker = ActionWorker([sys.executable, "-c", "import time; time.sleep(60)"])
    worker.start()
    assert _wait_until(lambda: worker.process is not None), "child never started"
    child = worker.process
    assert child is not None

    worker.cancel()

    assert child.poll() is not None, "child process survived cancel()"
    assert worker.wait(5000), "worker thread did not stop"


def test_missing_binary_reports_error(qt_app):
    messages = []
    worker = ActionWorker(["definitely-not-a-real-binary-xyz"])
    worker.output.connect(messages.append)
    worker.start()
    assert worker.wait(5000)
    qt_app.processEvents()
    assert any("cannot start" in m for m in messages)


def test_traffic_worker_batches_packets(qt_app):
    worker = TrafficWorker("lo0")
    batches = []
    worker.packets.connect(batches.append)

    worker._buffer = [
        {"src": "10.0.0.1", "dst": "10.0.0.2", "proto": "TCP", "port": "443", "size": 60}
        for _ in range(3)
    ]
    worker._flush()
    qt_app.processEvents()

    assert len(batches) == 1
    assert len(batches[0]) == 3
    assert worker._buffer == []
