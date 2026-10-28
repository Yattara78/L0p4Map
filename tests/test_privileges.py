"""Privilege handling: the UI must degrade instead of refusing to start."""

import os

import pytest

from core.scanner import check_root, has_raw_socket_access


def test_raw_socket_probe_returns_bool():
    assert isinstance(has_raw_socket_access(), bool)


def test_root_process_always_has_raw_access():
    if os.getuid() != 0:
        pytest.skip("not running as root")
    assert has_raw_socket_access() is True
    check_root()  # must not raise


def test_check_root_raises_only_without_raw_access():
    if has_raw_socket_access():
        pytest.skip("this session already has raw sockets")
    with pytest.raises(PermissionError):
        check_root()


def test_ui_module_does_not_call_check_root_at_import():
    """The GUI must import and start unprivileged (regression: it used to abort)."""
    pytest.importorskip("PyQt6")
    import ast
    from pathlib import Path

    source = Path(__file__).resolve().parents[1] / "ui" / "app.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))

    main_guard = [
        node
        for node in tree.body
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Compare)
        and isinstance(node.test.left, ast.Name)
        and node.test.left.id == "__name__"
    ]
    assert main_guard, "no __main__ guard found"

    calls = [
        node.func.id
        for stmt in main_guard[0].body
        for node in ast.walk(stmt)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    ]
    assert "check_root" not in calls, "__main__ still refuses to start unprivileged"
    assert "has_raw_socket_access" in calls
