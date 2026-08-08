"""
Pytest configuration for the ClauseCheck test suite.

Contains one Windows-only shim. Everything else about these tests is platform
independent; on Linux and macOS this file does nothing at all.
"""

import atexit
import os
import sys
import tempfile

# --------------------------------------------------------------------------- shim
#
# gltest's Direct Mode loader writes the GenVM message frame to a temp file, dup2's
# its fd onto stdin, and then unlinks the path while that fd is still open. POSIX
# permits unlinking an open file; Windows does not, and raises WinError 32.
#
# The unlink is only cleanup, so deferring it to process exit is safe and keeps the
# tests runnable on Windows without patching the installed package.

if sys.platform == "win32":
    _pending: list[str] = []
    _real_unlink = os.unlink
    _tmp_root = os.path.realpath(tempfile.gettempdir())

    def _unlink_tolerating_open_handles(path, *args, **kwargs):
        try:
            return _real_unlink(path, *args, **kwargs)
        except PermissionError:
            # Only tolerate this for temp files; anywhere else it is a real error.
            if os.path.realpath(os.fspath(path)).startswith(_tmp_root):
                _pending.append(os.fspath(path))
                return None
            raise

    def _drain_pending() -> None:
        for path in _pending:
            try:
                _real_unlink(path)
            except OSError:
                pass

    os.unlink = _unlink_tolerating_open_handles
    atexit.register(_drain_pending)
