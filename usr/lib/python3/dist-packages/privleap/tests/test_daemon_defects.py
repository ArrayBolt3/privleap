#!/usr/bin/python3 -su

## Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

# pylint: disable=protected-access, too-few-public-methods, missing-class-docstring
# Rationale:
#   protected-access: Tests reach into module globals to install stubs.
#   too-few-public-methods: The fakes below are deliberately minimal stubs.
#   missing-class-docstring: The fakes are self-explanatory test doubles.

"""
test_daemon_defects.py - Focused, deterministic regression tests for two
security-relevant privleapd main-loop defects. These do NOT need root, real
sockets, or the full autopkgtest harness -- they drive the daemon's dispatch
logic directly with stubs.

Defect 1 -- a stale epoll-ready fd that is no longer in socket_list is an
ordinary poll->lock race, not a bookkeeping failure. It must be skipped, NOT
terminate the daemon (a prior sys.exit(1) could, under systemd's
StartLimitBurst, permanently prevent privleapd from restarting).

Defect 2 -- on a transient accept resource error (EMFILE/ENFILE/...), the
level-triggered epoll loop keeps the listen fd readable and busy-spins a core at
100% CPU, while the watchdog is still pinged so systemd sees the pegged,
non-serving process as healthy. The loop must back off AND must NOT satisfy the
watchdog for such an iteration.

Run with:
  python3 -m unittest privleap.tests.test_daemon_defects
"""

import errno
import unittest
from unittest import mock

# Only base-safe symbols are imported at module load, so the behavioral
# main_loop tests below still execute (and fail on the real defect) when this
# file is run against the UNFIXED daemon. The fix-only symbols
# (dispatch_ready_sockets, classify_accept_error, PrivleapdAcceptError) are
# reached via attribute access inside the tests that need them.
from privleap import privleapd
from privleap.privleapd import (
    PrivleapdGlobal,
    PrivleapdSocketInfo,
    handle_comm_socket_conn,
)
from privleap.privleap import PrivleapSocketType


class _StopLoop(Exception):
    """Sentinel raised by the fake epoll to break main_loop's while True."""


class _RecordingNotifier:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def notify(self, message: str) -> None:
        self.messages.append(message)


class _FakeReadPipe:
    def read(self) -> bytes:
        return b""


class _FakeBackendSocket:
    def __init__(self, fd: int) -> None:
        self._fd = fd

    def fileno(self) -> int:
        return self._fd


class _FakeListenSocket:
    def __init__(
        self,
        fd: int,
        socket_type: PrivleapSocketType,
        raise_exc: BaseException | None = None,
        user_name: str = "testuser",
    ) -> None:
        self.backend_socket = _FakeBackendSocket(fd)
        self.socket_type = socket_type
        self.user_name = user_name
        self._raise_exc = raise_exc
        self.session_started = False

    def get_session(self) -> object:
        if self._raise_exc is not None:
            raise self._raise_exc
        self.session_started = True
        return object()


class _FakeEpoll:
    """
    Minimal select.epoll stand-in. poll() replays a scripted list of results,
    then raises _StopLoop to break the otherwise-infinite main loop.
    """

    def __init__(self, poll_results: list[list[tuple[int, int]]]) -> None:
        self._poll_results = list(poll_results)
        self.registered_fds: list[int] = []

    def register(self, fd: int, _events: int) -> None:
        self.registered_fds.append(fd)

    def poll(self, _timeout: float) -> list[tuple[int, int]]:
        if not self._poll_results:
            raise _StopLoop()
        return self._poll_results.pop(0)


def _make_comm_sock_info(
    fd: int, raise_exc: BaseException | None = None
) -> PrivleapdSocketInfo:
    listen_socket = _FakeListenSocket(
        fd, PrivleapSocketType.COMMUNICATION, raise_exc=raise_exc
    )
    return PrivleapdSocketInfo(
        listen_socket=listen_socket,  # type: ignore[arg-type]
        term_notify_read_fd=-1,
        term_notify_write_fd=-1,
        term_notify_read_pipe=None,
        term_notify_write_pipe=None,
    )


class DaemonDefectTests(unittest.TestCase):
    def setUp(self) -> None:
        # Save global state we mutate so each test is isolated.
        self._saved_socket_list = PrivleapdGlobal.socket_list
        self._saved_notifier = PrivleapdGlobal.sdnotify_object
        self._saved_ctm_read_pipe = PrivleapdGlobal.ctm_read_pipe
        self._saved_ctm_read_fd = PrivleapdGlobal.ctm_read_fd

        PrivleapdGlobal.socket_list = []
        self.notifier = _RecordingNotifier()
        PrivleapdGlobal.sdnotify_object = self.notifier  # type: ignore[assignment]
        PrivleapdGlobal.ctm_read_pipe = _FakeReadPipe()  # type: ignore[assignment]
        # A ctm fd that never appears in scripted poll results.
        PrivleapdGlobal.ctm_read_fd = 9000

    def tearDown(self) -> None:
        PrivleapdGlobal.socket_list = self._saved_socket_list
        PrivleapdGlobal.sdnotify_object = self._saved_notifier
        PrivleapdGlobal.ctm_read_pipe = self._saved_ctm_read_pipe
        PrivleapdGlobal.ctm_read_fd = self._saved_ctm_read_fd

    # ----- Defect 1: stale ready fd must be skipped, not fatal -----

    def test_dispatch_skips_unknown_fd_without_exit(self) -> None:
        """A ready fd absent from socket_list is skipped and reported healthy."""
        PrivleapdGlobal.socket_list = []
        # Must not raise SystemExit; must report the iteration healthy.
        result = privleapd.dispatch_ready_sockets([1234])
        self.assertTrue(
            result, "skipping a stale fd must count as a healthy iteration"
        )

    def test_main_loop_does_not_exit_on_unknown_fd(self) -> None:
        """
        Drives the real main_loop. On the fixed code the stale fd is skipped and
        the next poll raises _StopLoop. On the defective code main_loop calls
        sys.exit(1) (SystemExit) instead -- which this test catches and fails on.
        """
        PrivleapdGlobal.socket_list = []
        fake_epoll = _FakeEpoll([[(1234, 1)]])
        fake_select = mock.Mock()
        fake_select.epoll = lambda: fake_epoll
        fake_select.EPOLLIN = 1

        raised: BaseException | None = None
        with mock.patch.object(privleapd, "select", fake_select):
            try:
                privleapd.main_loop()
            except BaseException as exc:  # noqa: BLE001 - inspect what escaped
                raised = exc

        self.assertIsInstance(
            raised,
            _StopLoop,
            "an unknown ready fd must be skipped, not terminate the daemon "
            f"(got {type(raised).__name__}: {raised!r})",
        )

    # ----- Defect 2: transient accept resource error must back off -----

    def test_classify_accept_error(self) -> None:
        classify = privleapd.classify_accept_error
        accept_error = privleapd.PrivleapdAcceptError
        self.assertEqual(
            classify(OSError(errno.EMFILE, "too many open files")),
            accept_error.RESOURCE,
        )
        self.assertEqual(
            classify(OSError(errno.ENFILE, "file table overflow")),
            accept_error.RESOURCE,
        )
        self.assertEqual(
            classify(BlockingIOError(errno.EAGAIN, "try again")),
            accept_error.SPURIOUS,
        )
        self.assertEqual(
            classify(ValueError("nope")),
            accept_error.OTHER,
        )

    def test_handle_comm_conn_signals_backoff_on_emfile(self) -> None:
        """
        On EMFILE, handle_comm_socket_conn must return exactly False (signal the
        main loop to back off) and must not start a session. The defective code
        returns None instead.
        """
        sock_info = _make_comm_sock_info(
            42, raise_exc=OSError(errno.EMFILE, "too many open files")
        )
        result = handle_comm_socket_conn(sock_info)
        self.assertIs(
            result,
            False,
            "EMFILE must return False to trigger backoff, not None",
        )
        # listen_socket is a _FakeListenSocket test double, not a real
        # PrivleapSocket, hence the no-member suppression.
        self.assertFalse(
            sock_info.listen_socket.session_started  # pylint: disable=no-member
        )

    def test_main_loop_backs_off_and_withholds_watchdog_on_emfile(self) -> None:
        """
        Drives the real main_loop with a comm socket whose accept() raises
        EMFILE. The fixed code must back off (time.sleep) and must NOT ping
        WATCHDOG=1 for that iteration. The defective code pings WATCHDOG=1 every
        iteration and never backs off -- which this test fails on.
        """
        emfile_fd = 42
        sock_info = _make_comm_sock_info(
            emfile_fd, raise_exc=OSError(errno.EMFILE, "too many open files")
        )
        PrivleapdGlobal.socket_list = [sock_info]

        fake_epoll = _FakeEpoll([[(emfile_fd, 1)]])
        fake_select = mock.Mock()
        fake_select.epoll = lambda: fake_epoll
        fake_select.EPOLLIN = 1

        raised: BaseException | None = None
        with mock.patch.object(privleapd, "select", fake_select), mock.patch(
            "privleap.privleapd.time.sleep"
        ) as sleep_mock:
            try:
                privleapd.main_loop()
            except BaseException as exc:  # noqa: BLE001
                raised = exc

        self.assertIsInstance(
            raised, _StopLoop, f"loop ended unexpectedly: {raised!r}"
        )
        self.assertNotIn(
            "WATCHDOG=1",
            self.notifier.messages,
            "watchdog must NOT be satisfied during an EMFILE busy-spin",
        )
        sleep_mock.assert_called_once_with(
            privleapd.accept_resource_backoff_seconds
        )

    def test_main_loop_pings_watchdog_on_healthy_idle(self) -> None:
        """
        Sanity guard: an ordinary idle iteration (empty poll result) must still
        ping the watchdog, so the backoff gating did not break liveness.
        """
        PrivleapdGlobal.socket_list = []
        fake_epoll = _FakeEpoll([[]])  # one idle poll, then _StopLoop
        fake_select = mock.Mock()
        fake_select.epoll = lambda: fake_epoll
        fake_select.EPOLLIN = 1

        raised: BaseException | None = None
        with mock.patch.object(privleapd, "select", fake_select):
            try:
                privleapd.main_loop()
            except BaseException as exc:  # noqa: BLE001
                raised = exc

        self.assertIsInstance(raised, _StopLoop)
        self.assertIn(
            "WATCHDOG=1",
            self.notifier.messages,
            "a healthy idle iteration must still ping the watchdog",
        )


if __name__ == "__main__":
    unittest.main()
