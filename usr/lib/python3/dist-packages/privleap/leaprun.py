#!/usr/bin/python3 -su

# Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught,duplicate-code
# Rationale:
#   broad-exception-caught: except blocks are general error handlers.
#   duplicate-code: This is being triggered because of generic_error and
#     unexpected_error_msg, which are very similar in leapctl and leaprun but
#     can't be reasonably broken out of either due to the fact that they access
#     incompatible variants of the cleanup_and_exit function.

"""leaprun.py - privleap client for running actions."""

import sys
import getpass
import select
import os
import pwd
import signal
import time
from pathlib import Path
from typing import cast, Union, NoReturn, Tuple
from types import FrameType

from .privleap import (
    PrivleapCommClientAccessCheckMsg,
    PrivleapCommClientSignalMsg,
    PrivleapCommClientTerminateMsg,
    PrivleapCommon,
    PrivleapCommServerAccessCheckResultsEndMsg,
    PrivleapCommServerAuthorizedMsg,
    PrivleapCommServerResultExitcodeMsg,
    PrivleapCommServerResultStderrMsg,
    PrivleapCommServerResultStdoutMsg,
    PrivleapCommServerTriggerErrorMsg,
    PrivleapCommServerTriggerMsg,
    PrivleapCommServerUnauthorizedMsg,
    PrivleapMsg,
    PrivleapSession,
    PrivleapValidateType,
)

Buffer = Union[bytes, bytearray, memoryview]


# pylint: disable=too-few-public-methods
# Rationale:
#   too-few-public-methods: This class just stores global variables, it needs no
#     public methods. Namespacing global variables in a class makes things
#     safer.
class LeaprunGlobal:
    """
    Global variables for leaprun.
    """

    signal_name_list: list[str] = []
    check_mode: bool = False
    test_mode: bool = False
    output_msg: (
        PrivleapCommClientSignalMsg | PrivleapCommClientAccessCheckMsg | None
    ) = None
    in_response_handler: bool = False
    terminate_session: bool = False
    user_name: str = getpass.getuser()
    comm_session: PrivleapSession | None = None


def cleanup_and_exit(exit_code: int) -> NoReturn:
    """
    Ensures any active session is closed, then exits.
    """

    if LeaprunGlobal.comm_session is not None:
        LeaprunGlobal.comm_session.close_session()
    sys.exit(exit_code)


def print_auth_notice(
    auth_signal_list: list[str], unauth_signal_list: list[str]
) -> None:
    """
    Prints information about which actions the user is and is not authorized
    to execute.
    """

    calling_account = get_calling_account_str()

    for signal_name in auth_signal_list:
        print(
            f"Account {calling_account} is authorized to run action "
            + f"{repr(signal_name)}."
        )
    for signal_name in unauth_signal_list:
        print(
            f"ERROR: Account {calling_account} is unauthorized to run action "
            + f"{repr(signal_name)}.",
            file=sys.stderr,
        )


def print_usage() -> NoReturn:
    """
    Prints usage information.
    """

    print(
        """leaprun [-c|--check] <action_name1> [<action_name2> ...]

    -c, --check  : Check if the current user is authorized to run an action.
    action_name1 : The name of the action leaprun should handle. leaprun will
                   send a signal to trigger the named action (or will ask
                   privleapd to check if the user can trigger the action).
                   If using -c or --check, up to 63 action names can be passed
                   to check them all at once."""
    )
    cleanup_and_exit(1)


def generic_error(error_msg: str) -> NoReturn:
    """
    Prints an error, then cleans up and exits.
    """

    print(f"ERROR: {error_msg}", file=sys.stderr)
    cleanup_and_exit(1)


def unexpected_msg_error(comm_msg: PrivleapMsg) -> NoReturn:
    """
    Alerts about an unexpected message type being received from the server.
    """

    print(
        "ERROR: privleapd returned an unexpected message as follows:",
        file=sys.stderr,
    )
    print(comm_msg.serialize(), file=sys.stderr)
    cleanup_and_exit(1)


def create_output_msg() -> None:
    """
    Creates an output message from a signal name.
    """

    for signal_name in LeaprunGlobal.signal_name_list:
        if not PrivleapCommon.validate_id(
            signal_name, PrivleapValidateType.SIGNAL_NAME
        ):
            generic_error(f"Signal name {repr(signal_name)} is invalid!")

    if LeaprunGlobal.check_mode:
        LeaprunGlobal.output_msg = PrivleapCommClientAccessCheckMsg(
            LeaprunGlobal.signal_name_list, skip_signal_name_validate=True
        )
    else:
        LeaprunGlobal.output_msg = PrivleapCommClientSignalMsg(
            LeaprunGlobal.signal_name_list[0],
            skip_signal_name_validate=True,
        )


def wait_for_comm_socket() -> None:
    """
    Waits for up to 5 seconds for the comm socket to become available.
    """

    ## Note: We use polling to detect the socket. See the comment in
    ## leapctl.py in function `wait_for_control_socket()` for rationale.

    target_path: Path = Path(PrivleapCommon.comm_dir, LeaprunGlobal.user_name)
    for _ in range(50):
        if target_path.is_socket():
            return
        time.sleep(0.1)


def start_comm_session() -> None:
    """
    Starts a comm session with the server.
    """

    try:
        # Yes, we are explicitly stating the user's username here. This is not
        # to identify ourselves to the server, but rather to actually open the
        # right socket. privleapd provides a different socket for each user,
        # and sets each socket's permissions to only allow a user to open the
        # socket assigned to them. The only socket we can connect to is the one
        # matching our username, thus we pass the username so that we open a
        # socket that we actually *can* open. This authenticates us as a
        # side-effect, but the authentication is not dependent on us telling the
        # truth, so there isn't a vulnerability here.
        LeaprunGlobal.comm_session = PrivleapSession(LeaprunGlobal.user_name)
    except Exception:
        generic_error("Could not connect to privleapd!")

    if LeaprunGlobal.test_mode:
        # Insert a bit of delay before sending messages, to allow the test
        # suite to win race conditions reliably.
        time.sleep(0.01)


def send_output_msg() -> None:
    """
    Sends a signal to the server using the open comm session.
    """

    assert LeaprunGlobal.comm_session is not None
    assert LeaprunGlobal.output_msg is not None
    try:
        # noinspection PyUnboundLocalVariable
        LeaprunGlobal.comm_session.send_msg(LeaprunGlobal.output_msg)
    except Exception:
        if LeaprunGlobal.check_mode:
            generic_error(
                "Could not query privleapd for authorization to run actions "
                f"{", ".join([repr(x) for x in LeaprunGlobal.signal_name_list])}!"
            )
        else:
            generic_error(
                "Could not request privleapd to run action "
                f"{repr(LeaprunGlobal.signal_name_list[0])}!"
            )


def check_terminate_session() -> None:
    """
    Checks if the user has attempted to terminate the session, and instructs
    the server to terminate the running action if so.
    """

    if LeaprunGlobal.terminate_session:
        try:
            assert LeaprunGlobal.comm_session is not None
            LeaprunGlobal.comm_session.send_msg(
                PrivleapCommClientTerminateMsg()
            )
            # TODO: Why was 130 chosen as an exit code constant here? Is this
            # relied upon by anything else? This should be documented.
            cleanup_and_exit(130)
        except Exception:
            generic_error("Could not send terminate message to privleapd!")


def get_calling_account_str() -> str:
    """
    Returns a string indicating the username and UID of the calling account.
    """

    uid = os.geteuid()
    return f"'{pwd.getpwuid(uid).pw_name}' ({uid})"


# pylint: disable=too-many-branches, too-many-statements
# Rationale:
#   too-many-branches, too-many-statements: This function is essentially a
#     finite state machine and would be difficult to split into other
#     functions while remaining readable.
def handle_response() -> NoReturn:
    """
    Handles the signal response from the server.
    """

    # This variable changes the behavior of the signal handler so that we
    # send a 'TERMINATE' message if the user interrupts an action run with
    # Ctrl+C.
    LeaprunGlobal.in_response_handler = True

    assert LeaprunGlobal.comm_session is not None
    assert LeaprunGlobal.comm_session.backend_socket is not None

    processing_trigger: bool = False
    unauth_signal_list: list[str] = []
    auth_signal_list: list[str] = []

    while True:
        try:
            check_terminate_session()

            # TODO: Use epoll here.
            ready_streams: Tuple[list[int], list[int], list[int]] = (
                select.select(
                    [LeaprunGlobal.comm_session.backend_socket.fileno()],
                    [],
                    [],
                    0.1,
                )
            )

            if (
                LeaprunGlobal.comm_session.backend_socket.fileno()
                in ready_streams[0]
            ):
                comm_msg = LeaprunGlobal.comm_session.get_msg()
            else:
                continue
        except Exception:
            if processing_trigger:
                generic_error(
                    "Action triggered, but privleapd closed the connection "
                    "before sending all output!"
                )
            else:
                generic_error(
                    "privleapd didn't return a valid message sequence!"
                )

        if isinstance(comm_msg, PrivleapCommServerUnauthorizedMsg):
            if len(unauth_signal_list) > 0:
                generic_error(
                    "privleapd returned two 'UNAUTHORIZED' messages in the "
                    + "same session!"
                )
            if processing_trigger:
                generic_error(
                    "privleapd returned an 'UNAUTHORIZED' message after "
                    + "having sent a 'TRIGGER' message!"
                )
            unauth_signal_list = comm_msg.signal_name_list
            if not LeaprunGlobal.check_mode:
                # When not running in auth mode, UNAUTHORIZED is the last
                # message the server will send.
                print_auth_notice(auth_signal_list, unauth_signal_list)
                cleanup_and_exit(1)

        elif isinstance(comm_msg, PrivleapCommServerAuthorizedMsg):
            if not LeaprunGlobal.check_mode:
                generic_error(
                    "privleapd returned an 'AUTHORIZED' message when leaprun "
                    + "was not in check mode!"
                )
            # We don't need to check if processing_trigger is True, because we
            # reject a 'TRIGGER' message sent when in check mode.
            if len(auth_signal_list) != 0:
                generic_error(
                    "privleapd returned two 'AUTHORIZED' messages in the "
                    + "same session!"
                )
            auth_signal_list = comm_msg.signal_name_list

        elif isinstance(comm_msg, PrivleapCommServerAccessCheckResultsEndMsg):
            if not LeaprunGlobal.check_mode:
                generic_error(
                    "privleapd returned an 'ACCESS_CHECK_RESULTS_END' "
                    + "message when leaprun was not in check mode!"
                )
            if len(unauth_signal_list) == 0 and len(auth_signal_list) == 0:
                generic_error(
                    "privleapd returned an 'ACCESS_CHECK_RESULTS_END' "
                    + "message before sending an 'AUTHORIZED' or "
                    + "'UNAUTHORIZED' message!"
                )
            print_auth_notice(auth_signal_list, unauth_signal_list)
            if len(unauth_signal_list) == 0:
                cleanup_and_exit(0)
            cleanup_and_exit(1)

        elif isinstance(comm_msg, PrivleapCommServerTriggerErrorMsg):
            if LeaprunGlobal.check_mode:
                generic_error(
                    "privleapd returned a 'TRIGGER_ERROR' message when "
                    + "leaprun was in check mode!"
                )
            generic_error(
                "An error was encountered launching action "
                f"{repr(LeaprunGlobal.signal_name_list[0])}."
            )

        elif isinstance(comm_msg, PrivleapCommServerTriggerMsg):
            if processing_trigger:
                generic_error(
                    "privleapd returned two 'TRIGGER' messages in the same "
                    + "session!"
                )
            if LeaprunGlobal.check_mode:
                generic_error(
                    "privleapd returned a 'TRIGGER' message when leaprun was "
                    + "in check mode!"
                )
            processing_trigger = True

        elif isinstance(comm_msg, PrivleapCommServerResultStdoutMsg):
            if not processing_trigger:
                generic_error(
                    "privleapd returned a 'RESULT_STDOUT' message before a "
                    + "'TRIGGER' message!"
                )
            _ = sys.stdout.buffer.write(cast(Buffer, comm_msg.stdout_bytes))

        elif isinstance(comm_msg, PrivleapCommServerResultStderrMsg):
            if not processing_trigger:
                generic_error(
                    "privleapd returned a 'RESULT_STDERR' message before a "
                    + "'TRIGGER' message!"
                )
            _ = sys.stderr.buffer.write(cast(Buffer, comm_msg.stderr_bytes))

        elif isinstance(comm_msg, PrivleapCommServerResultExitcodeMsg):
            if not processing_trigger:
                generic_error(
                    "privleapd returned a 'RESULT_EXITCODE' message before a "
                    + "'TRIGGER' message!"
                )
            cleanup_and_exit(comm_msg.exit_code)

        else:
            unexpected_msg_error(comm_msg)


# pylint: disable=unused-argument
def signal_handler(sig: int, frame: FrameType | None) -> None:
    """
    SIGINT / SIGTERM handler for aborting an operation.
    """

    if LeaprunGlobal.in_response_handler:
        LeaprunGlobal.terminate_session = True
    else:
        sys.exit(128)


def main() -> NoReturn:
    """
    Main function.
    """

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    end_of_options = False
    for arg in sys.argv[1:]:
        if arg in ("-c", "--check") and not end_of_options:
            LeaprunGlobal.check_mode = True
        elif arg == "--test" and not end_of_options:
            LeaprunGlobal.test_mode = True
        elif (arg == "--") and not end_of_options:
            end_of_options = True
        else:
            LeaprunGlobal.signal_name_list.append(arg)

    if not 1 <= len(LeaprunGlobal.signal_name_list) <= 63:
        print_usage()
    if len(LeaprunGlobal.signal_name_list) > 1 and not LeaprunGlobal.check_mode:
        print_usage()

    create_output_msg()
    wait_for_comm_socket()
    start_comm_session()
    send_output_msg()
    handle_response()


if __name__ == "__main__":
    main()
