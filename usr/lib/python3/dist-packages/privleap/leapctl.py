#!/usr/bin/python3 -su

# Copyright (C) 2025 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught,duplicate-code
# Rationale:
#   broad-exception-caught: except blocks are general error handlers.
#   duplicate-code: This is being triggered because of generic_error and
#     unexpected_error_msg, which are very similar in leapctl and leaprun but
#     can't be reasonably broken out of either due to the fact that they access
#     incompatible variants of the cleanup_and_exit function.

"""leapctl.py - privleapd client for controlling available comm sockets."""

import sys
import time
import pwd
from typing import NoReturn

from .privleap import (
    PrivleapCommon,
    PrivleapControlClientCreateMsg,
    PrivleapControlClientDestroyMsg,
    PrivleapControlClientReloadMsg,
    PrivleapControlServerControlErrorMsg,
    PrivleapControlServerDisallowedUserMsg,
    PrivleapControlServerExistsMsg,
    PrivleapControlServerExpectedDisallowedUserMsg,
    PrivleapControlServerNouserMsg,
    PrivleapControlServerOkMsg,
    PrivleapControlServerPersistentUserMsg,
    PrivleapMsg,
    PrivleapSession,
)


# pylint: disable=too-few-public-methods
# Rationale:
#   too-few-public-methods: This class just stores global variables, it needs no
#     public methods. Namespacing global variables in a class makes things
#     safer.
class LeapctlGlobal:
    """
    Global variables for leapctl.
    """

    control_session: PrivleapSession | None = None


def cleanup_and_exit(exit_code: int) -> NoReturn:
    """
    Ensures any active session is closed, then exits.
    """

    if LeapctlGlobal.control_session is not None:
        LeapctlGlobal.control_session.close_session()
    sys.exit(exit_code)


def print_usage() -> NoReturn:
    """
    Prints usage information.
    """

    print(
        """leapctl <--create|--destroy> <user>
leapctl --reload

     --create : Specifies that leapctl should request a communication socket to
                be created for the specified user account.
    --destroy : Specifies that leapctl should request a communication socket
                to be destroyed for the specified user account.
     --reload : Instructs privleapd to reload configuration without restarting.
         user : The username or UID of the user account to create or destroy a
                communication socket for."""
    )
    cleanup_and_exit(1)


def generic_error(error_msg: str, exit_int: int = 1) -> NoReturn:
    """
    Prints an error, then cleans up and exits.
    """

    print(f"ERROR: {error_msg}", file=sys.stderr)
    cleanup_and_exit(exit_int)


def unexpected_msg_error(control_msg: PrivleapMsg) -> NoReturn:
    """
    Alerts about an unexpected message type being received from the server.
    """

    print(
        "ERROR: privleapd returned an unexpected message as follows:",
        file=sys.stderr,
    )
    print(control_msg.serialize(), file=sys.stderr)
    cleanup_and_exit(1)


def wait_for_control_socket() -> None:
    """
    Waits for up to 5 seconds for the control socket to become available.
    """

    ## NOTE: We use polling to detect the socket. In nearly all cases, the
    ## socket will already exist, thus polling will only have to check for the
    ## socket's existence once, which is likely very fast. The only known case
    ## where the socket doesn't exist when leapctl is run is when the user
    ## runs something like `sudo systemctl restart privleapd; leapctl ...`, in
    ## which case minor delays from polling are acceptable. If in the future
    ## polling becomes a bottleneck, we may be able to use Varlink to listen
    ## for when the privleapd systemd unit comes up.

    for _ in range(50):
        if PrivleapCommon.control_path.is_socket():
            return
        time.sleep(0.1)


def start_control_session() -> None:
    """
    Starts a control session with the server.
    """

    try:
        LeapctlGlobal.control_session = PrivleapSession(is_control_session=True)
    except Exception:
        generic_error("Could not connect to privleapd!")


def handle_create_request(user_id: str) -> NoReturn:
    """
    Requests that privleapd create a socket for the specified user, and handles
    the response to the request.
    """

    assert LeapctlGlobal.control_session is not None

    try:
        LeapctlGlobal.control_session.send_msg(
            PrivleapControlClientCreateMsg(user_id)
        )
    except Exception:
        generic_error("Could not request privleapd to create a comm socket!")

    try:
        control_msg: PrivleapMsg = LeapctlGlobal.control_session.get_msg()
    except Exception:
        generic_error("privleapd didn't return a valid response!")

    if isinstance(control_msg, PrivleapControlServerOkMsg):
        print(f"Comm socket created for account {repr(user_id)}.")
        cleanup_and_exit(0)
    elif isinstance(control_msg, PrivleapControlServerControlErrorMsg):
        generic_error(
            "privleapd encountered an error while creating a comm socket "
            f"for account {repr(user_id)}!"
        )
    elif isinstance(control_msg, PrivleapControlServerDisallowedUserMsg):
        generic_error(
            f"Account {repr(user_id)} is not permitted to have a comm socket!",
            2,
        )
    elif isinstance(
        control_msg, PrivleapControlServerExpectedDisallowedUserMsg
    ):
        print(
            f"Account {repr(user_id)} is not permitted to have a comm "
            "socket, as expected, ok."
        )
        cleanup_and_exit(0)
    elif isinstance(control_msg, PrivleapControlServerExistsMsg):
        print(f"Comm socket already exists for account {repr(user_id)}.")
        cleanup_and_exit(0)
    else:
        unexpected_msg_error(control_msg)


def handle_destroy_request(user_id: str) -> NoReturn:
    """
    Requests that privleapd destroy a socket for the specified user, and handles
    the response to the request.
    """

    assert LeapctlGlobal.control_session is not None

    try:
        # noinspection PyUnboundLocalVariable
        LeapctlGlobal.control_session.send_msg(
            PrivleapControlClientDestroyMsg(user_id)
        )
    except Exception:
        generic_error("Could not request privleapd to destroy a comm socket!")

    try:
        control_msg: PrivleapMsg = LeapctlGlobal.control_session.get_msg()
    except Exception:
        generic_error("privleapd didn't return a valid response!")

    if isinstance(control_msg, PrivleapControlServerOkMsg):
        print(f"Comm socket destroyed for account {repr(user_id)}.")
        cleanup_and_exit(0)
    elif isinstance(control_msg, PrivleapControlServerControlErrorMsg):
        generic_error(
            "privleapd encountered an error while destroying a comm "
            f"socket for account {repr(user_id)}!"
        )
    elif isinstance(control_msg, PrivleapControlServerNouserMsg):
        print(f"Comm socket does not exist for account {repr(user_id)}.")
        cleanup_and_exit(0)
    elif isinstance(control_msg, PrivleapControlServerPersistentUserMsg):
        print(f"Cannot destroy socket for persistent account {repr(user_id)}.")
        # It is not an error to try to destroy a socket for a persistent user,
        # since this may legitimately happen if someone logs in as a user that
        # happens to be persistent in privleap's config, and then logs out.
        cleanup_and_exit(0)
    else:
        unexpected_msg_error(control_msg)


def handle_reload_request() -> NoReturn:
    """
    Requests that privleapd reload its configuration files without restarting.
    """

    assert LeapctlGlobal.control_session is not None

    try:
        LeapctlGlobal.control_session.send_msg(PrivleapControlClientReloadMsg())
    except Exception:
        generic_error("Could not request privleapd to reload configuration!")

    try:
        control_msg: PrivleapMsg = LeapctlGlobal.control_session.get_msg()
    except Exception:
        generic_error("privleapd didn't return a valid response!")

    if isinstance(control_msg, PrivleapControlServerOkMsg):
        print("privleapd configuration reload successful.")
        cleanup_and_exit(0)
    elif isinstance(control_msg, PrivleapControlServerControlErrorMsg):
        generic_error("privleapd failed to reload configuration!")
    else:
        unexpected_msg_error(control_msg)


def main() -> NoReturn:
    """
    Main function.
    """

    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print_usage()

    control_action: str = sys.argv[1]
    control_user_id: str | None = None
    if len(sys.argv) == 3:
        control_user_id = sys.argv[2]

    if control_action not in ("--create", "--destroy", "--reload"):
        print_usage()
    if control_action == "--reload" and control_user_id is not None:
        print_usage()

    if control_user_id is not None:
        control_user_struct: pwd.struct_passwd | None = (
            PrivleapCommon.normalize_user_id(control_user_id)
        )
        # Allow a username that doesn't exist to be passed when using --destroy,
        # so if a user is deleted before their comm socket is destroyed, the
        # socket can be destroyed anyway. Note that this will only work if the
        # deleted user's UID is passed, since there is no way to recover a
        # deleted user's UID to correlate it to a UID.
        if control_user_struct is None:
            if control_action != "--destroy":
                generic_error(
                    f"Specified account {repr(control_user_id)} does "
                    + "not exist."
                )
        else:
            control_user_id = str(control_user_struct.pw_name)

    wait_for_control_socket()
    start_control_session()

    if control_action == "--create":
        assert control_user_id is not None
        handle_create_request(control_user_id)
    elif control_action == "--destroy":
        assert control_user_id is not None
        handle_destroy_request(control_user_id)
    else:
        handle_reload_request()


if __name__ == "__main__":
    main()
