#!/usr/bin/python3 -u

## Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught,too-few-public-methods
# Rationale:
#   broad-exception-caught: We use broad exception catching for general-purpose
#     error handlers.
#   too-few-public-methods: Global variable class uses no methods intentionally.

"""
run_test_util.py - Utility functions for run_test.py.
"""

import subprocess
import os
import sys
import logging
import pwd
import grp
import shutil
import time
import socket
import fcntl
from pathlib import Path
from typing import Tuple, IO
from datetime import datetime, timedelta

class PlTestGlobal:
    """
    Global variables for privleap tests.
    """

    linebuf: str = ""
    privleap_conf_base_dir: Path = Path("/etc/privleap")
    privleap_conf_dir: Path = Path(f"{privleap_conf_base_dir}/conf.d")
    privleap_conf_backup_dir: Path = Path(f"{privleap_conf_base_dir}/conf.d.bak")
    privleapd_proc: subprocess.Popen[str] | None = None
    test_username: str = "privleaptest"
    test_username_bytes: bytes = test_username.encode("utf-8")
    test_home_dir: Path = Path(f"/home/{test_username}")
    privleap_state_dir: Path = Path("/run/privleapd")
    privleap_state_comm_dir: Path = Path(privleap_state_dir, "comm")
    base_delay: float = 0.1
    privleapd_running: bool = False
    no_service_handling = False
    all_asserts_passed = True

SelectInfo = (Tuple[list[IO[bytes]], list[IO[bytes]], list[IO[bytes]]])

def proc_try_readline(proc: subprocess.Popen[str], timeout: float,
    read_stderr: bool = False) -> str | None:
    """
    Reads a line of test from the stdout or stderr of a process. Allows
      specifying a timeout for bailing out early. The stdout (or stderr)
      of the process must be in non-blocking mode.
    """

    assert proc.stdout is not None
    assert proc.stderr is not None

    # If there's a line already in the buffer, find and return it.
    if "\n" in PlTestGlobal.linebuf:
        linebuf_parts: list[str] = PlTestGlobal.linebuf.split("\n",
            maxsplit = 1)
        PlTestGlobal.linebuf = linebuf_parts[1]
        return linebuf_parts[0] + "\n"

    # Select the correct stream to read from.
    if read_stderr:
        target_stream: IO[str] = proc.stderr
    else:
        target_stream = proc.stdout

    # Attempt to read from the stream, adding whatever is available from the
    # stream into a buffer.
    current_time: datetime = datetime.now()
    end_time = current_time + timedelta(seconds = timeout)
    while True:
        try:
            PlTestGlobal.linebuf += target_stream.read()
        except Exception:
            pass
        if "\n" in PlTestGlobal.linebuf:
            break
        current_time = datetime.now()
        if current_time >= end_time:
            break

    # Retrieve a line from the buffer and return it.
    linebuf_parts = PlTestGlobal.linebuf.split("\n",
        maxsplit = 1)
    if len(linebuf_parts) == 2:
        PlTestGlobal.linebuf = linebuf_parts[1]
        return linebuf_parts[0] + "\n"

    # If there was no line to retrieve, return None.
    return None

def ensure_running_as_root() -> None:
    """
    Ensures the test is running as root. The tests cannot function when
      running as a user as they have to execute commands as root.
    """

    if os.geteuid() != 0:
        logging.error("The tests must run as root.")
        sys.exit(1)

def ensure_path_lacks_files(path: Path) -> None:
    """
    Ensures all components of the provided path either do not exist or are
      directories.
    """

    if path.exists() and not path.is_dir():
        logging.critical("Path '%s' contains a non-dir at '%s'!", str(path),
            str(path))
        sys.exit(1)
    for parent_path in path.parents:
        if parent_path.exists() and not parent_path.is_dir():
            logging.critical("Path '%s' contains a non-dir at '%s'!", str(path),
                str(parent_path))
            sys.exit(1)

def setup_test_account(test_username: str, test_home_dir: Path) -> None:
    """
    Ensures the user account used by the test script exists and is properly
      configured.
    """

    user_name_list: list[str] = [p.pw_name for p in pwd.getpwall()]
    if test_username not in user_name_list:
        try:
            subprocess.run(["useradd", "-m", test_username],
                check = True)
        except Exception as e:
            logging.critical("Could not create user '%s'!",
                test_username, exc_info = e)
            sys.exit(1)
    user_gid: int = pwd.getpwnam(test_username).pw_gid
    group_list: list[str] = [grp.getgrgid(gid).gr_name \
        for gid in os.getgrouplist(test_username, user_gid)]
    if not "sudo" in group_list:
        try:
            subprocess.run(["adduser", test_username, "sudo"],
                check = True)
        except Exception as e:
            logging.critical("Could not add user '%s' to group 'sudo'!",
                test_username, exc_info = e)
            sys.exit(1)
    ensure_path_lacks_files(test_home_dir)
    if not test_home_dir.exists():
        test_home_dir.mkdir(parents = True)
        shutil.chown(test_home_dir, user = test_username, group = test_username)

def displace_old_privleap_config() -> None:
    """
    Moves the existing privleap configuration dir to a backup location so we can
      put custom config in for testing purposes.
    """

    if PlTestGlobal.privleap_conf_backup_dir.exists():
        logging.critical("Backup config dir at '%s' exist, please move or "
        "remove it before continuing.",
        str(PlTestGlobal.privleap_conf_backup_dir))
        sys.exit(1)
    ensure_path_lacks_files(PlTestGlobal.privleap_conf_dir)
    ensure_path_lacks_files(PlTestGlobal.privleap_conf_backup_dir)
    PlTestGlobal.privleap_conf_base_dir.mkdir(parents = True, exist_ok = True)
    if PlTestGlobal.privleap_conf_dir.exists():
        shutil.move(PlTestGlobal.privleap_conf_dir, PlTestGlobal.privleap_conf_backup_dir)
    PlTestGlobal.privleap_conf_dir.mkdir(parents = True, exist_ok = True)

def restore_old_privleap_config() -> None:
    """
    Moves the backup privleap configuration dir back to the original location.
    """

    ensure_path_lacks_files(PlTestGlobal.privleap_conf_dir)
    ensure_path_lacks_files(PlTestGlobal.privleap_conf_backup_dir)
    PlTestGlobal.privleap_conf_base_dir.mkdir(parents = True, exist_ok = True)
    if PlTestGlobal.privleap_conf_backup_dir.exists():
        if PlTestGlobal.privleap_conf_dir.exists():
            shutil.rmtree(PlTestGlobal.privleap_conf_dir)
        shutil.move(PlTestGlobal.privleap_conf_backup_dir, PlTestGlobal.privleap_conf_dir)
    # Make sure the "real" config dir exists even if there wasn't a backup dir
    # to move into position
    PlTestGlobal.privleap_conf_dir.mkdir(parents = True, exist_ok = True)

def stop_privleapd_service() -> None:
    """
    Stops the privleapd service. This must be called before testing starts.
    """

    if PlTestGlobal.no_service_handling:
        return
    try:
        subprocess.run(["systemctl", "stop", "privleapd"], check = True)
    except Exception as e:
        logging.critical("Could not stop privleapd service!",
            exc_info = e)
        sys.exit(1)

def start_privleapd_subprocess(allow_error_output: bool = False) -> None:
    """
    Launches privleapd as a subprocess so its output can be monitored by the
      tester.
    """

    try:
        # pylint: disable=consider-using-with
        # Rationale:
        #   consider-using-with: "with" is not suitable for the architecture of
        #   this script in this scenario.
        PlTestGlobal.privleapd_proc = subprocess.Popen(["/usr/bin/privleapd",
            "--test"],
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE,
            encoding = "utf-8")
    except Exception as e:
        logging.critical("Could not start privleapd server!",
            exc_info = e)
    assert PlTestGlobal.privleapd_proc is not None
    assert PlTestGlobal.privleapd_proc.stdout is not None
    assert PlTestGlobal.privleapd_proc.stderr is not None
    fcntl.fcntl(PlTestGlobal.privleapd_proc.stdout.fileno(),
        fcntl.F_SETFL, os.O_NONBLOCK)
    fcntl.fcntl(PlTestGlobal.privleapd_proc.stderr.fileno(),
        fcntl.F_SETFL, os.O_NONBLOCK)
    time.sleep(PlTestGlobal.base_delay)
    if not allow_error_output:
        early_privleapd_output: str | None = proc_try_readline(
            PlTestGlobal.privleapd_proc, PlTestGlobal.base_delay,
            read_stderr = True)
        if early_privleapd_output is not None:
            logging.critical("privleapd returned error messages at startup!")
            while True:
                logging.critical(early_privleapd_output)
                early_privleapd_output = proc_try_readline(
                    PlTestGlobal.privleapd_proc, PlTestGlobal.base_delay,
                    read_stderr = True)
                if early_privleapd_output is None:
                    break
            sys.exit(1)
    PlTestGlobal.privleapd_running = True

def stop_privleapd_subprocess() -> None:
    """
    Stops the privleapd subprocess.
    """

    assert PlTestGlobal.privleapd_proc is not None
    try:
        PlTestGlobal.privleapd_proc.kill()
        _ = PlTestGlobal.privleapd_proc.communicate()
    except Exception as e:
        logging.critical("Could not kill privleapd!", exc_info = e)
    time.sleep(PlTestGlobal.base_delay)
    PlTestGlobal.privleapd_running = False

def assert_command_result(command_data: list[str], exit_code: int,
    stdout_data: bytes = b"", stderr_data: bytes = b"") -> bool:
    """
    Runs a command and ensures that the stdout, stderr, and exitcode match
      expected values.
    """

    test_result: subprocess.CompletedProcess[bytes] \
        = subprocess.run(command_data, check = False, capture_output = True)
    logging.info("Ran command: %s", command_data)
    logging.info("Exit code: %s", test_result.returncode)
    logging.info("Stdout: %s", test_result.stdout)
    logging.info("Stderr: %s", test_result.stderr)
    assert_failed: bool = False
    if exit_code != test_result.returncode:
        logging.error("Exit code assert failed, expected: %s", exit_code)
        assert_failed = True
    if stdout_data != test_result.stdout:
        logging.error("Stdout assert failed, expected: %s", stdout_data)
        assert_failed = True
    if stderr_data != test_result.stderr:
        logging.error("Stderr assert failed, expected: %s", stderr_data)
        assert_failed = True
    if assert_failed:
        return False
    return True

def write_privleap_test_config() -> None:
    """
    Writes test privleap config data.
    """

    with open(Path(PlTestGlobal.privleap_conf_dir, "unit-test.conf"), "w",
        encoding = "utf-8") as config_file:
        config_file.write(PlTestData.primary_test_config_file)

def compare_privleapd_stderr(assert_line_list: list[str], quiet: bool = False) \
    -> bool:
    """
    Compares the stdout output of privleapd with a string list, testing to see
      if each expected line has a corresponding returned line. The list of
      expected lines may omit arbitrary output lines.
    """

    assert PlTestGlobal.privleapd_proc is not None
    result_good: bool = True
    read_lines: list[str] = []
    for line in assert_line_list:
        while True:
            proc_line = proc_try_readline(PlTestGlobal.privleapd_proc,
                PlTestGlobal.base_delay, read_stderr = True)
            if proc_line is None:
                result_good = False
                break
            read_lines.append(proc_line)
            if proc_line != line:
                continue
            # If we get this far, line == proc_line
            break
    while True:
        proc_line = proc_try_readline(PlTestGlobal.privleapd_proc,
            PlTestGlobal.base_delay, read_stderr = True)
        if proc_line is None:
            break
        read_lines.append(proc_line)
    if not result_good:
        if not quiet:
            logging.error("Unexpected response from server!")
            for line in read_lines:
                logging.error("%s", line)
    return result_good

def discard_privleapd_stderr() -> None:
    """
    Ensures that the running privleapd's stdout stream has no pending contents.
    """

    if PlTestGlobal.privleapd_running:
        assert PlTestGlobal.privleapd_proc is not None
        while True:
            proc_line = proc_try_readline(PlTestGlobal.privleapd_proc,
                PlTestGlobal.base_delay, read_stderr = True)
            if proc_line is None:
                break

def start_privleapd_service() -> None:
    """
    Starts the privleapd service. This should only be called once all testing is
      done.
    """

    if PlTestGlobal.no_service_handling:
        return
    try:
        subprocess.run(["systemctl", "start", "privleapd"], check = True)
    except Exception as e:
        logging.critical("Could not start privleapd service!",
            exc_info = e)
        sys.exit(1)

def socket_send_raw_bytes(sock: socket.socket, buf: bytes) -> bool:
    """
    Sends a buffer of bytes through a socket, coping with partial sends
      properly.
    """
    buf_sent: int = 0
    while buf_sent < len(buf):
        last_sent: int = sock.send(buf[buf_sent:])
        if last_sent == 0:
            return False
        buf_sent += last_sent
    return True

class PlTestData:
    """
    Data for privleap tests.
    """

    primary_test_config_file: str = f"""[test-act-free]
Command=echo 'test-act-free'

[persistent-users]
# UID 3 = sys
User=3

[test-act-userrestrict]
Command=echo 'test-act-userrestrict'
AuthorizedUsers=sys

[test-act-grouprestrict]
Command=echo 'test-act-grouprestrict'
AuthorizedGroups=sys

[test-act-grouppermit-userrestrict]
Command=echo 'test-act-grouppermit-userrestrict'
AuthorizedUsers=sys
AuthorizedGroups={PlTestGlobal.test_username}

[allowed-users]
User={PlTestGlobal.test_username}
User=_apt
User=daemon
User=deleteme
User=root

[test-act-grouprestrict-userpermit]
Command=echo 'test-act-grouprestrict-userpermit'
AuthorizedUsers={PlTestGlobal.test_username}
AuthorizedGroups=sys

[test-act-userpermit]
Command=echo 'test-act-userpermit'
AuthorizedUsers={PlTestGlobal.test_username}

[persistent-users]
User=bin
User=uucp

[test-act-grouppermit]
Command=echo 'test-act-grouppermit'
AuthorizedGroups={PlTestGlobal.test_username}

[test-act-grouppermit-userpermit]
Command=echo 'test-act-grouppermit-userpermit'
AuthorizedUsers={PlTestGlobal.test_username}
AuthorizedGroups={PlTestGlobal.test_username}

# Not all groups have a corresponding username, this tests that edge case
[test-act-sudopermit]
Command=echo 'test-act-sudopermit'
AuthorizedGroups=sudo

[test-act-multiuser-permit]
Command=echo 'test-act-multiuser-permit'
AuthorizedUsers={PlTestGlobal.test_username},3,messagebus

[test-act-multigroup-permit]
Command=echo 'test-act-multigroup-permit'
AuthorizedGroups={PlTestGlobal.test_username},3,messagebus

[test-act-multiuser-multigroup-permit]
Command=echo 'test-act-multiuser-multigroup-permit'
AuthorizedUsers={PlTestGlobal.test_username},sys
AuthorizedGroups=sys,messagebus

[test-act-exit240]
Command=echo 'test-act-exit240'; exit 240

[test-act-stderr]
Command=1>&2 echo 'test-act-stderr'

[test-act-stdout-stderr-interleaved]
Command=echo 'stdout00'; 1>&2 echo 'stderr00'; echo 'stdout01'; 1>&2 echo 'stderr01'

[test-act-invalid-bash]
Command=ahem, this will not work

[test-act-target-user]
Command=id
TargetUser={PlTestGlobal.test_username}

[test-act-target-group]
Command=id
TargetGroup={PlTestGlobal.test_username}

[test-act-target-user-and-group]
Command=id
TargetUser={PlTestGlobal.test_username}
TargetGroup=root

[test-act-missing-user]
Command=echo 'test-act-missing-user'
AuthorizedUsers={PlTestGlobal.test_username},nonexistent

[test-act-multi-equals]
Command=echo abc=def

[persistent-users]
User=messagebus
"""
    invalid_filename_test_config_file: str = """[test-act-invalid]
Command=echo 'test-act-invalid'
"""
    # noinspection SpellCheckingInspection
    crash_config_file: str = """[test-act-crash]
Commandecho 'test-act-crash'
"""
    test_username_create_error: bytes \
        = (b"ERROR: privleapd encountered an error while creating a comm "
           b"socket for user '"
           + PlTestGlobal.test_username_bytes
           + b"'!\n")
    privleapd_invalid_response: bytes \
        = b"ERROR: privleapd didn't return a valid response!\n"
    specified_user_missing: bytes \
        = b"ERROR: Specified user does not exist.\n"
    nonexistent_socket_missing: bytes \
        = b"Comm socket does not exist for user 'nonexistent'.\n"
    apt_socket_created: bytes \
        = b"Comm socket created for user '_apt'.\n"
    apt_socket_destroyed: bytes \
        = b"Comm socket destroyed for user '_apt'.\n"
    test_username_socket_created: bytes \
        = (b"Comm socket created for user '"
           + PlTestGlobal.test_username_bytes
           + b"'.\n")
    test_username_socket_destroyed: bytes \
        = (b"Comm socket destroyed for user '"
           + PlTestGlobal.test_username_bytes
           + b"'.\n")
    test_username_socket_missing: bytes \
        = (b"Comm socket does not exist for user '"
           + PlTestGlobal.test_username_bytes
           + b"'.\n")
    test_username_socket_exists: bytes \
        = (b"Comm socket already exists for user '"
           + PlTestGlobal.test_username_bytes
           + b"'.\n")
    privleapd_connection_failed: bytes \
        = b"ERROR: Could not connect to privleapd!\n"
    root_create_error: bytes \
        = (b"ERROR: privleapd encountered an error while creating a "
           + b"comm socket for user 'root'!\n")
    root_socket_created: bytes = b"Comm socket created for user 'root'.\n"
    root_socket_destroyed: bytes = b"Comm socket destroyed for user 'root'.\n"
    leapctl_help: bytes \
= (b"leapctl <--create|--destroy> <user>\n"
+ b"\n"
+ b"    user : The username or UID of the user account to create or destroy a\n"
+ b"           communication socket for.\n"
+ b"    --create : Specifies that leapctl should request a communication "
+ b"socket to\n"
+ b"               be created for the specified user.\n"
+ b"    --destroy : Specifies that leapctl should request a communication "
+ b"socket\n"
+ b"                to be destroyed for the specified user.\n")
    test_act_nonexistent_unauthorized: bytes \
        = (b"ERROR: You are unauthorized to run action "
           + b"'test-act-userrestrict'.\n")
    test_act_grouprestrict_unauthorized: bytes \
        = (b"ERROR: You are unauthorized to run action "
           + b"'test-act-grouprestrict'.\n")
    test_act_multiuser_permit_unauthorized: bytes \
        = (b"ERROR: You are unauthorized to run action "
           + b"'test-act-multiuser-permit'.\n")
    test_act_multigroup_permit_unauthorized: bytes \
        = (b"ERROR: You are unauthorized to run action "
           + b"'test-act-multigroup-permit'.\n")
    test_act_multiuser_multigroup_permit_unauthorized: bytes \
        = (b"ERROR: You are unauthorized to run action "
           + b"'test-act-multiuser-multigroup-permit'.\n")
    test_act_target_user: bytes \
        = (b"uid=1002("
           + PlTestGlobal.test_username_bytes
           + b") gid=1002("
           + PlTestGlobal.test_username_bytes
           + b") groups=1002("
           + PlTestGlobal.test_username_bytes
           + b"),0(root)\n")
    test_act_target_group: bytes \
        = (b"uid=0(root) gid=1002("
           + PlTestGlobal.test_username_bytes
           + b") groups=1002("
           + PlTestGlobal.test_username_bytes
           + b"),0(root)\n")
    test_act_target_user_and_group: bytes \
        = (b"uid=1002("
           + PlTestGlobal.test_username_bytes
           + b") gid=0(root) groups=0(root)\n")
    # noinspection SpellCheckingInspection
    bad_config_file_lines: list[str] = [
        "parse_config_files: CRITICAL: Failed to load config file "
        + "'/etc/privleap/conf.d/crash.conf'!\n",
        "Traceback (most recent call last):\n",
        "ValueError: Invalid config line 'Commandecho 'test-act-crash''\n"
    ]
    control_disconnect_lines: list[str] = [
        "handle_control_session: ERROR: Could not get message from client!\n",
        "Traceback (most recent call last):\n",
        "ConnectionAbortedError: Connection unexpectedly closed\n"
    ]
    control_create_invalid_user_socket_lines: list[str] = [
        "handle_control_create_msg: WARNING: User 'nonexistent' does not "
        + "exist\n"
    ]
    create_invalid_user_socket_and_bail_lines: list[str] = [
        "handle_control_create_msg: WARNING: User 'nonexistent' does not "
        + "exist\n",
        "send_msg_safe: ERROR: Could not send 'CONTROL_ERROR'\n",
        "Traceback (most recent call last):\n",
        "BrokenPipeError: [Errno 32] Broken pipe\n"
    ]
    destroy_invalid_user_socket_lines: list[str] = [
        "handle_control_destroy_msg: INFO: Handled DESTROY message for user "
        + "'nonexistent', socket did not exist\n"
    ]
    create_user_socket_lines: list[str] = [
        "handle_control_create_msg: INFO: Handled CREATE message for user "
        + f"'{PlTestGlobal.test_username}', socket created\n",
        "handle_control_create_msg: INFO: Handled CREATE message for user "
        + f"'{PlTestGlobal.test_username}', socket already exists\n"
    ]
    create_existing_user_socket_and_bail_lines: list[str] = [
        "handle_control_create_msg: INFO: Handled CREATE message for user "
        + f"'{PlTestGlobal.test_username}', socket already exists\n",
        "send_msg_safe: ERROR: Could not send 'EXISTS'\n",
        "BrokenPipeError: [Errno 32] Broken pipe\n"
    ]
    create_blocked_user_socket_lines: list[str] = [
        "handle_control_create_msg: ERROR: Failed to create socket for user "
        + f"'{PlTestGlobal.test_username}'!\n",
        "Traceback (most recent call last):\n",
        "OSError: [Errno 98] Address already in use\n"
    ]
    create_blocked_user_socket_and_bail_lines: list[str] = [
        "handle_control_create_msg: ERROR: Failed to create socket for "
        + f"user '{PlTestGlobal.test_username}'!\n",
        "Traceback (most recent call last):\n",
        "OSError: [Errno 98] Address already in use\n",
        "send_msg_safe: ERROR: Could not send 'CONTROL_ERROR'\n",
        "OSError: [Errno 98] Address already in use\n",
        "During handling of the above exception, another exception "
        + "occurred:\n",
        "Traceback (most recent call last):\n",
        "BrokenPipeError: [Errno 32] Broken pipe\n",
        ]
    destroy_missing_user_socket_lines: list[str] = [
        "handle_control_destroy_msg: WARNING: Handling DESTROY, no socket to "
        + f"delete at '/run/privleapd/comm/{PlTestGlobal.test_username}'\n",
        "handle_control_destroy_msg: INFO: Handled DESTROY message for user "
        + f"'{PlTestGlobal.test_username}', socket destroyed\n"
    ]
    destroy_user_socket_and_bail_lines: list[str] = [
        "handle_control_destroy_msg: INFO: Handled DESTROY message for "
        + f"user '{PlTestGlobal.test_username}', socket destroyed\n",
        "send_msg_safe: ERROR: Could not send 'OK'\n",
        "Traceback (most recent call last):\n",
        "BrokenPipeError: [Errno 32] Broken pipe\n"
    ]
    privleapd_verify_not_running_twice_fail: bytes \
        = (b"verify_not_running_twice: CRITICAL: Cannot run two "
           + b"privleapd processes at the same time!\n")
    privleapd_ensure_running_as_root_fail: bytes \
        = b"ensure_running_as_root: CRITICAL: privleapd must run as root!\n"
    test_act_invalid_unauthorized: bytes \
        = b"ERROR: You are unauthorized to run action 'test-act-invalid'.\n"
    destroy_bad_user_socket_and_bail_lines: list[str] = [
        "handle_control_destroy_msg: INFO: Handled DESTROY message for user "
        + f"'{PlTestGlobal.test_username}', socket did not exist\n",
        "send_msg_safe: ERROR: Could not send 'NOUSER'\n",
        "Traceback (most recent call last):\n",
        "BrokenPipeError: [Errno 32] Broken pipe\n"
    ]
    send_invalid_control_message_lines: list[str] = [
        "handle_control_session: ERROR: Could not get message from client!\n",
        "Traceback (most recent call last):\n",
        "ValueError: Invalid message type 'BOB' for socket\n"
    ]
    send_corrupted_control_message_lines: list[str] = [
        "handle_control_session: ERROR: Could not get message from client!\n",
        "Traceback (most recent call last):\n",
        "ValueError: recv_buf contains data past the last string\n"
    ]
    bail_comm_lines: list[str] = [
        "get_signal_msg: ERROR: Could not get message from client!\n",
        "Traceback (most recent call last):\n",
        "ConnectionAbortedError: Connection unexpectedly closed\n"
    ]
    send_invalid_comm_message_lines: list[str] = [
        "get_signal_msg: ERROR: Could not get message from client!\n",
        "Traceback (most recent call last):\n",
        "ValueError: Invalid message type 'BOB' for socket\n"
    ]
    send_nonexistent_signal_and_bail_lines_part1: list[str] = [
        "auth_signal_request: WARNING: Could not find action 'nonexistent'\n",
    ]
    unauthorized_broken_pipe_lines: list[str] = [
        "send_msg_safe: ERROR: Could not send 'UNAUTHORIZED'\n",
        "Traceback (most recent call last):\n",
        "BrokenPipeError: [Errno 32] Broken pipe\n"
    ]
    send_userrestrict_signal_and_bail_lines_part1: list[str] = [
        f"auth_signal_request: WARNING: User '{PlTestGlobal.test_username}' is "
        + "not authorized to run action 'test-act-userrestrict'\n",
    ]
    send_grouprestrict_signal_and_bail_lines_part1: list[str] = [
        f"auth_signal_request: WARNING: User '{PlTestGlobal.test_username}' is "
        + "not authorized to run action 'test-act-grouprestrict'\n",
    ]
    send_invalid_bash_signal_lines: list[str] = [
        "handle_comm_session: INFO: Triggered action 'test-act-invalid-bash'\n",
        "send_action_results: INFO: Action 'test-act-invalid-bash' completed\n"
    ]
    send_valid_signal_and_bail_lines: list[str] = [
        "handle_comm_session: INFO: Triggered action 'test-act-free'\n",
        "send_msg_safe: ERROR: Could not send 'TRIGGER'\n",
        "BrokenPipeError: [Errno 32] Broken pipe\n"
    ]
    send_random_garbage_lines: list[str] = [
        "get_signal_msg: ERROR: Could not get message from client!\n",
    ]
    invalid_ascii_list: list[bytes] = [
        b"\x00\x00\x00\x05\x1BTEST",
        b"\x00\x00\x00\x05TEST\x1B",
        b"\x00\x00\x00\x05TE\x1BST",
        b"\x00\x00\x00\x05\x1FTEST",
        b"\x00\x00\x00\x05TEST\x1F",
        b"\x00\x00\x00\x05TE\x1FST",
        b"\x00\x00\x00\x05\x7FTEST",
        b"\x00\x00\x00\x05TEST\x7F",
        b"\x00\x00\x00\x05TE\x7FST",
        b"\x00\x00\x00\x04TEST",
        b"\x00\x00\x00\x0ESIGNAL PARAM1\x1B",
        b"\x00\x00\x00\x0ESIGNAL \x1BPARAM1",
        b"\x00\x00\x00\x0ESIGNAL PAR\x1BAM1",
        b"\x00\x00\x00\x0ESIGNAL PARAM1\x1F",
        b"\x00\x00\x00\x0ESIGNAL \x1FPARAM1",
        b"\x00\x00\x00\x0ESIGNAL PAR\x1BAM1",
        b"\x00\x00\x00\x0ESIGNAL PARAM1\x1F",
        b"\x00\x00\x00\x0ESIGNAL \x7FPARAM1",
        b"\x00\x00\x00\x0ESIGNAL PAR\x7FAM1",
        b"\x00\x00\x00\x0DSIGNAL PARAM1",
        b"\x00\x00\x00\x0ESIGNAL  PARAM1"
    ]
    # TODO: Any good way to avoid all the repetition?
    invalid_ascii_lines_list: list[list[str]] = [
        [ "get_signal_msg: ERROR: Could not get message from client!\n",
          "Traceback (most recent call last):\n",
          "ValueError: Invalid byte found in ASCII string data\n" ],
        [ "get_signal_msg: ERROR: Could not get message from client!\n",
          "Traceback (most recent call last):\n",
          "ValueError: Invalid byte found in ASCII string data\n" ],
        [ "get_signal_msg: ERROR: Could not get message from client!\n",
          "Traceback (most recent call last):\n",
          "ValueError: Invalid byte found in ASCII string data\n" ],
        [ "get_signal_msg: ERROR: Could not get message from client!\n",
          "Traceback (most recent call last):\n",
          "ValueError: Invalid byte found in ASCII string data\n" ],
        [ "get_signal_msg: ERROR: Could not get message from client!\n",
          "Traceback (most recent call last):\n",
          "ValueError: Invalid byte found in ASCII string data\n" ],
        [ "get_signal_msg: ERROR: Could not get message from client!\n",
          "Traceback (most recent call last):\n",
          "ValueError: Invalid byte found in ASCII string data\n" ],
        [ "get_signal_msg: ERROR: Could not get message from client!\n",
          "Traceback (most recent call last):\n",
          "ValueError: Invalid byte found in ASCII string data\n" ],
        [ "get_signal_msg: ERROR: Could not get message from client!\n",
          "Traceback (most recent call last):\n",
          "ValueError: Invalid byte found in ASCII string data\n" ],
        [ "get_signal_msg: ERROR: Could not get message from client!\n",
          "Traceback (most recent call last):\n",
          "ValueError: Invalid byte found in ASCII string data\n" ],
        [ "get_signal_msg: ERROR: Could not get message from client!\n",
          "Traceback (most recent call last):\n",
          "ValueError: Invalid message type 'TEST' for socket\n" ],
        [ "get_signal_msg: ERROR: Could not get message from client!\n",
          "Traceback (most recent call last):\n",
          "ValueError: Invalid byte found in ASCII string data\n" ],
        [ "get_signal_msg: ERROR: Could not get message from client!\n",
          "Traceback (most recent call last):\n",
          "ValueError: Invalid byte found in ASCII string data\n" ],
        [ "get_signal_msg: ERROR: Could not get message from client!\n",
          "Traceback (most recent call last):\n",
          "ValueError: Invalid byte found in ASCII string data\n" ],
        [ "get_signal_msg: ERROR: Could not get message from client!\n",
          "Traceback (most recent call last):\n",
          "ValueError: Invalid byte found in ASCII string data\n" ],
        [ "get_signal_msg: ERROR: Could not get message from client!\n",
          "Traceback (most recent call last):\n",
          "ValueError: Invalid byte found in ASCII string data\n" ],
        [ "get_signal_msg: ERROR: Could not get message from client!\n",
          "Traceback (most recent call last):\n",
          "ValueError: Invalid byte found in ASCII string data\n" ],
        [ "get_signal_msg: ERROR: Could not get message from client!\n",
          "Traceback (most recent call last):\n",
          "ValueError: Invalid byte found in ASCII string data\n" ],
        [ "get_signal_msg: ERROR: Could not get message from client!\n",
          "Traceback (most recent call last):\n",
          "ValueError: Invalid byte found in ASCII string data\n" ],
        [ "get_signal_msg: ERROR: Could not get message from client!\n",
          "Traceback (most recent call last):\n",
          "ValueError: Invalid byte found in ASCII string data\n" ],
        [ "auth_signal_request: WARNING: Could not find action 'PARAM1'\n" ],
        [ "get_signal_msg: ERROR: Could not get message from client!\n",
          "Traceback (most recent call last):\n",
          "ValueError: recv_buf contains data past the last string\n" ]
    ]
