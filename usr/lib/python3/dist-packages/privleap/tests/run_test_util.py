#!/usr/bin/python3 -su

## Copyright (C) 2025 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught,too-few-public-methods,too-many-lines
# Rationale:
#   broad-exception-caught: We use broad exception catching for general-purpose
#     error handlers.
#   too-few-public-methods: Global variable class uses no methods intentionally.
#   too-many-lines: Splitting this up is not a priority at the moment.

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
from typing import IO, Callable
from datetime import datetime, timedelta


class PlTestGlobal:
    """
    Global variables for privleap tests.
    """

    linebuf: str = ""
    privleap_conf_base_dir: Path = Path("/etc/privleap")
    privleap_conf_dir: Path = Path(f"{privleap_conf_base_dir}/conf.d")
    privleap_system_local_conf_dir: Path = Path(
        "/usr/local/etc/privleap/conf.d"
    )
    privleapd_proc: subprocess.Popen[str] | None = None
    privleapd_test_ready_file: Path = Path("/tmp/privleapd-ready-for-test")
    privleap_state_dir: Path = Path("/run/privleapd")
    privleap_state_comm_dir: Path = Path(privleap_state_dir, "comm")
    base_delay: float = 0.1
    privleapd_running: bool = False
    no_service_handling = False
    all_asserts_passed = True
    multithreading_test_unexpected_stderr = False
    multithreading_test_monitor_stop = False


def proc_try_readline(
    proc: subprocess.Popen[str], timeout: float, read_stderr: bool = False
) -> str | None:
    """
    Reads a line of test from the stdout or stderr of a process. Allows
    specifying a timeout for bailing out early. The stdout (or stderr) of the
    process must be in non-blocking mode.
    """

    assert proc.stdout is not None
    assert proc.stderr is not None

    # If there's a line already in the buffer, find and return it.
    if "\n" in PlTestGlobal.linebuf:
        linebuf_parts: list[str] = PlTestGlobal.linebuf.split("\n", maxsplit=1)
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
    end_time = current_time + timedelta(seconds=timeout)
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
        time.sleep(0.0001)

    # Retrieve a line from the buffer and return it.
    linebuf_parts = PlTestGlobal.linebuf.split("\n", maxsplit=1)
    if len(linebuf_parts) == 2:
        PlTestGlobal.linebuf = linebuf_parts[1]
        return linebuf_parts[0] + "\n"

    # If there was no line to retrieve, return None.
    return None


def ensure_running_as_root() -> None:
    """
    Ensures the test is running as root. The tests cannot function when
    running as a standard user as they have to execute commands as root.
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
        logging.critical(
            "Path '%s' contains a non-dir at '%s'!", str(path), str(path)
        )
        sys.exit(1)
    for parent_path in path.parents:
        if parent_path.exists() and not parent_path.is_dir():
            logging.critical(
                "Path '%s' contains a non-dir at '%s'!",
                str(path),
                str(parent_path),
            )
            sys.exit(1)


def setup_test_account(test_username: str, test_home_dir: Path) -> None:
    """
    Ensures the user account used by the test script exists and is properly
    configured.
    """

    user_name_list: list[str] = [p.pw_name for p in pwd.getpwall()]
    if test_username not in user_name_list:
        try:
            subprocess.run(["useradd", "-m", test_username], check=True)
        except Exception as e:
            logging.critical(
                "Could not create account '%s'!", test_username, exc_info=e
            )
            sys.exit(1)
    user_gid: int = pwd.getpwnam(test_username).pw_gid
    group_list: list[str] = [
        grp.getgrgid(gid).gr_name
        for gid in os.getgrouplist(test_username, user_gid)
    ]
    for additional_group in ("sudo", "privleap"):
        if not additional_group in group_list:
            try:
                subprocess.run(
                    ["adduser", test_username, additional_group],
                    check=True,
                )
            except Exception as e:
                logging.critical(
                    "Could not add account '%s' to group '%s'!",
                    test_username,
                    additional_group,
                    exc_info=e,
                )
                sys.exit(1)
    ensure_path_lacks_files(test_home_dir)
    if not test_home_dir.exists():
        test_home_dir.mkdir(parents=True)
        shutil.chown(test_home_dir, user=test_username, group=test_username)


def erase_old_privleap_config() -> None:
    """
    Wipes the existing privleap configuration dirs and creates new empty ones.
    """

    ## This dir should always exist. If we can't remove it, that's an error.
    shutil.rmtree(PlTestGlobal.privleap_conf_dir)

    ## This dir probably won't exist yet though.
    try:
        shutil.rmtree(PlTestGlobal.privleap_system_local_conf_dir)
    except FileNotFoundError:
        pass

    PlTestGlobal.privleap_conf_dir.mkdir(parents=True, exist_ok=False)
    PlTestGlobal.privleap_system_local_conf_dir.mkdir(
        parents=True, exist_ok=False
    )


def stop_privleapd_service() -> None:
    """
    Stops the privleapd service. This must be called before testing starts.
    """

    if PlTestGlobal.no_service_handling:
        return
    try:
        subprocess.run(["systemctl", "stop", "privleapd"], check=True)
    except Exception as e:
        logging.critical("Could not stop privleapd service!", exc_info=e)
        sys.exit(1)


def check_privleapd_error_output(expected_error_output: list[str]) -> None:
    """
    Checks early error output from privleapd to ensure it matches the expected
    output. The test bails out if the check fails.
    """

    assert PlTestGlobal.privleapd_proc is not None
    for expected_error_line in expected_error_output:
        early_privleapd_output = proc_try_readline(
            PlTestGlobal.privleapd_proc,
            PlTestGlobal.base_delay,
            read_stderr=True,
        )
        if early_privleapd_output is None:
            logging.critical(
                "privleapd did not return an expected error message "
                "at startup! Expected message: '%s'",
                expected_error_line,
            )
            sys.exit(1)
        if early_privleapd_output != expected_error_line:
            logging.critical(
                "privleapd returned an unexpected error message at "
                + "startup! Expected message: '%s', actual message: "
                + "'%s'",
                expected_error_line,
                early_privleapd_output,
            )
            sys.exit(1)


def start_privleapd_subprocess(
    extra_args: list[str],
    allow_error_output: bool = False,
    expected_error_output: list[str] | None = None,
) -> None:
    """
    Launches privleapd as a subprocess so its output can be monitored by the
    tester.
    """

    try:
        # pylint: disable=consider-using-with
        # Rationale:
        #   consider-using-with: "with" is not suitable for the architecture of
        #   this script in this scenario.
        full_args: list[str] = ["/usr/bin/privleapd", "--test"]
        for arg in extra_args:
            full_args.append(arg)
        PlTestGlobal.privleapd_proc = subprocess.Popen(
            full_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
        )
    except Exception as e:
        logging.critical("Could not start privleapd server!", exc_info=e)
    assert PlTestGlobal.privleapd_proc is not None
    assert PlTestGlobal.privleapd_proc.stdout is not None
    assert PlTestGlobal.privleapd_proc.stderr is not None
    fcntl.fcntl(
        PlTestGlobal.privleapd_proc.stdout.fileno(),
        fcntl.F_SETFL,
        os.O_NONBLOCK,
    )
    fcntl.fcntl(
        PlTestGlobal.privleapd_proc.stderr.fileno(),
        fcntl.F_SETFL,
        os.O_NONBLOCK,
    )
    early_privleapd_output: str | None
    if allow_error_output:
        time.sleep(PlTestGlobal.base_delay * 2)
        if expected_error_output is not None:
            check_privleapd_error_output(expected_error_output)
    else:
        privleapd_started_checks = 0
        privleapd_start_failed = False
        while not PlTestGlobal.privleapd_test_ready_file.exists():
            if privleapd_started_checks >= 10:
                logging.critical("privleapd failed to start!")
                privleapd_start_failed = True
                break
            time.sleep(PlTestGlobal.base_delay)
            privleapd_started_checks += 1
        early_privleapd_output = proc_try_readline(
            PlTestGlobal.privleapd_proc,
            PlTestGlobal.base_delay,
            read_stderr=True,
        )
        if early_privleapd_output is not None:
            logging.critical("privleapd returned error messages at startup!")
            while True:
                logging.critical(early_privleapd_output)
                early_privleapd_output = proc_try_readline(
                    PlTestGlobal.privleapd_proc,
                    PlTestGlobal.base_delay,
                    read_stderr=True,
                )
                if early_privleapd_output is None:
                    break
            sys.exit(1)
        elif privleapd_start_failed:
            sys.exit(1)
    PlTestGlobal.privleapd_test_ready_file.unlink(missing_ok=True)
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
        logging.critical("Could not kill privleapd!", exc_info=e)
    time.sleep(PlTestGlobal.base_delay)
    PlTestGlobal.privleapd_running = False


def assert_command_result(
    command_data: list[str],
    exit_code: int,
    stdout_data: bytes = b"",
    stderr_data: bytes = b"",
    filter_func: Callable[[bytes, bool], bytes] | None = None,
) -> bool:
    """
    Runs a command and ensures that the stdout, stderr, and exitcode match
    expected values.
    """

    should_capture_output: bool = True
    if stdout_data == b"" and stderr_data == b"":
        should_capture_output = False
    if not should_capture_output and filter_func is not None:
        logging.error(
            "Cannot specify filter_func without specifying "
            + "stdout_data or stderr_data!"
        )
        sys.exit(1)
    test_result: subprocess.CompletedProcess[bytes] = subprocess.run(
        command_data, check=False, capture_output=should_capture_output
    )
    logging.info("Ran command: %s", command_data)
    logging.info("Exit code: %s", test_result.returncode)
    logging.info("Stdout: %s", test_result.stdout)
    logging.info("Stderr: %s", test_result.stderr)
    assert_failed: bool = False
    stdout_result: bytes
    stderr_result: bytes
    if not should_capture_output:
        stdout_result = b""
        stderr_result = b""
    elif filter_func is None:
        stdout_result = test_result.stdout
        stderr_result = test_result.stderr
    else:
        stdout_result = filter_func(test_result.stdout, True)
        stderr_result = filter_func(test_result.stderr, False)
        logging.info("Filtered stdout: %s", stdout_result)
        logging.info("Filtered stderr: %s", stderr_result)
    if exit_code != test_result.returncode:
        logging.error("Exit code assert failed, expected: %s", exit_code)
        assert_failed = True
    if stdout_data != stdout_result:
        logging.error("Stdout assert failed, expected: %s", stdout_data)
        assert_failed = True
    if stderr_data != stderr_result:
        logging.error("Stderr assert failed, expected: %s", stderr_data)
        assert_failed = True
    if assert_failed:
        return False
    return True


def write_privleap_test_config() -> None:
    """
    Writes test privleap config data. Includes one legitimate config file, one
    empty file, and one file that contains only comments. Also creates the
    secondary configuration directory so that notices about it not existing
    don't appear in most instances.
    """

    with open(
        Path(PlTestGlobal.privleap_conf_dir, "unit-test.conf"),
        "w",
        encoding="utf-8",
    ) as config_file:
        config_file.write(PlTestData.primary_test_config_file)
    with open(
        Path(PlTestGlobal.privleap_conf_dir, "comment-only.conf"),
        "w",
        encoding="utf-8",
    ) as config_file:
        config_file.write(PlTestData.comment_only_config_file)
    with open(
        Path(PlTestGlobal.privleap_conf_dir, "empty.conf"),
        "w",
        encoding="utf-8",
    ) as config_file:
        config_file.write("\n")
    Path("/usr/local/etc/privleap/conf.d").mkdir(parents=True, exist_ok=True)


def compare_privleapd_stderr(
    assert_line_list: list[str], quiet: bool = False
) -> bool:
    """
    Compares the stderr output of privleapd with a string list, testing to see
    if each expected line has a corresponding returned line. The list of
    expected lines may omit arbitrary output lines.
    """

    assert PlTestGlobal.privleapd_proc is not None
    result_good: bool = True
    read_lines: list[str] = []
    for line in assert_line_list:
        while True:
            proc_line = proc_try_readline(
                PlTestGlobal.privleapd_proc,
                PlTestGlobal.base_delay,
                read_stderr=True,
            )
            if proc_line is None:
                result_good = False
                break
            read_lines.append(proc_line)
            if proc_line != line:
                continue
            # If we get this far, line == proc_line
            break
    while True:
        proc_line = proc_try_readline(
            PlTestGlobal.privleapd_proc,
            PlTestGlobal.base_delay,
            read_stderr=True,
        )
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
            proc_line = proc_try_readline(
                PlTestGlobal.privleapd_proc,
                PlTestGlobal.base_delay,
                read_stderr=True,
            )
            if proc_line is None:
                break


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

    primary_test_config_file: str = """[action:test-act-free]
Command=echo 'test-act-free'
AuthorizedUsers=privleaptestone

[persistent-users]
# UID 3 = sys
User=3

[action:test-act-userrestrict]
Command=echo 'test-act-userrestrict'
AuthorizedUsers=sys

[action:test-act-grouprestrict]
Command=echo 'test-act-grouprestrict'
AuthorizedGroups=sys

[action:test-act-grouppermit-userrestrict]
Command=echo 'test-act-grouppermit-userrestrict'
AuthorizedUsers=sys
AuthorizedGroups=privleaptestone

[allowed-users]
User=privleaptestone
User=_apt
User=daemon
User=deleteme
User=root
Group=privleap
Group=idontexist

[action:test-act-grouprestrict-userpermit]
Command=echo 'test-act-grouprestrict-userpermit'
AuthorizedUsers=privleaptestone
AuthorizedGroups=sys

[action:test-act-userpermit]
Command=echo 'test-act-userpermit'
AuthorizedUsers=privleaptestone

[action:test-act-privleap-grouppermit]
Command=echo 'test-act-privleap-grouppermit'
AuthorizedGroups=privleap

[persistent-users]
User=bin
User=uucp

[action:test-act-grouppermit]
Command=echo 'test-act-grouppermit'
AuthorizedGroups=privleaptestone

[action:test-act-grouppermit-userpermit]
Command=echo 'test-act-grouppermit-userpermit'
AuthorizedUsers=privleaptestone
AuthorizedGroups=privleaptestone

# Not all groups have a corresponding username, this tests that edge case
[action:test-act-sudopermit]
Command=echo 'test-act-sudopermit'
AuthorizedGroups=sudo

[action:test-act-multiuser-permit]
Command=echo 'test-act-multiuser-permit'
AuthorizedUsers=privleaptestone,3,messagebus

[action:test-act-multigroup-permit]
Command=echo 'test-act-multigroup-permit'
AuthorizedGroups=privleaptestone,3,messagebus

[action:test-act-multiuser-multigroup-permit]
Command=echo 'test-act-multiuser-multigroup-permit'
AuthorizedUsers=privleaptestone,sys
AuthorizedGroups=sys,messagebus

[action:test-act-exit240]
Command=echo 'test-act-exit240'; exit 240
AuthorizedUsers=privleaptestone

[action:test-act-stderr]
Command=1>&2 echo 'test-act-stderr'
AuthorizedUsers=privleaptestone

[action:test-act-stdout-stderr-interleaved]
Command=echo 'stdout00'; 1>&2 echo 'stderr00'; echo 'stdout01'; 1>&2 echo 'stderr01'
AuthorizedUsers=privleaptestone

[action:test-act-invalid-bash]
Command=ahem, this will not work
AuthorizedUsers=privleaptestone

[action:test-act-target-user]
Command=id
TargetUser=privleaptestone
AuthorizedUsers=privleaptestone

[action:test-act-target-group]
Command=id
TargetGroup=privleaptestone
AuthorizedUsers=root

[action:test-act-target-user-and-group]
Command=id
AuthorizedUsers=privleaptestone
TargetUser=privleaptestone
TargetGroup=root

[action:test-act-missing-user]
Command=echo 'test-act-missing-user'
AuthorizedUsers=privleaptestone,nonexistent

[action:test-act-multi-equals]
Command=echo abc=def
AuthorizedUsers=privleaptestone

[action:test-act-rootdata]
Command=pwd; id; env
AuthorizedUsers=privleaptestone

[action:test-act-userdata]
Command=pwd; id; env
AuthorizedUsers=privleaptestone
TargetUser=privleaptestone

[action:test-act-noreturn]
Command=sleep infinity
AuthorizedUsers=privleaptestone

[action:test-act-interrupt]
Command=fn() { touch /test-act-interrupt; }; trap fn TERM; sleep infinity & wait $!
AuthorizedUsers=privleaptestone

[action:test-act-anyone]
Command=echo 'test-act-anyone'
AuthorizedUsers=privleaptestone,privleaptesttwo,privleaptestthree,privleaptestfour,privleaptestfive,privleaptestsix,privleaptestseven,privleaptesteight,privleaptestnine,privleaptestten

[expected-disallowed-users]
User=irc
User=news

[persistent-users]
User=messagebus
"""
    comment_only_config_file: str = """# this is a comment
# and so is this
"""
    invalid_filename_test_config_file: str = """[action:test-act-invalid]
Command=echo 'test-act-invalid'
AuthorizedUsers=root
"""
    # noinspection SpellCheckingInspection
    crash_config_file: str = """[action:test-act-crash]
Commandecho 'test-act-crash'
AuthorizedUsers=root
"""
    duplicate_action_config_file: str = """[action:test-act-sudopermit]
Command=echo 'duplicate-test-act-sudopermit'
AuthorizedGroups=sudo
"""
    wrongorder_config_file: str = """Command=echo 'test-act-wrongorder'
[action:test-act-wrongorder]
AuthorizedUsers=root
"""
    duplicate_keys_config_file: str = """[action:test-act-dupkeys]
Command=echo 'test-act-dupkeys'
Command=echo 'oops'
AuthorizedUsers=root
"""
    absent_command_directive_config_file: str = """[action:test-act-notabsent]
Command=echo 'test-act-notabsent'
AuthorizedUsers=root

[action:test-act-absent]
# Command=echo 'test-act-absent'
"""
    invalid_action_config_file: str = """[action:test-@ct-invalidaction]
Command=echo 'test-@ct-invalidaction'
AuthorizedUsers=root
"""
    added_actions_config_file: str = """[action:test-act-added1]
Command=echo 'test-act-added1'
AuthorizedUsers=privleaptestone

[action:test-act-added2]
Command=echo 'test-act-added2'
AuthorizedUsers=privleaptestone
"""
    added_actions_bad_config_file: str = """[action:test-act-added1]
Command=echo 'test-act-added1'
AuthorizedUsers=privleaptestone

[action:test-act-added2]
Command=echo 'test-act-added2'
AuthorizedUsers=privleaptestone

[action:test-act-added-bad]
Commandecho 'test-act-added-bad'
AuthorizedUsers=privleaptestone
"""
    bad_target_ident_config_file: str = """[action:test-act-bad-target-user]
Command=echo 'bad-target-user'
AuthorizedUsers=privleaptestone
TargetUser=idontexist1

[action:test-act-bad-target-group]
Command=echo 'bad-target-group'
AuthorizedUsers=privleaptestone
TargetGroup=idontexist2
"""
    unrecognized_header_config_file: str = """[unrecognized-header]
Command=echo 'unrecognized-header'
AuthorizedUsers=root
"""
    missing_auth_config_file: str = """[action:test-act-missing-auth]
Command=echo 'test-act-missing-auth'
"""
    nonexistent_restrict_config_file: str = """\
[action:test-act-nonexistent-restrict]
Command=echo 'test-act-nonexistent-restrict'
AuthorizedUsers=nonexistent
"""
    system_local_config_file: str = """\
[action:test-act-system-local]
Command=echo 'test-act-system-local'
AuthorizedUsers=privleaptestone
"""
    new_persistent_users_config_file: str = """\
[persistent-users]
User=privleaptesttwo
User=privleaptestthree
"""
    privleaptestone_create_error: bytes = (
        b"ERROR: privleapd encountered an error while creating a comm "
        b"socket for account 'privleaptestone'!\n"
    )
    privleapd_invalid_response: bytes = (
        b"ERROR: privleapd didn't return a valid response!\n"
    )
    privleapd_invalid_msg_seq: bytes = (
        b"ERROR: privleapd didn't return a valid message sequence!\n"
    )
    privleapd_midaction_cutoff: bytes = (
        b"ERROR: Action triggered, but privleapd closed the connection "
        + b"before sending all output!\n"
    )
    specified_user_missing: bytes = (
        b"ERROR: Specified account 'nonexistent' does not exist.\n"
    )
    nonexistent_socket_missing: bytes = (
        b"Comm socket does not exist for account 'nonexistent'.\n"
    )
    apt_socket_created: bytes = b"Comm socket created for account '_apt'.\n"
    apt_socket_destroyed: bytes = b"Comm socket destroyed for account '_apt'.\n"
    privleaptestone_socket_created: bytes = (
        b"Comm socket created for account 'privleaptestone'.\n"
    )
    privleaptestone_socket_destroyed: bytes = (
        b"Comm socket destroyed for account 'privleaptestone'.\n"
    )
    privleaptestone_socket_missing: bytes = (
        b"Comm socket does not exist for account 'privleaptestone'.\n"
    )
    privleaptestone_socket_exists: bytes = (
        b"Comm socket already exists for account 'privleaptestone'.\n"
    )
    privleapd_connection_failed: bytes = (
        b"ERROR: Could not connect to privleapd!\n"
    )
    root_create_error: bytes = (
        b"ERROR: privleapd encountered an error while creating a "
        b"comm socket for account 'root'!\n"
    )
    root_socket_created: bytes = b"Comm socket created for account 'root'.\n"
    root_socket_destroyed: bytes = (
        b"Comm socket destroyed for account 'root'.\n"
    )
    daemon_socket_created: bytes = (
        b"Comm socket created for account 'daemon'.\n"
    )
    daemon_socket_destroyed: bytes = (
        b"Comm socket destroyed for account 'daemon'.\n"
    )
    cannot_destroy_persistent_sys_socket: bytes = (
        b"Cannot destroy socket for persistent account 'sys'.\n"
    )
    deleteme_socket_created: bytes = (
        b"Comm socket created for account 'deleteme'.\n"
    )
    deleteme_socket_destroyed: bytes = (
        b"Comm socket destroyed for account 'XXX_DELETEME_UID_XXX'.\n"
    )
    man_socket_not_permitted: bytes = (
        b"ERROR: Account 'man' is not permitted to have a comm socket!\n"
    )
    irc_expected_socket_not_permitted: bytes = (
        b"Account 'irc' is not permitted to have a comm socket, as expected, "
        b"ok.\n"
    )
    news_expected_socket_not_permitted: bytes = (
        b"Account 'news' is not permitted to have a comm socket, as "
        b"expected, ok.\n"
    )
    privleaptesttwo_socket_created: bytes = (
        b"Comm socket created for account 'privleaptesttwo'.\n"
    )
    privleaptesttwo_socket_destroyed: bytes = (
        b"Comm socket destroyed for account 'privleaptesttwo'.\n"
    )
    privleaptesttwo_socket_not_permitted: bytes = (
        b"ERROR: Account 'privleaptesttwo' is not permitted to have a comm socket!\n"
    )
    privleaptestthree_socket_created: bytes = (
        b"Comm socket created for account 'privleaptestthree'.\n"
    )
    leapctl_help: bytes = (
        b"leapctl <--create|--destroy> <user>\n"
        + b"leapctl --reload\n"
        + b"\n"
        + b"     --create : Specifies that leapctl should request a communication "
        + b"socket to\n"
        + b"                be created for the specified user account.\n"
        + b"    --destroy : Specifies that leapctl should request a communication "
        + b"socket\n"
        + b"                to be destroyed for the specified user account.\n"
        + b"     --reload : Instructs privleapd to reload configuration without "
        + b"restarting.\n"
        + b"         user : The username or UID of the user account to create "
        + b"or destroy a\n"
        + b"                communication socket for.\n"
    )
    leaprun_help: bytes = (
        b"leaprun [-c|--check] <action_name1> [<action_name2> ...]\n"
        + b"\n"
        + b"     -c, --check : Check if the current user is authorized to "
        + b"run an action.\n"
        + b"    action_name1 : The name of the action leaprun should handle. "
        + b"leaprun will\n"
        + b"                   send a signal to trigger the named action (or "
        + b"will ask\n"
        + b"                   privleapd to check if the user can trigger "
        + b"the action).\n"
        + b"                   If using -c or --check, up to 63 action names "
        + b"can be passed\n"
        + b"                   to check them all at once.\n"
    )
    privleapd_run_request_failed: bytes = (
        b"ERROR: Could not request privleapd to run action 'test-act-free'!\n"
    )
    privleapd_check_query_failed: bytes = (
        b"ERROR: Could not query privleapd for authorization to run actions "
        + b"'test-act-free', 'test-act-grouppermit-userrestrict', "
        + b"'test-act-grouprestrict-userpermit'!\n"
    )
    privleapd_multi_unauthorized: bytes = (
        b"ERROR: privleapd returned two 'UNAUTHORIZED' messages in the same "
        + b"session!\n"
    )
    privleapd_unauth_after_trigger: bytes = (
        b"ERROR: privleapd returned an 'UNAUTHORIZED' message after having "
        + b"sent a 'TRIGGER' message!\n"
    )
    privleapd_auth_during_exec: bytes = (
        b"ERROR: privleapd returned an 'AUTHORIZED' message when leaprun was "
        + b"not in check mode!\n"
    )
    privleapd_multi_authorized: bytes = (
        b"ERROR: privleapd returned two 'AUTHORIZED' messages in the same "
        + b"session!\n"
    )
    privleapd_unexpected_access_check_end = (
        b"ERROR: privleapd returned an 'ACCESS_CHECK_RESULTS_END' message "
        + b"when leaprun was not in check mode!\n"
    )
    privleapd_access_check_end_before_results = (
        b"ERROR: privleapd returned an 'ACCESS_CHECK_RESULTS_END' message "
        + b"before sending an 'AUTHORIZED' or 'UNAUTHORIZED' message!\n"
    )
    privleapd_trigger_error_during_check = (
        b"ERROR: privleapd returned a 'TRIGGER_ERROR' message when leaprun "
        + b"was in check mode!\n"
    )
    privleapd_multi_trigger = (
        b"ERROR: privleapd returned two 'TRIGGER' messages in the same "
        + b"session!\n"
    )
    privleapd_trigger_during_check = (
        b"ERROR: privleapd returned a 'TRIGGER' message when leaprun was "
        + b"in check mode!\n"
    )
    privleapd_result_stdout_before_trigger = (
        b"ERROR: privleapd returned a 'RESULT_STDOUT' message before a "
        + b"'TRIGGER' message!\n"
    )
    privleapd_result_stderr_before_trigger = (
        b"ERROR: privleapd returned a 'RESULT_STDERR' message before a "
        + b"'TRIGGER' message!\n"
    )
    privleapd_result_exitcode_before_trigger = (
        b"ERROR: privleapd returned a 'RESULT_EXITCODE' message before a "
        + b"'TRIGGER' message!\n"
    )
    test_act_free_authorized: bytes = (
        b"Account 'privleaptestone' (1002) is authorized to run action "
        + b"'test-act-free'.\n"
    )
    test_act_multi_auth: bytes = (
        b"Account 'privleaptestone' (1002) is authorized to run action "
        + b"'test-act-free'.\n"
        + b"Account 'privleaptestone' (1002) is authorized to run action "
        + b"'test-act-grouppermit-userrestrict'.\n"
    )
    test_act_multi_unauth: bytes = (
        b"ERROR: Account 'privleaptestone' (1002) is unauthorized to run "
        + b"action 'test-act-nonsenseabc'.\n"
        + b"ERROR: Account 'privleaptestone' (1002) is unauthorized to run "
        + b"action 'test-act-nonsensedef'.\n"
    )
    test_act_userrestrict_unauthorized: bytes = (
        b"ERROR: Account 'privleaptestone' (1002) is unauthorized to run "
        + b"action 'test-act-userrestrict'.\n"
    )
    test_act_grouprestrict_unauthorized: bytes = (
        b"ERROR: Account 'privleaptestone' (1002) is unauthorized to run "
        + b"action 'test-act-grouprestrict'.\n"
    )
    test_act_multiuser_permit_unauthorized: bytes = (
        b"ERROR: Account 'bin' (2) is unauthorized to run action "
        b"'test-act-multiuser-permit'.\n"
    )
    test_act_multigroup_permit_unauthorized: bytes = (
        b"ERROR: Account 'bin' (2) is unauthorized to run action "
        b"'test-act-multigroup-permit'.\n"
    )
    test_act_multiuser_multigroup_permit_unauthorized: bytes = (
        b"ERROR: Account 'bin' (2) is unauthorized to run action "
        b"'test-act-multiuser-multigroup-permit'.\n"
    )
    test_act_nonexistent_unauthorized: bytes = (
        b"ERROR: Account 'privleaptestone' (1002) is unauthorized to run "
        + b"action 'test-act-nonexistent'.\n"
    )
    test_act_bad_target_user_unauthorized: bytes = (
        b"ERROR: Account 'privleaptestone' (1002) is unauthorized to run "
        + b"action 'test-act-bad-target-user'.\n"
    )
    test_act_bad_target_group_unauthorized: bytes = (
        b"ERROR: Account 'privleaptestone' (1002) is unauthorized to run "
        + b"action 'test-act-bad-target-group'.\n"
    )
    test_act_added1_unauthorized: bytes = (
        b"ERROR: Account 'privleaptestone' (1002) is unauthorized to run "
        + b"action 'test-act-added1'.\n"
    )
    test_act_added2_unauthorized: bytes = (
        b"ERROR: Account 'privleaptestone' (1002) is unauthorized to run "
        + b"action 'test-act-added2'.\n"
    )
    test_act_invalid_unauthorized: bytes = (
        b"ERROR: Account 'privleaptestone' (1002) is unauthorized to run "
        + b"action 'test-act-invalid'.\n"
    )
    test_act_target_user: bytes = (
        b"uid=1002(privleaptestone) gid=1002(privleaptestone) groups=1002("
        + b"privleaptestone)\n"
    )
    test_act_target_group: bytes = (
        b"uid=0(root) gid=1002(privleaptestone) "
        + b"groups=1002(privleaptestone)\n"
    )
    test_act_target_user_and_group: bytes = (
        b"uid=1002(privleaptestone) gid=0(root) groups=0(root)\n"
    )
    test_act_rootdata: bytes = (
        b"/root\n"
        b"uid=0(root) gid=0(root) groups=0(root)\n"
        b"SHELL=/usr/bin/bash\n"
        b"AUTOPKGTEST_NORMAL_USER=unshare\n"
        b"PWD=/root\n"
        b"LOGNAME=root\n"
        b"HOME=/root\n"
        b"LANG=C.UTF-8\n"
        b"USER=root\n"
        b"ADT_NORMAL_USER=unshare\n"
        b"SHLVL=1\n"
        b"LC_ALL=C\n"
        b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        b"MAIL=/var/mail/root\n"
        b"DEBIAN_FRONTEND=noninteractive\n"
        b"OLDPWD=/\n"
        b"_=/usr/bin/env\n"
    )
    test_act_userdata: bytes = (
        b"/home/privleaptestone\n"
        b"uid=1002(privleaptestone) gid=1002(privleaptestone) "
        b"groups=1002(privleaptestone)\n"
        b"SHELL=/usr/bin/bash\n"
        b"AUTOPKGTEST_NORMAL_USER=unshare\n"
        b"PWD=/home/privleaptestone\n"
        b"LOGNAME=privleaptestone\n"
        b"HOME=/home/privleaptestone\n"
        b"LANG=C.UTF-8\n"
        b"USER=privleaptestone\n"
        b"ADT_NORMAL_USER=unshare\n"
        b"SHLVL=1\n"
        b"LC_ALL=C\n"
        b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        b"MAIL=/var/mail/root\n"
        b"DEBIAN_FRONTEND=noninteractive\n"
        b"OLDPWD=/\n"
        b"_=/usr/bin/env\n"
    )
    privleapd_help: bytes = (
        b"privleapd: privleap backend server\n"
        b"Usage:\n"
        b"  privleapd [-C|--check-config] [-h|--help|-?]\n"
        b"Options:\n"
        b"  -C, --check-config: Check configuration for validity.\n"
        b"  -h, --help, -?: Print usage information.\n"
        b"If run without any options specified, the server will start "
        b"normally.\n"
    )
    privleapd_unrecognized_argument: bytes = (
        b"Unrecognized argument '-z', try 'privleapd --help' for usage info\n"
    )
    privleapd_unrecognized_argument_escape: bytes = (
        b"Unrecognized argument '\\x1b[31mHi\\x1b[m', try 'privleapd "
        b"--help' for usage info\n"
    )
    bad_config_file_lines: list[str] = [
        "parse_config_file: ERROR: Error parsing config: "
        + "'/etc/privleap/conf.d/crash.conf:2:error:Invalid syntax'\n",
        "main: CRITICAL: Failed initial config load!\n",
    ]
    bad_config_file_check_lines: list[str] = [
        "/etc/privleap/conf.d/crash.conf:2:error:Invalid syntax\n"
    ]
    control_disconnect_lines: list[str] = [
        "handle_control_session: ERROR: Could not get message from control client!\n",
        "Traceback (most recent call last):\n",
        "ConnectionAbortedError: Connection unexpectedly closed\n",
    ]
    control_create_invalid_user_socket_lines: list[str] = [
        "handle_control_create_msg: WARNING: Account 'nonexistent' does not "
        + "exist\n"
    ]
    create_invalid_user_socket_and_bail_lines: list[str] = [
        "handle_control_create_msg: WARNING: Account 'nonexistent' does not "
        + "exist\n",
        "send_msg_safe: ERROR: Could not send 'CONTROL_ERROR'\n",
        "Traceback (most recent call last):\n",
        "BrokenPipeError: [Errno 32] Broken pipe\n",
    ]
    destroy_invalid_user_socket_lines: list[str] = [
        "destroy_comm_socket: INFO: Could not destroy comm socket for account "
        + "'12345', account has no comm socket open\n",
        "handle_control_destroy_msg: INFO: Handled DESTROY message for account "
        + "'12345', socket did not exist\n",
    ]
    destroy_nonexistent_user_lines: list[str] = [
        "destroy_comm_socket: WARNING: Could not destroy comm socket for "
        + "account 'nonexistent', account does not exist and its original UID "
        + "was not given\n",
        "handle_control_destroy_msg: INFO: Handled DESTROY message for account "
        + "'nonexistent', socket did not exist\n",
    ]
    create_user_socket_lines: list[str] = [
        "handle_control_create_msg: INFO: Handled CREATE message for account "
        + "'privleaptestone', socket created\n",
        "handle_control_create_msg: INFO: Handled CREATE message for account "
        + "'privleaptestone', socket already exists\n",
    ]
    create_existing_user_socket_and_bail_lines: list[str] = [
        "handle_control_create_msg: INFO: Handled CREATE message for account "
        + "'privleaptestone', socket already exists\n",
        "send_msg_safe: ERROR: Could not send 'EXISTS'\n",
        "BrokenPipeError: [Errno 32] Broken pipe\n",
    ]
    create_blocked_user_socket_lines: list[str] = [
        "handle_control_create_msg: ERROR: Failed to create socket for account "
        + "'privleaptestone'!\n",
        "Traceback (most recent call last):\n",
        "OSError: [Errno 98] Address already in use\n",
    ]
    create_blocked_user_socket_and_bail_lines: list[str] = [
        "handle_control_create_msg: ERROR: Failed to create socket for "
        + "account 'privleaptestone'!\n",
        "Traceback (most recent call last):\n",
        "OSError: [Errno 98] Address already in use\n",
        "send_msg_safe: ERROR: Could not send 'CONTROL_ERROR'\n",
        "OSError: [Errno 98] Address already in use\n",
        "During handling of the above exception, another exception "
        + "occurred:\n",
        "Traceback (most recent call last):\n",
        "BrokenPipeError: [Errno 32] Broken pipe\n",
    ]
    destroy_persistent_user_lines: list[str] = [
        "destroy_comm_socket: INFO: Refusing to destroy comm socket for "
        + "persistent account 'uucp'\n",
        "handle_control_destroy_msg: INFO: Handled DESTROY message for "
        + "account 'uucp', account is persistent, so socket not destroyed\n",
    ]
    destroy_missing_user_socket_lines: list[str] = [
        "destroy_comm_socket: WARNING: Destroying comm socket for account "
        + "'privleaptestone', no UNIX socket to delete at "
        + "'/run/privleapd/comm/XXX_PRIVLEAPTESTONE_UID_XXX'\n",
        "destroy_comm_socket: INFO: Successfully destroyed comm socket for "
        + "account 'privleaptestone'\n",
        "handle_control_destroy_msg: INFO: Handled DESTROY message for account "
        + "'privleaptestone', socket destroyed\n",
    ]
    destroy_user_socket_and_bail_lines: list[str] = [
        "destroy_comm_socket: INFO: Successfully destroyed comm socket for "
        + "account 'privleaptestone'\n",
        "handle_control_destroy_msg: INFO: Handled DESTROY message for "
        + "account 'privleaptestone', socket destroyed\n",
        "send_msg_safe: ERROR: Could not send 'OK'\n",
        "Traceback (most recent call last):\n",
        "BrokenPipeError: [Errno 32] Broken pipe\n",
    ]
    privleapd_verify_not_running_twice_fail: bytes = (
        b"verify_not_running_twice: CRITICAL: Cannot run two "
        + b"privleapd processes at the same time!\n"
    )
    privleapd_ensure_running_as_root_fail: bytes = (
        b"ensure_running_as_root: CRITICAL: privleapd must run as root!\n"
    )
    destroy_bad_user_socket_and_bail_lines: list[str] = [
        "destroy_comm_socket: INFO: Could not destroy comm socket for account "
        + "'privleaptestone', account has no comm socket open\n",
        "handle_control_destroy_msg: INFO: Handled DESTROY message for account "
        + "'privleaptestone', socket did not exist\n",
        "send_msg_safe: ERROR: Could not send 'NOUSER'\n",
        "Traceback (most recent call last):\n",
        "BrokenPipeError: [Errno 32] Broken pipe\n",
    ]
    send_invalid_control_message_lines: list[str] = [
        "handle_control_session: ERROR: Could not get message from control client!\n",
        "Traceback (most recent call last):\n",
        "ValueError: Unrecognized message type 'BOB'\n",
    ]
    send_corrupted_control_message_lines: list[str] = [
        "handle_control_session: ERROR: Could not get message from control client!\n",
        "Traceback (most recent call last):\n",
        "ValueError: recv_buf contains data past the last string\n",
    ]
    bail_comm_lines: list[str] = [
        "get_client_initial_msg: ERROR: Could not get message from client run by account "
        + "'privleaptestone'!\n",
        "Traceback (most recent call last):\n",
        "ConnectionAbortedError: Connection unexpectedly closed\n",
    ]
    send_invalid_comm_message_lines: list[str] = [
        "get_client_initial_msg: ERROR: Could not get message from client run by account "
        + "'privleaptestone'!\n",
        "Traceback (most recent call last):\n",
        "ValueError: Unrecognized message type 'BOB'\n",
    ]
    send_nonexistent_signal_and_bail_lines_part1: list[str] = [
        "auth_signal_request: WARNING: Action run request: Could not find "
        + "action 'nonexistent' requested by account "
        + "'privleaptestone'\n"
    ]
    unauthorized_broken_pipe_lines: list[str] = [
        "send_msg_safe: ERROR: Could not send 'UNAUTHORIZED'\n",
        "Traceback (most recent call last):\n",
        "BrokenPipeError: [Errno 32] Broken pipe\n",
    ]
    send_userrestrict_signal_and_bail_lines_part1: list[str] = [
        "auth_signal_request: WARNING: Action run request: Account "
        + "'privleaptestone' is not authorized to run action "
        + "'test-act-userrestrict'\n"
    ]
    send_grouprestrict_signal_and_bail_lines_part1: list[str] = [
        "auth_signal_request: WARNING: Action run request: Account "
        + "'privleaptestone' is not authorized to run action "
        + "'test-act-grouprestrict'\n"
    ]
    send_invalid_bash_signal_lines: list[str] = [
        "handle_signal_message: INFO: Triggered action 'test-act-invalid-bash' "
        + "for account 'privleaptestone'\n",
        "send_action_results: INFO: Action 'test-act-invalid-bash' requested "
        + "by account 'privleaptestone' completed\n",
    ]
    send_valid_signal_and_bail_lines: list[str] = [
        "handle_signal_message: INFO: Triggered action 'test-act-free' "
        + "for account 'privleaptestone'\n",
        "send_msg_safe: ERROR: Could not send 'TRIGGER'\n",
        "BrokenPipeError: [Errno 32] Broken pipe\n",
    ]
    send_random_garbage_lines: list[str] = [
        "get_client_initial_msg: ERROR: Could not get message from client "
        + "run by account 'privleaptestone'!\n"
    ]
    invalid_ascii_list: list[bytes] = [
        b"\x00\x00\x00\x07\x1bTEST 0",
        b"\x00\x00\x00\x07TEST\x1b 0",
        b"\x00\x00\x00\x07TE\x1bST 0",
        b"\x00\x00\x00\x07\x1fTEST 0",
        b"\x00\x00\x00\x07TEST\x1f 0",
        b"\x00\x00\x00\x07TE\x1fST 0",
        b"\x00\x00\x00\x07\x7fTEST 0",
        b"\x00\x00\x00\x07TEST\x7f 0",
        b"\x00\x00\x00\x07TE\x7fST 0",
        b"\x00\x00\x00\x06TEST 0",
        b"\x00\x00\x00\x10SIGNAL 1 PARAM1\x1b",
        b"\x00\x00\x00\x10SIGNAL 1 \x1bPARAM1",
        b"\x00\x00\x00\x10SIGNAL 1 PAR\x1bAM1",
        b"\x00\x00\x00\x10SIGNAL 1 PARAM1\x1f",
        b"\x00\x00\x00\x10SIGNAL 1 \x1fPARAM1",
        b"\x00\x00\x00\x10SIGNAL 1 PAR\x1bAM1",
        b"\x00\x00\x00\x10SIGNAL 1 PARAM1\x1f",
        b"\x00\x00\x00\x10SIGNAL 1 \x7fPARAM1",
        b"\x00\x00\x00\x10SIGNAL 1 PAR\x7fAM1",
        b"\x00\x00\x00\x0fSIGNAL 1 PARAM1",
        b"\x00\x00\x00\x10SIGNAL 1  PARAM1",
    ]
    # TODO: Any good way to avoid all the repetition?
    invalid_ascii_lines_list: list[list[str]] = [
        [
            "get_client_initial_msg: ERROR: Could not get message from client "
            + "run by account 'privleaptestone'!\n",
            "Traceback (most recent call last):\n",
            "ValueError: Invalid byte found in ASCII string data\n",
        ],
        [
            "get_client_initial_msg: ERROR: Could not get message from client "
            + "run by account 'privleaptestone'!\n",
            "Traceback (most recent call last):\n",
            "ValueError: Invalid byte found in ASCII string data\n",
        ],
        [
            "get_client_initial_msg: ERROR: Could not get message from client "
            + "run by account 'privleaptestone'!\n",
            "Traceback (most recent call last):\n",
            "ValueError: Invalid byte found in ASCII string data\n",
        ],
        [
            "get_client_initial_msg: ERROR: Could not get message from client "
            + "run by account 'privleaptestone'!\n",
            "Traceback (most recent call last):\n",
            "ValueError: Invalid byte found in ASCII string data\n",
        ],
        [
            "get_client_initial_msg: ERROR: Could not get message from client "
            + "run by account 'privleaptestone'!\n",
            "Traceback (most recent call last):\n",
            "ValueError: Invalid byte found in ASCII string data\n",
        ],
        [
            "get_client_initial_msg: ERROR: Could not get message from client "
            + "run by account 'privleaptestone'!\n",
            "Traceback (most recent call last):\n",
            "ValueError: Invalid byte found in ASCII string data\n",
        ],
        [
            "get_client_initial_msg: ERROR: Could not get message from client "
            + "run by account 'privleaptestone'!\n",
            "Traceback (most recent call last):\n",
            "ValueError: Invalid byte found in ASCII string data\n",
        ],
        [
            "get_client_initial_msg: ERROR: Could not get message from client "
            + "run by account 'privleaptestone'!\n",
            "Traceback (most recent call last):\n",
            "ValueError: Invalid byte found in ASCII string data\n",
        ],
        [
            "get_client_initial_msg: ERROR: Could not get message from client "
            + "run by account 'privleaptestone'!\n",
            "Traceback (most recent call last):\n",
            "ValueError: Invalid byte found in ASCII string data\n",
        ],
        [
            "get_client_initial_msg: ERROR: Could not get message from client "
            + "run by account 'privleaptestone'!\n",
            "Traceback (most recent call last):\n",
            "ValueError: Unrecognized message type 'TEST'\n",
        ],
        [
            "get_client_initial_msg: ERROR: Could not get message from client "
            + "run by account 'privleaptestone'!\n",
            "Traceback (most recent call last):\n",
            "ValueError: Invalid byte found in ASCII string data\n",
        ],
        [
            "get_client_initial_msg: ERROR: Could not get message from client "
            + "run by account 'privleaptestone'!\n",
            "Traceback (most recent call last):\n",
            "ValueError: Invalid byte found in ASCII string data\n",
        ],
        [
            "get_client_initial_msg: ERROR: Could not get message from client "
            + "run by account 'privleaptestone'!\n",
            "Traceback (most recent call last):\n",
            "ValueError: Invalid byte found in ASCII string data\n",
        ],
        [
            "get_client_initial_msg: ERROR: Could not get message from client "
            + "run by account 'privleaptestone'!\n",
            "Traceback (most recent call last):\n",
            "ValueError: Invalid byte found in ASCII string data\n",
        ],
        [
            "get_client_initial_msg: ERROR: Could not get message from client "
            + "run by account 'privleaptestone'!\n",
            "Traceback (most recent call last):\n",
            "ValueError: Invalid byte found in ASCII string data\n",
        ],
        [
            "get_client_initial_msg: ERROR: Could not get message from client "
            + "run by account 'privleaptestone'!\n",
            "Traceback (most recent call last):\n",
            "ValueError: Invalid byte found in ASCII string data\n",
        ],
        [
            "get_client_initial_msg: ERROR: Could not get message from client "
            + "run by account 'privleaptestone'!\n",
            "Traceback (most recent call last):\n",
            "ValueError: Invalid byte found in ASCII string data\n",
        ],
        [
            "get_client_initial_msg: ERROR: Could not get message from client "
            + "run by account 'privleaptestone'!\n",
            "Traceback (most recent call last):\n",
            "ValueError: Invalid byte found in ASCII string data\n",
        ],
        [
            "get_client_initial_msg: ERROR: Could not get message from client "
            + "run by account 'privleaptestone'!\n",
            "Traceback (most recent call last):\n",
            "ValueError: Invalid byte found in ASCII string data\n",
        ],
        [
            "auth_signal_request: WARNING: Action run request: Could not find "
            + "action 'PARAM1' requested by account "
            + "'privleaptestone'\n"
        ],
        [
            "get_client_initial_msg: ERROR: Could not get message from client "
            + "run by account 'privleaptestone'!\n",
            "Traceback (most recent call last):\n",
            "ValueError: recv_buf contains data past the last string\n",
        ],
    ]
    duplicate_actions_config_file_lines: list[str] = [
        "parse_config_file: ERROR: Error parsing config: "
        + "'/etc/privleap/conf.d/unit-test.conf:58:error:Duplicate action "
        + "found: 'test-act-sudopermit''\n",
        "main: CRITICAL: Failed initial config load!\n",
    ]
    wrongorder_config_file_lines: list[str] = [
        "parse_config_file: ERROR: Error parsing config: "
        + "'/etc/privleap/conf.d/wrongorder.conf:1:error:Config line "
        + "before header'\n",
        "main: CRITICAL: Failed initial config load!\n",
    ]
    duplicate_keys_config_file_lines: list[str] = [
        "parse_config_file: ERROR: Error parsing config: "
        + "'/etc/privleap/conf.d/dupkeys.conf:3:error:Multiple 'Command' "
        + "keys in action 'test-act-dupkeys''\n",
        "main: CRITICAL: Failed initial config load!\n",
    ]
    absent_command_directive_config_file_lines: list[str] = [
        "parse_config_file: ERROR: Error parsing config: "
        + "'/etc/privleap/conf.d/absent.conf:5:error:No command configured for "
        + "action: 'test-act-absent''\n",
        "main: CRITICAL: Failed initial config load!\n",
    ]
    invalid_action_config_file_lines: list[str] = [
        "parse_config_file: ERROR: Error parsing config: "
        + "'/etc/privleap/conf.d/invalidaction.conf:1:error:Invalid action "
        + "name: 'test-@ct-invalidaction''\n",
        "main: CRITICAL: Failed initial config load!\n",
    ]
    config_reload_success_lines: list[str] = [
        "handle_control_reload_msg: INFO: Handled RELOAD message, "
        + "configuration reloaded\n"
    ]
    config_reload_success_with_kick_lines: list[str] = [
        "handle_control_reload_msg: INFO: Handled RELOAD message, "
        + "configuration reloaded\n",
        "prune_disallowed_comm_sockets: INFO: Destroying comm socket for "
        + "no-longer-allowed account 'privleaptesttwo'\n",
        "prune_disallowed_comm_sockets: INFO: Destroying comm socket for "
        + "no-longer-allowed account 'privleaptestthree'\n",
    ]
    config_reload_bad_ident_lines: list[str] = [
        "__init__: WARNING: PrivleapAction: Account 'idontexist1' specified "
        + "by field 'TargetUser' of action 'test-act-bad-target-user' does "
        + "not exist.\n",
        "__init__: WARNING: PrivleapAction: Group 'idontexist2' specified "
        + "by field 'TargetGroup' of action 'test-act-bad-target-group' does "
        + "not exist.\n",
    ]
    test_act_added1_success_lines: list[str] = [
        "handle_signal_message: INFO: Triggered action 'test-act-added1' "
        + "for account 'privleaptestone'\n",
        "send_action_results: INFO: Action 'test-act-added1' requested "
        + "by account 'privleaptestone' completed\n",
    ]
    test_act_added2_success_lines: list[str] = [
        "handle_signal_message: INFO: Triggered action 'test-act-added2' "
        + "for account 'privleaptestone'\n",
        "send_action_results: INFO: Action 'test-act-added2' requested "
        + "by account 'privleaptestone' completed\n",
    ]
    test_act_added1_failure_lines: list[str] = [
        "auth_signal_request: WARNING: Action run request: Could not find "
        + "action 'test-act-added1' requested by account "
        + "'privleaptestone'\n"
    ]
    test_act_added2_failure_lines: list[str] = [
        "auth_signal_request: WARNING: Action run request: Could not find "
        + "action 'test-act-added2' requested by account "
        + "'privleaptestone'\n"
    ]
    test_act_userpermit_success_lines: list[str] = [
        "handle_signal_message: INFO: Triggered action 'test-act-userpermit' "
        + "for account 'privleaptestone'\n",
        "send_action_results: INFO: Action 'test-act-userpermit' requested "
        + "by account 'privleaptestone' completed\n",
    ]
    config_reload_failure_lines: list[str] = [
        "parse_config_file: ERROR: Error parsing config: "
        + "'/etc/privleap/conf.d/added_actions_bad.conf:10:error:Invalid "
        + "syntax'\n",
        "handle_control_reload_msg: WARNING: Handled RELOAD message, "
        + "configuration was invalid!\n",
    ]
    unrecognized_header_config_file_lines: list[str] = [
        "parse_config_file: ERROR: Error parsing config: "
        + "'/etc/privleap/conf.d/unrec_header.conf:1:error:Unrecognized header "
        + "'unrecognized-header''\n",
        "main: CRITICAL: Failed initial config load!\n",
    ]
    missing_auth_config_file_lines: list[str] = [
        "parse_config_file: ERROR: Error parsing config: "
        + "'/etc/privleap/conf.d/missing_auth.conf:1:error:No "
        + "authorized users or groups for action: 'test-act-missing-auth''\n",
        "main: CRITICAL: Failed initial config load!\n",
    ]
    allowed_action_access_check_lines: list[str] = [
        "auth_signal_request: INFO: Access check: Account "
        + "'privleaptestone' is authorized to run action "
        + "'test-act-free'\n"
    ]
    disallowed_action_access_check_lines: list[str] = [
        "auth_signal_request: WARNING: Access check: Account "
        + "'privleaptestone' is not authorized to run action "
        + "'test-act-userrestrict'\n"
    ]
    create_expected_disallowed_socket_lines: list[str] = [
        "handle_control_create_msg: INFO: Expected disallowed account 'irc' "
        + "requested a comm socket, request denied\n"
    ]
    leaprun_terminate_lines: list[str] = [
        "handle_signal_message: INFO: Triggered action 'test-act-noreturn' "
        + "for account 'privleaptestone'\n",
        "assert_action_terminate: INFO: Action 'test-act-noreturn' "
        + "prematurely terminated by account "
        + "'privleaptestone'\n",
        "send_action_results: INFO: Action 'test-act-noreturn' requested by "
        + "account 'privleaptestone' completed\n",
    ]
    terminate_sent_first_lines: list[str] = [
        "get_client_initial_msg: WARNING: Did not read SIGNAL or "
        + "ACCESS_CHECK as first message from client run by account "
        + "'privleaptestone', forcibly closing connection.\n"
    ]
    test_act_privleap_grouppermit_privleaptesttwo_success_lines: list[str] = [
        "handle_signal_message: INFO: Triggered action "
        + "'test-act-privleap-grouppermit' for account 'privleaptesttwo'\n",
        "send_action_results: INFO: Action 'test-act-privleap-grouppermit' "
        + "requested by account 'privleaptesttwo' completed\n",
    ]
    test_act_privleap_grouppermit_privleaptesttwo_kick_lines: list[str] = [
        "handle_comm_session: WARNING: Ending session and destroying comm "
        + "socket for no-longer-allowed account 'privleaptesttwo'\n"
    ]
    test_act_nonexistent_restrict_lines: list[str] = [
        "auth_signal_request: WARNING: Action run request: Account "
        + "'privleaptestone' is not authorized to run action "
        + "'test-act-nonexistent-restrict'\n"
    ]
    insecure_permissions_on_file_lines: list[str] = [
        "parse_config_file: ERROR: Error parsing config: "
        + "'Config file '/etc/privleap/conf.d/added_actions.conf' has "
        + "insecure permissions; it must be owned by 'root:root' and not be "
        + "world-writable!'\n"
    ]
    insecure_permissions_on_config_dir_lines: list[str] = [
        "parse_config_files: WARNING: Config directory "
        + "'/etc/privleap/conf.d' exists but has insecure permissions, "
        + "ignoring all files in this directory.\n",
        "parse_config_files: ERROR: No valid configuration files found! "
        + "Checked paths: '/etc/privleap/conf.d', "
        + "'/usr/local/etc/privleap/conf.d'\n",
    ]
    invalid_config_file_name_lines: list[str] = [
        "parse_config_files: WARNING: Config file "
        + "'/etc/privleap/conf.d/invalid%config.conf' has an illegal name, "
        + "skipping.\n"
    ]
    missing_local_config_dir_lines: list[str] = [
        "parse_config_files: INFO: Config directory "
        + "'/usr/local/etc/privleap/conf.d' does not exist, skipping.\n"
    ]
    multithreading_test_set: set[str] = set(
        [
            "handle_control_create_msg: INFO: Handled CREATE message for "
            + "account 'XXX_USERNAME_XXX', socket created",
            "destroy_comm_socket: INFO: Successfully destroyed comm socket "
            + "for account 'XXX_USERNAME_XXX'",
            "handle_control_destroy_msg: INFO: Handled DESTROY message for "
            + "account 'XXX_USERNAME_XXX', socket destroyed",
            "auth_signal_request: INFO: Action run request: Account "
            + "'XXX_USERNAME_XXX' is authorized to run action "
            + "'test-act-anyone'",
            "handle_signal_message: INFO: Triggered action 'test-act-anyone' "
            + "for account 'XXX_USERNAME_XXX'",
            "send_action_results: INFO: Action 'test-act-anyone' requested "
            + "by account 'XXX_USERNAME_XXX' completed",
        ]
    )
    privleapd_control_msg_mismatch_lines: list[str] = [
        "handle_control_session: ERROR: Could not get message from control client!\n",
        "Traceback (most recent call last):\n",
        "ValueError: Invalid message type 'SIGNAL' for socket\n",
    ]
    privleapd_comm_msg_mismatch_lines: list[str] = [
        "get_client_initial_msg: ERROR: Could not get message from client run by account "
        + "'privleaptestone'!\n",
        "Traceback (most recent call last):\n",
        "ValueError: Invalid message type 'CREATE' for socket\n",
    ]
