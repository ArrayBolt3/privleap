# Communication protocol for privleap

This is a rough specification of the protocol used by privleap. It is intended
to give a developer an idea of what IPC protocol used by privleap looks like.
It does not, however, answer every possible question one could have about the
format. As privleap is believed to be the only implementation of this
protocol, this is not expected to be a practical issue.

## Terminology

* *Action* - A set of commands and accompanying metadata defined in one of
  privleap's configuration files. Each action corresponds to a single line of
  Bash code that is run when the action is *triggered*. Actions can only be
  triggered by users and groups authorized to trigger them and may require the
  person operating the authorized user to prove their identity. Each action has
  a specific name.
* *Session* - A connection between a privleap client and a privleap background
  process. One or more *messages* may be sent back and forth in a session.
* *Message* - A single unit of data passed to privleap by an application, or
  passed to the application from privleap.
* *Signal* - A message sent to privleap specifying a particular action the
  application wishes to trigger. Each action has a corresponding signal with
  the same name as the action.

## Protocol

The server should assume that user-level clients are malicious and therefore
treat any data from them with the utmost caution. Additionally, the server
should aim to prevent DoS attacks caused by resource-intensive activity
patterns. In general, the server should err on the side of caution and terminate
a connection without explanation if the client is not sending data quickly
enough or sends unexpected data. This same level of care does not need to be
taken with the control socket, as it is accessible only by root and thus is not
a danger.

Each message is formatted as a Pascal-style string using an unsigned 4-byte
integer for the length prefix. The length prefix is in big-endian byte order.
The string may contain arbitrary binary data (including NUL bytes) and should
not be blindly trusted if it comes from an untrusted source. Messages are
case-sensitive.

The format of each message is as follows:

    <msg_name> <arg_count> [<arg_1> ... <arg_63>] [<binary_blob>]

Where:

* `<msg_name>` is the name of the message in question. It must consist
  entirely of non-whitespace 7-bit ASCII characters. It must be terminated
  by a space (ASCII `0x20`).
* `<arg_count>` is a single Base64-like digit representing the number of
  arguments being included with the message. If the digit is not `0`, or if a
  binary blob is included with a message, the count must be terminated by a
  space, otherwise there must not be a terminating space..
  * The characters `0-9` are used to represent values 0 through 9. The
    characters `A-Z` are used to represent values 10 through 35. The
    characters `a-z` are used to represent values 36-61. The characters `+`
    and `/` are used to represent values 62 and 63. This uses the same
    characters as true Base64, but in a more intuitive order that is not
    any more difficult to parse.
* `<arg_1> ... <arg_63>` represents the argument list. Each argument must
  consist entirely of non-whitespace 7-bit ASCII characters. Arguments that
  are not the last argument must be terminated by a space. For messages that
  include a trailing binary blob, the last argumet must be terminated by a
  space as well, otherwise there must not be a terminating space. There must
  be exactly as many arguments as specified by the argument count field.
* `<binary_blob>` represents arbitrary binary data. If it is supported by a
  message, it must be present, otherwise it must be absent. If it is present,
  it will occur immediately after the terminating space of the last argument
  (or immediately after the terminating space of the argument count if the
  argument count is 0).

When an application connects to any socket `privleapd` has open and is
listening on, it begins a session with `privleapd`. Sessions are only held
open for as long as necessary, and are closed as soon as possible.

On startup, `privleapd` creates and listens on a socket at
`/run/privleapd/control`. This socket is owned by `root:root` and uses
permissions `0600`. The containing directory `/run/privleapd` is owned by
`root:root` and uses permissions `0644`. The `control` socket is used to
manage communication sockets for each individual user account.

Any messages sent by the client must be no longer than 4096 bytes (not
including the four-byte message length header). `privleapd` will forcibly
disconnect a client that attempts to send a longer message than this. This is
expected to be enough to allow any practically-sized usernames, signal names,
and authentication data to be passed now and in the future. The server may send
messages longer than this.

`privleapd` understands the following messages passed via the `control` socket:

* `CREATE` - Creates a communication socket for a specified user. Supports one
  mandatory argument, the name or UID of the user to make a communication
  socket for. Does not include a binary blob. Must be sent as the first message
  in the session.
  * For instance, to create a user socket for account `john`, the message
    `CREATE 1 john` would be sent by the client.
* `DESTROY` - Destroys a communication socket for a specified user. Supports
  one mandatory argument, the name or UID of the user to destroy the
  communication socket of. Does not include a binary blob. Must be sent as the
  first message in the session.
  * For instance, to destroy a user socket for account `john`, the
    message `DESTROY 1 john` would be sent by the client.
* `RELOAD` - Reloads configuration data. Supports no arguments. Does not
  include a binary blob. Must be sent as the first message in the session.

`privleapd` can send the following messages on the `control` socket, which
clients must be able to understand:

* `OK` - The requested operation succeeded. Supports no arguments. Does not
  include a binary blob. May be sent as a reply to `CREATE`, `DESTROY`, or
  `RELOAD`.
* `CONTROL_ERROR` - The requested operation failed. Does not include a binary
  blob. Supports no arguments. May be sent as a reply to `CREATE`, `DESTROY`,
  or `RELOAD`.
* `EXISTS` - The user specified by the previous command already has a
  communication socket open. Supports no arguments. Does not include a binary
  blob. May be sent as a reply to `CREATE`.
* `NOUSER` - The user specified by the previous command does not have a
  communication socket open. Supports no arguments. Does not include a binary
  blob. May be sent as a reply to `DESTROY`.
* `PERSISTENT_USER` - The user specified by the previous command is a
  "persistent user" and cannot be destroyed. Supports no arguments. Does not
  include a binary blob. May be sent as a reply to `DESTROY`.
  * See `man privleap.conf` for more information on persistent users.
* `DISALLOWED_USER` - The user specified by the previous command is not an
  "allowed user" and cannot have a socket created for them. Supports no
  arguments. Does not include a binary blob. May be sent as a reply to
  `CREATE`.
  * See `man privleap.conf.d` for more information on allowed users.
* `EXPECTED_DISALLOWED_USER` - The user specified by the previous command is
  an "expected disallowed user" and cannot have a socket created for them.
  Supports no arguments. Does not include a binary blob. May be sent as a
  reply to `CREATE`.
  * See `man privleap.conf.d` for more information on allowed users.

Regardless of the reply, `privleapd` will close the session immediately after
sending one of the above messages, and will ignore all but the first message
the client sends.

In actual operation, an application involved in user login is expected to send
`CREATE 1 <username>` when `<username>` logs in, while an application involved
in user logout is expected to send `DESTROY 1 <username>` when the user logs
out. This ensures that only actively logged-in users have open communication
sockets. If using shell scripts for this, `leapctl --create <username>` can be
used to send `CREATE 1 <username>`, while `leapctl --destroy <username>` can
be used to send `DESTROY 1 <username>`.

Communication sockets are stored under `/run/privleapd/comm`. Each
communication socket is named after the UID of the user it is intended to be
used by (i.e. `1000`). It is owned by the user and group corresponding to that
user, and uses permissions `0600`. This ensures that only the authorized user
can communicate with `privleapd` over this socket, which in turn allows
`privleapd` to identify which user is sending messages to it.

`privleapd` understands the following messages passed via a communication
socket:

* `SIGNAL` - Sends a signal to `privleapd`, requesting the triggering of an
  action. Supports one mandatory argument, the name of the signal to send.
  Does not include a binary blob. Must be sent as the first message in the
  session.
  * For instance, to trigger an action named `do-thing`, the message
    `SIGNAL 1 do-thing` would be sent by the client.
* `ACCESS_CHECK` - Queries `privleapd` to determine if the caller is
  authorized to trigger the batch of actions corresponding to the signal names
  given as arguments. Supports up to 63 arguments, with only one argument
  being mandatory. Does not include a binary blob. Must be sent as the first
  message in the session.
  * For instance, to ask the server if the client may run the actions
    `do-thing`, `do-other`, and `whatnot`, the message
    `ACCESS_CHECK 3 do-thing do-other whatnot` would be sent by the client.
* `TERMINATE` - Instructs `privleapd` to immediately terminate the running
  action and cease sending process output to the client. Supports no
  arguments. Does not include a binary blob. May only be sent after receiving
  a `TRIGGER` message at some prior point in the session.

`privleapd` can send the following messages, which clients must be able to
understand:

* `TRIGGER` - Indicates that the action requested by the last message has been
  triggered and is now mid-execution. Supports no arguments. Does not include
  a binary blob. May be sent as a reply to `SIGNAL`.
* `TRIGGER_ERROR` - Indicates that the client was authorized to trigger the
  action requested by the last message, but that the action could not be
  executed. Supports no arguments. Does not include a binary blob. May be sent
  as a reply to `SIGNAL`.
  * Note that this message is reserved for issues actually starting the
    action. If the action can be executed but exits with a non-zero exit code,
    clients should expect to receive `TRIGGER`, followed by a
    `RESULT_EXITCODE` message at some later point in the session.
* `RESULT_STDOUT` - Transfers a block of data the action wrote to its stdout
  stream to the client. Supports no arguments. Includes a binary blob, which
  is the block of stdout data. May be sent at any time after sending
  `TRIGGER`, but must not be sent after the server has processed a `TERMINATE`
  message from the client or after the server has sent `RESULT_EXITCODE`.
* `RESULT_STDERR` - Identical to `RESULT_STDOUT`, but the block of data comes
  from the action's stderr stream.
* `RESULT_EXITCODE` - Indicates that the action requested by a prior `SIGNAL`
  message has completed execution, and provides its exit code to the client.
  Supports one mandatory argument, a string consisting entirely of ASCII
  digits that together represent an integer between 0 and 255 inclusive. Does
  not include a binary blob. May be sent at any time after sending `TRIGGER`.
  * For instance, if the action exited with code `42`, the message
    `RESULT_EXITCODE 1 42` would be sent by the server.
* `AUTHORIZED` - Indicates that the client is authorized to trigger the
  actions specified in the message. Supports up to 63 arguments, with only one
  argument being mandatory. Does not include a binary blob. May be sent at any
  time after recieving `ACCESS_CHECK`.
  * For instance, to tell the client that it is authorized to run actions
    `do-thing` and `do-other`, the message `AUTHORIZED 2 do-thing do-other`
    would be sent by the server.
* `UNAUTHORIZED` - Indicates that the user client's user account is not
  authorized to trigger the actions specified in the message, either because
  the actions exists but are not permitted for the user, or because the
  actions do not exist at all. Supports up to 63 arguments, with only one
  argument being mandatory. Does not include a binary blob. May be sent in
  reply to `SIGNAL`, or at any time aftrer recieving `ACCESS_CHECK`.
  * For instance, to tell the client that is it not authorized to run the
    action `whatnot`, the message `UNAUTHORIZED 1 whatnot` would be sent by
    the server.
  * Note that if an `UNAUTHORIZED` message is sent as one of the responses to
    an `ACCESS_CHECK` message, it is not expected to be the last message from
    the server in the session. An `ACCESS_CHECK_RESULTS_END` message is
    expected after it. However, when sent as a response to a `TRIGGER`
    message, `UNAUTHORIZED` is expected to be the last message from the
    server.
* `ACCESS_CHECK_RESULTS_END` - Indicates that the server is done sending
  access check results. Supports no arguments. Does not include a binary blob.
  May be sent at any point after an `ACCESS_CHECK` is received and one or both
  of `AUTHORIZED` and `UNAUTHORIZED` has already been sent.

`privleapd` will only parse the first one of each of the above client-sent
messages per session. When processing a `TRIGGER` message, `privleapd` will
exit immediately after sending an `UNAUTHORIZED` `RESULT_EXITCODE` message.
When processing an `ACCESS_CHECK` message, `privleapd` may exit after sending
one or both of `AUTHORIZED` and `UNAUTHORIZED`.

In actual operation, the client (most likely `leaprun`) is expected to open a
session with `privleapd` and send either a `SIGNAL` or `ACCESS_CHECK` message.

* If a `SIGNAL` message is sent, `privleapd` will respond with either
  `TRIGGER` if the client is authorized to trigger the action, or
  `UNAUTHORIZED` otherwise. If `TRIGGER` is sent, the server will will send
  `RESULT_STDOUT` and `RESULT_STDERR` messages to stream the stdout and stderr
  output from the action to the client, then sent `RESULT_EXITCODE` once the
  action finishes to send the exit code to the client.
* If an `ACCESS_CHECK` message is sent, `privleapd` will respond with an
  `AUTHORIZED` message listing all specified actions the client is authorized
  to trigger, and an `UNAUTHORIZED` message listing all specified actions the
  client is not authorized to trigger. It will then send an
  `ACCESS_CHECK_RESULTS_END` to signal to the client that the results are done
  and the server is about to disconnect.

After the appropriate actions are taken, `privleapd` will close the
connection.

## Potential future development:

* Right now, privleap is designed only to allow running specific actions as
  root without a password, without the dangers of sudo. It would be much
  more useful if it were able to handle identity verification. This could be
  done with `CHALLENGE` and `CHALLENGE_PASS` messages from the server, and
  a `RESPONSE` message from the client. This would only allow for simple
  password-based (or similar) authentication, though. PAM could potentially
  also be used, but trying to forward PAM auth requests over a socket could be
  extremely difficult or impossible, so in practice this would probably end up
  bypassing PAM, which is potentially livable, but not ideal.
* It may be useful to allow streaming stdin from the client to the server
  eventually. This would have to be done carefully to prevent too much attack
  surface from being present, potentially requiring some method of server-side
  filtering of client-provided stdin data.
