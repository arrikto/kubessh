#!/usr/bin/env python3
#
# kubessh.py
#
# Copyright © 2023 Arrikto Inc.  All Rights Reserved.

import os
import sys
import textwrap
from argparse import ArgumentParser, HelpFormatter , REMAINDER

# A wrapper to make "kubectl exec" function as ssh.
# It's mostly syntactic sugar to convert from OpenSSH's "ssh" syntax
# to "kubectl exec" syntax.

PROG = "kubessh"
VERSION = "0.0.1"


def parse_ssh_dest(dest, port_allowed=False):
    """Parse a 'destination' argument in one of two supported formats.

    Parse a 'destination' argument either as '[user@]hostname' or
    as '[user@]hostname[:port]' depending on the value of 'port_allowed'.

    """
    if "@" in dest:
        s = dest.split("@")
        if len(s) != 2:
            msg = ("Specified 'destination' must contain at most one '@'"
                   " character.")
            raise ValueError(msg)
        user, hostname = s[0], s[1]
    else:
        user = None
        hostname = dest

    port = None
    if port_allowed:
        if ":" in hostname:
            s = hostname.split(":")
            hostname = s[0]
            try:
                port = int(":".join(s[1:]))
            except ValueError:
                raise ValueError("If specified, port must be an integer,"
                                 " and cannot be empty.")

    return user, hostname, port

### FIXME: Add unittests for parse_ssh_dest()

class HonorNewlinesHelpFormatter(HelpFormatter):
    """A HelpFormatter for argparse which actually honors newlines.

    The default help formatter wraps text nicely, but doesn't honor explicit
    line breaks. Using RawDescriptionHelpFormatter honors newlines in the
    description, but doesn't wrap text at all, so it's not really a solution.

    This formatter will wrap text at the proper width, but work in paragraphs,
    separated by newline characters.

    This HelpFormatter overrides internal methods in the HelpFormatter class.
    argparse only considers the names of the classes public. 🙄
    For details, see:
    https://github.com/python/cpython/blob/main/Lib/argparse.py

    We'll have to bend the rules a bit and override some private methods,
    to make help output actually readable.
    """
    def _fill_text(self, text, width, indent):
        """This method seems to apply to the text of the description."""
        tw = textwrap

        # Indent the text, keep all newlines
        texti = tw.indent(tw.dedent(text), indent)

        # Split the text into individual paragraphs
        textl = texti.splitlines()

        # Wrap each line individually, and return the final result
        return "\n".join([tw.fill(line, width) for line in textl])

    def _split_lines(self, text, width):
        """This method seems to apply to the help text of individual args."""
        tw = textwrap

        # Dedent all text, keep all newlines
        textd = tw.dedent(text)

        # Split the text into individual paragraphs
        textl = textd.splitlines()

        # Wrap each line individually.
        # We need to return the final result as a flattened list of lines.
        # Note we return *lines* in a list, not the final joined result,
        # since we expect the caller to indent the lines appropriately.

        # Start with a list of lists, one sublist per paragraph
        textpar = [tw.fill(line,width).split("\n") for line in textl]

        # Then flatten it and return the final result
        flat_lines = []
        for paragraph in textpar:
            for line in paragraph:
                flat_lines.append(line)

        return flat_lines

def parse_args():
    """Parse command-line arguments as arguments to the OpenSSH client."""

    d = ("Execute into a pod on Kubernetes with an OpenSSH-compatible syntax."
         " In other words, make 'kubectl exec' appear and function as a"
         " replacement for the OpenSSH client [the 'ssh' command-line tool],"
         " and support a compatible syntax.\n\n"
         "By default, %(prog)s will mimic standard 'ssh' behavior and attempt"
         " to use a shell to run the specified command in the container,"
         " to ensure compatibility with what callers of 'ssh' expect, and also"
         " make for a seamless interactive experience. See the 'command',"
         " 'args', and '--no-shell' arguments below for more details.")

    p = ArgumentParser(prog=PROG, description=d,
                       formatter_class=HonorNewlinesHelpFormatter,
                       allow_abbrev=False)

    p.add_argument("-v", dest="verbose", action="store_true",
                   help=("Enable verbose mode. Output diagnostic messages"
                         " to stderr."))

    p.add_argument("-V", dest="version", action="store_true",
                   help="Output version information to stderr, and exit.")

    p.add_argument("-l", metavar="CONTAINER_NAME", dest="container",
                   action="store",
                   help=("Exec into a specific container, named CONTAINER in"
                         " the pod. If omitted, the underlying 'kubectl exec'"
                         " will exec into the container specified via the"
                         " 'kubectl.kubernetes.io/default-container'"
                         " annotation, or the first container in the pod"
                         " if no such annotation exists. %(prog)s maps this"
                         " option to the '-c' option of 'kubectl exec', see"
                         " the output of 'kubectl help exec' for more"
                         " details."))

    p.add_argument("-n", dest="pass_stdin", action="store_false",
                   help=("Prevent reading from stdin, do not pass the '-i'"
                         " option to 'kubectl exec'. Default is to use '-i',"
                         " and pass stdin to the container."))

    p.add_argument("-p", dest="port", action="store", type=int,
                   help=("This argument exists only to ensure compatibility"
                         " with 'ssh', and is ignored. %(prog)s ignores"
                         " PORT, but -- if specified -- it must be a valid"
                         " port number."))

    p.add_argument("destination",
                   help=("Exec into the specified destination,"
                         " which may be specified as"
                         " container@pod[.namespace],"
                         " or a URI of the form"
                         " ssh://[container@]pod[.namespace][:port].\n"
                         "Note: Kubernetes does not allow namespace names to"
                         " contain dots, but it *does* allow pod names to"
                         " contain dots, so you have to add the namespace"
                         " explicitly, if you wish to exec into a pod with a"
                         " dot in its name.\n"
                         "Note: It's forbidden to set the container name"
                         " both via '-l' and as part of 'destination'"
                         " at the same time.\n"
                         "Note: %(prog)s will ignore 'port' if specified"
                         " [but it must be a valid port number]."))

    tty_group = p.add_mutually_exclusive_group()
    tty_group.add_argument("-t", dest="alloc_tty", action="store_true",
                           default=None,
                           help=("Force pseudo-terminal allocation. Default"
                                 " is to allocate a pseudo-terminal only when"
                                 " no command has been specified, in an"
                                 " effort to mimic default 'ssh' behavior."))
    tty_group.add_argument("-T", dest="alloc_tty", action="store_false",
                           help="Disable pseudo-terminal allocation.")

    p.add_argument("--no-shell", dest="no_shell", action="store_true",
                   default=False,
                   help=("By default %(prog)s mimics standard 'ssh' behavior"
                         " and uses a shell to run the specified command in"
                         " the container. It uses the value of the"
                         " 'kubectl.kubernetes.io/default-shell' annotation to"
                         " determine the shell to invoke, or '/bin/sh' if no"
                         " such annotation exists. To use a shell, %(prog)s"
                         " concatenates the command and all its arguments into"
                         " a single space-separated string, and passes this to"
                         " the shell via its '-c' argument. Use '--no-shell'"
                         " to disable this behavior, in which case %(prog)s"
                         " passes the command and all its arguments to"
                         " `kubectl exec` without any modification. You have"
                         " to specify a 'command' when using '--no-shell'."))

    p.add_argument("command", nargs="?",
                   help=("The command to run inside the container. It may be"
                         " omitted, in which case the default is to start"
                         " the shell specified via the"
                         " 'kubectl.kubernetes.io/default-shell' annotation'"
                         " or '/bin/sh' if no such annotation exists."
                         " The goal is to mimic standard 'ssh' behavior, which"
                         " starts your login shell on the remote host, and to"
                         " make for a seamless interactive experience."))

    # We could use nargs="*" here and specify 'default=None' to workaround
    # this long-standing upstream bug in Python's argparse, see
    # https://github.com/python/cpython/issues/72795
    # *BUT* this would mean we would also be deviating from 'ssh' behavior
    # and interpreting arguments to the remote command as our own.
    # So, we *have* to use REMAINDER, and overwrite '.required' manually,
    # as a workaround. See
    # https://github.com/arrikto/dev/issues/2256#issuecomment-1405253049
    remhelp = ("Optional list of arguments to pass to the command to run"
               " inside the container.\n"
               "Note: %(prog)s will stop parsing its own"
               " arguments after encountering the 'command' positional"
               " argument, so you can specify arguments to the remote command"
               " here freely, without having to use '--' in the command line"
               " explicitly. Again, the goal is to mimic standard 'ssh'"
               " behavior and to make for a seamless interactive experience.")
    rem = p.add_argument("args", nargs=REMAINDER, help=remhelp)
    rem.required = False

    args = p.parse_args()

    container = vars(args).get("container")

    # Parse the 'destination' argument.
    # Allowed formats are
    # '[container@]pod[.namespace][:port]' and
    # 'ssh://[container@]pod[.namespace][:port].
    #
    # This aligned perfectly with SSH, which supports
    # '[user@]hostname' and
    # 'ssh://[user@]hostname[:port],
    # where 'user' becomes the container name and we assume as specific
    # format for 'hostname', using '.' to parse the namespace and pod names.

    # Parse destination as if it was '[user@]hostname' or
    # ssh://[user@]hostname[:port] in the OpenSSH command line.
    dest = args.destination
    if dest.startswith("ssh://"):
        user, hostname, port = parse_ssh_dest(dest[len("ssh://"):],
                                          port_allowed=True)
    else:
        user, hostname, port = parse_ssh_dest(dest, port_allowed=False)

    if args.port is not None and port is not None:
        raise ValueError("Cannot specify port number via 'destination'"
                         " when using the '-p' argument.")

    if args.container is not None and user is not None:
        raise ValueError("Cannot specify container name via 'destination'"
                         " when using the '-l' argument.")

    # Parse the hostname part into pod and namespace, separately
    if "." in hostname:
        s = hostname.split(".")
        pod = ".".join(s[:-1])
        namespace = s[-1]
    else:
        pod = hostname
        namespace = None
    del hostname

    # Final outputs, verify correctness
    port = args.port or port
    container = args.container or user

    if not pod:
        raise ValueError("You must specify a pod name via 'destination'.")
    if container is not None and container == "":
        raise ValueError("If specified, container name cannot be empty.")
    if port is not None and port <= 0:
        raise ValueError("If specified, port must be a positive integer.")

    if args.alloc_tty is None:
        args.alloc_tty = True if args.command is None else False

    # At this point, we're trying to emulate the combined behavior
    # of the OpenSSH client and the OpenSSH server wrt handling command-line
    # arguments and using the login shell on the remote to execute the remote
    # command.
    #
    # OpenSSH server will just run the login shell when it has received no
    # specific command to run, see
    # https://github.com/openssh/openssh-portable/blob/c3ffb54b4fc5e608206037921db6ccbc2f5ab25f/session.c#L1679
    # otherwise, it will pass the remote command to the login shell via its
    # '-c' argument, see
    # https://github.com/openssh/openssh-portable/blob/c3ffb54b4fc5e608206037921db6ccbc2f5ab25f/session.c#L1706
    if args.command is None:
        if args.no_shell:
            raise ValueError("You have to specify 'command' when using"
                             " '--no-shell'")
        cmdline = ["/bin/sh"]   # FIXME: Respect 'kubectl/default-shell'
    else:
        if not args.no_shell:
            # We're going to emulate the standard behavior of the 'ssh' client
            # and concatenate the command and full argument list into a single
            # space separated-string, so we can pass it to the shell via its
            # '-c' argument. See
            # https://github.com/openssh/openssh-portable/blob/35253af01d8c0ab444c8377402121816e71c71f5/ssh.c#L1130
            # for how OpenSSH does this.
            cmdline = ["/bin/sh", "-c"]   # FIXME: Respect 'kubectl/default-shell'
            cmdline.append(" ".join([args.command] + args.args))
        else:
            # At this point we're no longer trying to emulate
            # 'ssh' behavior. We will pass the full argument list to
            # 'kubectl exec' cleanly.
            cmdline = [args.command] + args.args

    # Delete all arguments which we never expect to access directly again,
    # and enhance the args Namespace with new, derived ones.
    del args.args
    del args.command
    del args.destination
    del args.port
    args.namespace = namespace
    args.pod = pod
    args.container = container
    args.cmdline = cmdline

    return vars(args)


def construct_cmdline_kubectl(args):
    cmdline = ["kubectl", "exec"]

    if args["alloc_tty"]:
        cmdline.append("-t")

    if args["pass_stdin"]:
        cmdline.append("-i")

    if args["container"]:
        cmdline.extend(["-c", args["container"]])

    if args["namespace"]:
        cmdline.extend(["-n", args["namespace"]])

    cmdline.append(args["pod"])

    cmdline.append("--")

    cmdline.extend(args["cmdline"])

    return cmdline


def main():
    args = parse_args()

    if args["version"]:
        sys.stderr.write("%s version %s\n" % (PROG, VERSION))
        return 0

    if args["verbose"]:
        sys.stderr.write(("*** Arguments: \n    " +
                          "\n    ".join(["%s: %s" % (k, v)
                                         for k, v in args.items()]) + "\n"))

    cmdline = construct_cmdline_kubectl(args)

    if args["verbose"]:
        sys.stderr.write("*** About to exec: %s\n" % repr(cmdline))

    os.execlp(cmdline[0], *cmdline)

    return 0


if __name__ == "__main__":
    sys.exit(main())
