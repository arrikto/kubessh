#!/usr/bin/env python3
#
# kubessh.py
#
# Copyright © 2023 Arrikto Inc.  All Rights Reserved.

import os
import sys
import argparse

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


def parse_args():
    """Parse command-line arguments as arguments to the OpenSSH client."""

    d = ("Execute into a pod on Kubernetes with an OpenSSH-compatible syntax."
         " In other words, make 'kubectl exec' appear and function as a"
         " replacement for the OpenSSH client [the 'ssh' command-line tool],"
         " and support a compatible syntax.\n\n"
         "The command to execute on the machine is optional. If omitted,"
         " %(prog)s will attempt to run '/bin/bash', in an effort to mimic"
         " the default behavior of 'ssh', which is to spawn a login shell"
         " on the remote machine.")

    p = argparse.ArgumentParser(prog=PROG, description=d)

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
                         " 'kubectl.kubernetes.io/default-container'",
                         " annotation, or the first container in the pod",
                         " if no such annotation exists. %(prog) maps this"
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
                         " ssh://[container@]pod[.namespace][:port]."
                         " Note: Kubernetes does not allow namespace names to"
                         " contain dots, but it *does* allow pod names to"
                         " contain dots, so you have to add the namespace"
                         " explicitly, if you wish to exec into a pod with a"
                         " dot in its name."
                         " Note: It's forbidden to set the container name"
                         " both via '-l' and as part of 'destination'"
                         " at the same time."
                         " Note: %(prog)s will ignore 'port' if specified"
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

    p.add_argument("command", nargs=argparse.REMAINDER,
                   help=("The command to run on the container."
                         " Default: /bin/bash, in an effort to mimic default"
                         " 'ssh' behavior, which starts the default login"
                         " shell on the remote host."))

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
        args.alloc_tty = True if args.command == [] else False

    if args.command == []:
        args.command = ["/bin/bash"]

    del args.destination
    del args.port
    args.namespace = namespace
    args.pod = pod
    args.container = container

    return vars(args)


def construct_cmdline_kubectl(args):
    cmdline = ["kubectl", "exec"]

    if args["alloc_tty"]:
        cmdline.append("-t")

    if args["pass_stdin"]:
        cmdline.append("-i")

    if args["container"]:
        cmdline += ["-c", args["container"]]

    if args["namespace"]:
        cmdline += ["-n", args["namespace"]]

    cmdline.append(args["pod"])

    cmdline.append("--")

    cmdline += args["command"]

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
