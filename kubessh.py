#!/usr/bin/env python3
#
# kubessh.py
#
# Copyright © 2023 Arrikto Inc.  All Rights Reserved.

import os
import sys
import argparse

# A wrapper to make "kubectl exec" function as ssh.
# It's mostly syntactic sugar to convert from "ssh" syntax
# to "kubectl exec" syntax.

PROG = "kubessh"
VERSION = "0.0.1"


def parse_args():

    d = ("Execute into a pod on Kubernetes with an SSH-compatible syntax."
         " In other words, make 'kubectl exec' appear and function as a"
         " replacement for the 'ssh' command-line tool, and support a"
         " compatible syntax.\n\n"
         "Contrary to standard 'ssh', %(prog)s will not run a login shell,"
         " but will follow standard 'kubectl exec' semantics instead, and"
         " will run the specified command using the container's entrypoint"
         " instead.")

    p = argparse.ArgumentParser(prog=PROG, description=d)

    p.add_argument("-v", dest="verbose", action="store_true",
                   help=("Enable verbose mode. Output diagnostic messages"
                         " to stderr."))

    p.add_argument("-V", dest="version", action="store_true",
                   help="Output version information to stderr, and exit.")

    p.add_argument("-l", metavar="POD_NAME[:CONTAINER_NAME]", dest="pod",
                   action="store",
                   help=("Exec into pod POD_NAME. Optionally specify"
                         " a non-default CONTAINER_NAME."))

    p.add_argument("-n", dest="pass_stdin", action="store_false",
                   help=("Prevent reading from stdin, do not pass the '-i'"
                         " option to 'kubectl exec'. Default is to use '-i',"
                         " and pass stdin."))

    p.add_argument("-p", dest="port", action="store", type=int,
                   help=("This argument exists only to ensure compatibility"
                         " with 'ssh', and is ignored. %(prog)s ignores"
                         " PORT, but it must be a valid port number,"
                         " if specified."))
    p.add_argument("destination",
                   help=("Exec into the specified destination,"
                         " which may be specified as"
                         " pod[:container][@namespace],"
                         " or a URI of the form"
                         " ssh://pod[:container][@namespace[:port]]."
                         " Note: It is mandatory to specify the pod name,"
                         " either via 'destination' or via the '-l' argument."
                         " Note: %(prog)s will ignore 'port' if specified."))

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

    pod = vars(args).get("pod")

    # FIXME
    # destination may just be the pod name, and pod is the only required
    # argument, so the semantics don't add up very nicely compared to 'ssh'.
    #

    # Parse the 'destination' argument into
    # separate 'pod', 'namespace' arguments,
    # and check them for correctness.
    s = args.destination.split("@")
    if s[0] and pod is not None:
        raise ValueError("Cannot specify pod name via 'destination' when"
                         " using the '-l' argument.")
        pod = s[0]
    namespace = "@".join(s[1:])

    container = None
    if ":" in pod:
        s = pod.split(":")
        pod = s[0]
        container = s[1]

    port = args.port
    if ":" in namespace:
        if port is not None:
            raise ValueError("Cannot specify port number via 'destination'"
                             " when using the '-p' argument.")
        s = namespace.split(":")
        namespace = s[0]
        try:
            port = int(":".join(s[1:]))
        except ValueError:
            raise ValueError("If specified, port must be an integer,"
                             " and cannot be empty.")

    if pod is None:
        raise ValueError("You must specify a pod name,"
                         "either via '-l' or via 'destination'.")
    if container is not None and container == "":
        raise ValueError("If specified, container name cannot be empty.")
    if port is not None and port <= 0:
        raise ValueError("If specified, port must be a positive integer.")
    if not namespace:
        raise ValueError("Namespace cannot be empty.")

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
