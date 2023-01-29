# KubeSSH

KubeSSH brings an SSH-like experience to running commands on Kubernetes pods.

On one hand, SSH is the venerable tool to execute commands securely on remote
nodes, which requires a remote server like OpenSSH's `sshd` to run on the
remote host.

On the other hand, Kubernetes admins can use `kubectl exec` to run commands on
Kubernetes pod. However, this has a few issues:

* Its syntax is rather cumbersome
* It doesn't have simple defaults for interactive use
* It is not a drop-in `ssh` replacement, so it can't function with tools like
  `git` or `rsync`.

KubeSSH wraps `kubectl exec` and makes it a drop-in replacement for SSH. In
other words it makes it appear and function as a replacement for the OpenSSH
client, by making it support a compatible syntax and most commonly-used
command-line arguments.

In fact, you can even use it as your everyday `ssh` tool, to exec into remote
hosts and Kubernetes containers seamlessly, with a single, simple syntax.
For more details, see section [Use as ssh](#-use-as-ssh) below.

**IMPORTANT:** This *still* uses `kubectl exec` underneath, so it doesn't
expose any extra services to the network [e.g., `sshd`]. It just connects to
the Kubernetes API server directly, and uses the exact same authorization
mechanism, Kubernetes RBAC.


## Interactive use

KubeSSH simplifies interactively executing into a container. For example:

<!--- NOTE use of two spaces at the end of a line to force a line break. This
is on purpose, do not modify. -->
* **Start a shell.**  
  With kubectl:
     ```console
     $ kubectl exec -it mypod -- /bin/sh
     ```
  With KubeSSH:
     ```console
     $ kubessh mypod
     ```

* **Get a shell in a specific container of a pod in a non-default namespace.**  
  With kubectl:
     ```console
     $ kubectl exec -c mycontainer -n myspace mypod -- /bin/bash
     ```
  With KubeSSH:
     ```console
     $ kubessh mycontainer@mypod.myspace
     ```

* **Run a more complex command pipeline on the container.**  
  With kubectl:
     ```console
     $ kubectl exec mypod -- /bin/bash -c 'mkdir /a/dir && touch /a/dir/file'
     ```
  With KubeSSH:
     ```console
     $ kubessh mypod 'mkdir /a/dir && touch /a/dir/file'
     ```

## Cool hacks

KubeSSH enables a set of cool hacks when combined with tools that already know
h ow to exec into a remote location using SSH. For example:

* Push your git branch into a remote container, using just `git`, no server
  required.
* Push whole directory trees into remote containers efficiently, using `rsync`.
* Debug processes running in remote containers using `gdb`, no other tools
  required.


## Design

KubeSSH mimics standard `ssh` behavior and implements a set of heuristics by
default to simplify its use, especially in interactive scenarios:

* It passes standard input to the remote process by default, so you don't have
  to specify `-i` manually every single time.
* It allocates a TTY automatically when it makes sense to do so, so you don't
  have to specify `-t` manually every single time.
* It implements an intuitive syntax to define the destination in a format
  similar to SSH. For example, all of the following work: `pod`,
  `pod.namespace`, `container@pod.namespace`, `svc/service.namespace`,
  `container@sts/statefulset1.namespace`, and do the expected thing.
* It parses its command line similarly to `ssh` and stops when it finds the
  name of the command to run on the remote, so you don't need to specify `--`
  all the time.
* It spawns a shell in the container to run your command, similarly to SSH, so
  you can run pretty complex pipelines directly from the command prompt, but
  you can disable this behavior if you need to have fine-grained control over
  the actual argument list, see the `--no-shell` argument.


## Install

KubeSSH is currently under heavy development.
This section describes how to install it in development mode, so you can make
changes to the code and see it run immediately.

1. Clone this repository:
      ```console
      $ git clone https://github.com/...
      ```
2. Create a new virtualenv for development:
      ```console
      $ mkvirtualenv -p python3 kubessh
      ```
3. Install the code in development mode:
      ```console
      $ python setup.py develop
      ```
4. Confirm the `kubessh` script is now available:
      ```console
      $ kubessh --help
      usage: kubessh [-h] [-v] [-V] [-l CONTAINER_NAME] [-n] [-p PORT] [-t | -T]
                     [--no-shell]
                     destination [command] ...
      ```


## Run tests

This section describes how to run coding style and unit tests for KubeSSH.

1. Install the `flake8` and `pytest` packages:
      ```console
      $ pip install flake8 pytest
      ```

2. Run coding style tests:
      ```console
      $ flake8
      ```

3. Run unit tests:
      ```console
      $ pytest
      ```


## Use as ssh

KubeSSH supports being your single 'ssh' executable via the `--ssh-passthrough`
argument. In SSH passthrough mode, KubeSSH will exec the standard 'ssh'
executable in your $PATH, and pass the full command line to it, excluding
KubeSSH-specific arguments [`--no-shell`, `--ssh-passthrough`].

KubeSSH will only activate if the hostname starts with the magic prefix `k8s_`.
This enables using KubeSSH as your everyday `ssh` tool for all kinds of remote
connections, both for standard SSH and for exec-int into Kubernetes pods via
`kubectl exec`.

There are at least two ways to enable this mode:

* **Option 1: Shell alias.** You wil need to set an alias in your shell.
* **Option 2: Two symbolic links.** You will need to configure two symbolic
  links, `ssh`, `ssh.real` in a directory that lives in your `$PATH` before the
  current location of `ssh`.

Option 2 enables `git`, `rsync` or any other tool to work directly with your
Kubernetes pods, without any extra configuration.


### Option 1: Shell alias

For this option, you will define a new shell alias, `ssh` pointing to KubeSSH.
How to define a new alias depends on your shell. The following instructions
work for Bash, instructions for other shells are more than welcome.

**Bash:** Edit `.bashrc` and add a line to configure `ssh` as an
alias, pointing to `kubessh --ssh-passthrough`:
  ```bash
  alias ssh='kubessh --ssh-passthrough'
  ```
Restart your shell, and verify the alias is there:
   ```console
   $ type ssh
   ssh is aliased to `kubessh --ssh-passthrough'
   ```

Finally, confirm everything is working properly:
   ```console
   $ ssh -V
   $ ssh --ssh-test user@host
   KubeSSH version 0.0.1 [location: /home/user/venvs/py38/bin/kubessh]. About to execute: /usr/bin/ssh
   OpenSSH_8.2p1 Ubuntu-4ubuntu0.5, OpenSSL 1.1.1f  31 Mar 2020

   ```


### Option 2: Two symbolic links

For this option, you'll create two new symbolic links in a directory which
exists in your `$PATH`, before the current location of your `ssh` binary.

First, confirm the current location of `ssh`:
   ```console
   $ which ssh
   /usr/bin/ssh
   ```

In this example, it lives under `/usr/bin`, so you must create any symbolic
links in a directory which lives before `/usr/bin` in your `$PATH`.

Inspect the value of `$PATH` to decide on a directory. A good choice would be
`$HOME/bin`, or `$VIRTUAL_ENV/bin`, if using a Python virtual environment.

Decide on a choice and set `$BINDIR` accordingly:
   ```console
   $ echo $PATH
   $ ls -ld $VIRTUAL_ENV/bin
   $ ls -ld $HOME/bin
   $ BINDIR=$HOME/bin
   ```

Finally, create a symbolic link called `ssh.real` pointing to the location of
your original `ssh`, and a symbolic link called `ssh` pointing to `kubessh`:
   ```console
   $ cd $BINDIR
   $ which ssh
   $ ln -s $(which ssh) ssh.real
   $ ln -s $(which kubessh) ssh
   $ hash -r
   ```

It should look similar to this:
   ```console
   $ ls -l ssh*
   lrwxrwxrwx 1 user user 42 Jan 29 00:48 ssh -> /home/user/venvs/py38/bin/kubessh*
   lrwxrwxrwx 1 user user 12 Jan 29 00:48 ssh.real -> /usr/bin/ssh*
   ```

Finally, confirm everything is working properly:
   ```console
   $ ssh -V
   $ ssh --ssh-test user@host
   KubeSSH version 0.0.1 [location: /home/user/venvs/py38/bin/kubessh]. About to execute: /usr/bin/ssh
   OpenSSH_8.2p1 Ubuntu-4ubuntu0.5, OpenSSL 1.1.1f  31 Mar 2020
   ```
