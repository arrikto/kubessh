KubeSSH
=======

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

<!--- In fact, you can even use it as your everyday `ssh`
tool, to exec into remote hosts and Kubernetes containers seamlessly, with a
single, simple syntax. -->

**IMPORTANT:** This *still* uses `kubectl exec` underneath, so it doesn't
expose any extra services to the network [e.g., `sshd`]. It just connects to
the Kubernetes API server directly, and uses the exact same authorization
mechanism, Kubernetes RBAC.


Interactive use
---------------

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
     $ kubectl exec -c mycontainer -n mynamespace mypod -- /bin/bash
     ```
  With KubeSSH:
     ```console
     $ kubessh mycontainer@mypod.mynamespace
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

Cool hacks
----------

KubeSSH enables a set of cool hacks when combined with tools that already know
h ow to exec into a remote location using SSH. For example:

* Push your git branch into a remote container, using just `git`, no server
  required.
* Push whole directory trees into remote containers efficiently, using `rsync`.
* Debug processes running in remote containers using `gdb`, no other tools
  required.


Design
------

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


Install
-------

KubeSSH is currently under heavy development.
Here is how to install KubeSSH:

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
