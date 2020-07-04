import ctypes
import errno
import logging
import os
import platform
import select
import signal
import six
import stat
import subprocess
import sys
import time
import socket

if sys.platform != 'win32':
    import fcntl
    import pty
    import resource
    import tty

from pwnlib import qemu
from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.timeout import Timeout
from pwnlib.tubes.tube import tube
from pwnlib.tubes.remote import remote
from pwnlib.util.hashes import sha256file
from pwnlib.util.misc import parse_ldd_output
from pwnlib.util.misc import which

from io import BytesIO
import docker
import dockerpty

log = getLogger(__name__)

class PTY(object): pass
PTY=PTY()
STDOUT = subprocess.STDOUT
PIPE = subprocess.PIPE

signal_names = {-v:k for k,v in signal.__dict__.items() if k.startswith('SIG')}

class dockerized(tube):
    def __init__(self, argv = None,
                 shell = False,
                 executable = None,
                 cwd = None,
                 env = None,
                 stdin  = PIPE,
                 stdout = PTY,
                 stderr = STDOUT,
                 close_fds = True,
                 preexec_fn = lambda: None,
                 raw = True,
                 aslr = None,
                 setuid = None,
                 where = 'local',
                 display = None,
                 alarm = None,
                 prefer_dockerfile = True,
                 baseimage = None,
                 withgdb = True,
                 gdbport = 1234,
                 reload = True,
                 *args,
                 **kwargs
                 ):
        super(dockerized, self).__init__(*args, **kwargs)

        # Permit using context.binary
        if argv is None:
            if context.binary:
                argv = [context.binary.path]
            else:
                raise TypeError('Must provide argv or set context.binary')


        #: :class:`subprocess.Popen` object that backs this process
        self.proc = None

        # We need to keep a copy of the un-_validated environment for printing
        original_env = env

        if shell:
            executable_val, argv_val, env_val = executable, argv, env
        else:
            executable_val, argv_val, env_val = self._validate(cwd, executable, argv, env)

        # Avoid the need to have to deal with the STDOUT magic value.
        if stderr is STDOUT:
            stderr = stdout

        # Determine which descriptors will be attached to a new PTY
        handles = (stdin, stdout, stderr)

        #: Which file descriptor is the controlling TTY
        self.pty          = handles.index(PTY) if PTY in handles else None

        #: Whether the controlling TTY is set to raw mode
        self.raw          = raw

        #: Whether ASLR should be left on
        self.aslr         = aslr if aslr is not None else context.aslr

        #: Whether setuid is permitted
        self._setuid      = setuid if setuid is None else bool(setuid)

        # Create the PTY if necessary
        stdin, stdout, stderr, master, slave = self._handles(*handles)

        #: Arguments passed on argv
        self.argv = argv_val

        #: Full path to the executable
        self.executable = executable_val

        if self.executable is None:
            if shell:
                self.executable = '/bin/sh'
            else:
                self.executable = which(self.argv[0])

        #: Environment passed on envp
        self.env = os.environ if env is None else env_val

        self._cwd = os.path.realpath(cwd or os.path.curdir)

        #: Alarm timeout of the process
        self.alarm        = alarm

        self.preexec_fn = preexec_fn
        self.display    = display or self.program

        message = "Starting %s process %r" % (where, self.display)

        if self.isEnabledFor(logging.DEBUG):
            if argv != [self.executable]: message += ' argv=%r ' % self.argv
            if original_env not in (os.environ, None):  message += ' env=%r ' % self.env

        ## Make new Dockerfile
        self.prefer_dockerfile = prefer_dockerfile
        self.baseimage = baseimage
        self.withgdb = withgdb
        self.gdbport = gdbport

        if (not os.path.isfile(os.path.join(self._cwd, 'Dockerfile'))) or (not self.prefer_dockerfile):
            dockerfile = f'''FROM {self.baseimage}
RUN mkdir -p {self._cwd}
WORKDIR {self._cwd}
COPY ./ ./
RUN chmod +x {self.executable}
'''
            if self.withgdb:
                dockerfile += f'''RUN apt-get update && apt-get install -y gdb gdbserver && rm -rf /var/lib/apt/lists/*
EXPOSE {self.gdbport}
'''
            dockerfile += '''CMD [ '''
            dockerfile += ', '.join(map(lambda a: f'"{a.decode("utf-8")}"', self.argv))
            dockerfile += ' ]\n'
            with open(os.path.join(self._cwd, 'Dockerfile'), 'w') as f:
                f.write(dockerfile)
        
        self.docker_image_tag = f'pwntools_{os.path.basename(self.executable)}'
        self.docker_container_name = self.docker_image_tag
        self.reload = reload
        
        client = docker.from_env()
        self.debug(f'Starting to build image with tag {self.docker_image_tag}')
        client.images.build(tag=self.docker_image_tag, path=self._cwd)
        self.success(f'Built image with tag {self.docker_image_tag}')
        try:
            container = client.containers.get(self.docker_container_name)
            if not self.reload:
                raise RuntimeError("Container with same name already exist. ")
            if container.attrs['Config']['Image'] != self.docker_image_tag:
                self.warn(f"Removing container with name {self.docker_container_name} and image {container.attrs['Config']['Image']}")
            container.remove(force=True)
        except docker.errors.NotFound:
            pass
        
        self.container = client.containers.run(self.docker_image_tag, name=self.docker_container_name, privileged=self.withgdb, ports={f'{self.gdbport}/tcp': ('127.0.0.1', self.gdbport)}, stdin_open=True, detach=True)
        self.container_sock_stdin_demuxed = dockerpty.io.Demuxer(self.container.attach_socket(params={'stdin': 1, 'stream': 1}))
        self.container_sock_stdout_demuxed = dockerpty.io.Demuxer(self.container.attach_socket(params={'stdout': 1, 'stderr': 1, 'stream': 1, 'logs': 1}))

        if self.withgdb:
            self.container.exec_run(['gdbserver', '--attach', '0.0.0.0:1234', '1'], privileged=True, detach=True)
            self.gdbsock = ('127.0.0.1', self.gdbport)

    def send_raw(self, data):
        if not self.container_sock_stdin_demuxed.stream.writable:
            raise EOFError
        
        try:
            self.container_sock_stdin_demuxed.stream._sock.send(data)
        except IOError:
            raise EOFError
    
    def recv_raw(self, numb):
        if not self.container_sock_stdout_demuxed.stream.readable:
            raise EOFError
        
        data = ''
        try:
            data = self.container_sock_stdout_demuxed.read(numb)
        except IOError:
            pass
        
        return data
        
    def _validate(self, cwd, executable, argv, env):
        """
        Perform extended validation on the executable path, argv, and envp.

        Mostly to make Python happy, but also to prevent common pitfalls.
        """

        cwd = cwd or os.path.curdir

        #
        # Validate argv
        #
        # - Must be a list/tuple of strings
        # - Each string must not contain '\x00'
        #
        if isinstance(argv, (six.text_type, six.binary_type)):
            argv = [argv]

        if not isinstance(argv, (list, tuple)):
            self.error('argv must be a list or tuple: %r' % argv)

        if not all(isinstance(arg, (six.text_type, six.binary_type)) for arg in argv):
            self.error("argv must be strings or bytes: %r" % argv)

        # Create a duplicate so we can modify it
        argv = list(argv or [])

        for i, oarg in enumerate(argv):
            if isinstance(oarg, six.text_type):
                arg = oarg.encode('utf-8')
            else:
                arg = oarg
            if b'\x00' in arg[:-1]:
                self.error('Inappropriate nulls in argv[%i]: %r' % (i, oarg))
            argv[i] = arg.rstrip(b'\x00')

        #
        # Validate executable
        #
        # - Must be an absolute or relative path to the target executable
        # - If not, attempt to resolve the name in $PATH
        #
        if not executable:
            if not argv:
                self.error("Must specify argv or executable")
            executable = argv[0]

        if not isinstance(executable, str):
            executable = executable.decode('utf-8')

        # Do not change absolute paths to binaries
        if executable.startswith(os.path.sep):
            pass

        # If there's no path component, it's in $PATH or relative to the
        # target directory.
        #
        # For example, 'sh'
        elif os.path.sep not in executable and which(executable):
            executable = which(executable)

        # Either there is a path component, or the binary is not in $PATH
        # For example, 'foo/bar' or 'bar' with cwd=='foo'
        elif os.path.sep not in executable:
            tmp = executable
            executable = os.path.join(cwd, executable)
            self.warn_once("Could not find executable %r in $PATH, using %r instead" % (tmp, executable))

        if not os.path.exists(executable):
            self.error("%r does not exist"  % executable)
        if not os.path.isfile(executable):
            self.error("%r is not a file" % executable)
        if not os.access(executable, os.X_OK):
            self.error("%r is not marked as executable (+x)" % executable)

        #
        # Validate environment
        #
        # - Must be a dictionary of {string:string}
        # - No strings may contain '\x00'
        #

        # Create a duplicate so we can modify it safely
        env = os.environ if env is None else env

        env2 = {}
        for k,v in env.items():
            if not isinstance(k, (bytes, six.text_type)):
                self.error('Environment keys must be strings: %r' % k)
            if not isinstance(k, (bytes, six.text_type)):
                self.error('Environment values must be strings: %r=%r' % (k,v))
            if isinstance(k, six.text_type):
                k = k.encode('utf-8')
            if isinstance(v, six.text_type):
                v = v.encode('utf-8', 'surrogateescape')
            if b'\x00' in k[:-1]:
                self.error('Inappropriate nulls in env key: %r' % (k))
            if b'\x00' in v[:-1]:
                self.error('Inappropriate nulls in env value: %r=%r' % (k, v))
            env2[k.rstrip(b'\x00')] = v.rstrip(b'\x00')

        return executable, argv, env2
        
    def _handles(self, stdin, stdout, stderr):
        master = slave = None

        if self.pty is not None:
            # Normally we could just use PIPE and be happy.
            # Unfortunately, this results in undesired behavior when
            # printf() and similar functions buffer data instead of
            # sending it directly.
            #
            # By opening a PTY for STDOUT, the libc routines will not
            # buffer any data on STDOUT.
            master, slave = pty.openpty()

            if self.raw:
                # By giving the child process a controlling TTY,
                # the OS will attempt to interpret terminal control codes
                # like backspace and Ctrl+C.
                #
                # If we don't want this, we set it to raw mode.
                tty.setraw(master)
                tty.setraw(slave)

            if stdin is PTY:
                stdin = slave
            if stdout is PTY:
                stdout = slave
            if stderr is PTY:
                stderr = slave

        return stdin, stdout, stderr, master, slave
    
    @property
    def program(self):
        """Alias for ``executable``, for backward compatibility.

        Example:

            >>> p = process('true')
            >>> p.executable == '/bin/true'
            True
            >>> p.executable == p.program
            True

        """
        return self.executable
