from pwn import *
from dpwn import dockerized

# context.log_level = 'debug'

context.terminal = [ '/home/ohk990102/vscode-terminal' ]

if __name__ == "__main__":
    p = dockerized('./realloc', baseimage='ubuntu:19.04', prefer_dockerfile=False, withgdb=True)
    gdb.attach(p.gdbsock, exe='./realloc')
    p.interactive()