#!/usr/bin/env python3

import paramiko
import termios
import socket
import select
import sys
import tty

from paramiko.py3compat import u


def shell(channel: paramiko.channel.Channel):
    original_tty_attribs = termios.tcgetattr(sys.stdin)

    try:
        tty.setraw(sys.stdin.fileno())
        tty.setcbreak(sys.stdin.fileno())
        channel.settimeout(0.0)

        while True:
            r, w, e = select.select([channel, sys.stdin], [], [])
            if channel in r:
                try:
                    data = u(channel.recv(1024))
                    if len(data) == 0:
                        sys.stdout.write("\r\nSession Closed.\r\n")
                        break
                    sys.stdout.write(data)
                    sys.stdout.flush()
                except socket.timeout:
                    pass
            if sys.stdin in r:
                data = sys.stdin.read(1)
                if len(data) == 0:
                    break
                channel.send(data)

    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, original_tty_attribs)


def client(hostname, username):
    c = paramiko.SSHClient()
    c.load_system_host_keys()
    c.connect(hostname, 22, username, timeout=10, compress=True)
    chan = c.invoke_shell()
    shell(chan)


if __name__ == '__main__':
    client("rhodes", "tom")
