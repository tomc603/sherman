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

    # Transfer any necessary script files to the remote host
    # sftp = c.open_sftp()
    # sftp.close()

    # Execute commands on the server
    chStdIn, chStdOut, chStdErr = c.exec_command('find /sys', timeout=1.0)
    chStdIn.close()
    print(u(chStdOut.read()))
    print(u(chStdErr.read()))
    status = chStdOut.channel.recv_exit_status()
    print('Status: {}'.format(status))
    chStdOut.close()
    chStdErr.close()

    # Execute a shell on the remote server
    # chan = c.invoke_shell()
    # shell(chan)
    # chan.close()

    # Close the SSH connection
    c.close()


if __name__ == '__main__':
    client("server.domain.tld", "tom")
