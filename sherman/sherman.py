#!/usr/bin/env python3

import fabric
import paramiko
import termios
import socket
import select
import sys
import tty

from paramiko.py3compat import u


# TODO:
#   Send script to remote server
#   Run script on remote server
#   Save script output to log file on remote server
#   Transfer log file from remote server

def send_file(channel: paramiko.channel.Channel, localpath: str, remotepath: str):
    try:
        sftp_client = channel.transport.open_sftp_client()
        sftp_file_attribs = sftp_client.put(localpath, remotepath, confirm=True)
        sftp_client.close()
    except paramiko.ChannelException as ex:
        print(f'Error: sftp put failed. {ex}')


def run_command(client: paramiko.client.SSHClient, cmd):
    try:
        stdin, stdout, stderr = client.exec_command(cmd)
        stdin.close()
        print(u(stdout.read()))
        print(u(stderr.read()))
        status = stdout.channel.recv_exit_status()
        print(f'Status: {status}')
        stdout.close()
        stderr.close()

    except paramiko.ssh_exception.SSHException as ex:
        print(f'Error: SSH exception while running remote command. {ex}')


def retrieve_log(channel: paramiko.channel.Channel, remotepath: str, localpath: str):
    try:
        sftp_client = channel.transport.open_sftp_client()
        sftp_client.get(remotepath, localpath)
        sftp_client.remove(remotepath)
        sftp_client.close()
    except paramiko.ChannelException as ex:
        print(f'Error: sftp get failed. {ex}')


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
    try:
        c = paramiko.SSHClient()
        c.load_system_host_keys()
        c.load_host_keys('sherman_host_keys')
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        c.connect(hostname, 22, username, timeout=10, compress=True)
        c.save_host_keys('sherman_host_keys')
    except paramiko.ssh_exception.AuthenticationException as ex:
        print(f'Error: Authentication error for {username}@{hostname}. {ex}')
    except paramiko.ssh_exception.BadHostKeyException as ex:
        print(f'Error: Bad host key for {hostname}. {ex}')
    except paramiko.ssh_exception.SSHException as ex:
        print(f'Error: SSH exception for {hostname}. {ex}')
    except socket.error as ex:
        print(f'Error: Socket error for {hostname}. {ex}')

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
