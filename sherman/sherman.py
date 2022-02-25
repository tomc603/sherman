#!/usr/bin/env python3

import argparse
from collections import UserDict
import getpass
import logging
import os
import select
import socket
import sys
import termios
import tty

import fabric
import paramiko

from paramiko.py3compat import u


# Overview:
# Sherman connects to remote hosts, and executes the commands within each "job" module through those connections.
# Optionally, connections may be made through a Proxy server. If a proxy server is utilized, multiple connections
# may be made through a single proxy to keep the total number of connections low.

# TODO:
#   Convert to using Fabric
#     * c: fabric.Connection
#   Make a CLI for various common commands
#     * Create job scripts for common functions
#     * For script jobs, send script to remote server & run it
#     * Run common commands on remote server
#     * Optionally log all output, command output
#     * Use fabric.group.ThreadingGroup when running commands on multiple servers

DEFAULT_TIMEOUT = 10.0
DEFAULT_PORT = 22
PROMPT_SUDO_RE = r'\[sudo\] password for '
PROMPT_2FA_RE = r'Duo two-factor login'

logging.basicConfig(level=logging.DEBUG)
logging.getLogger(__name__).setLevel(logging.DEBUG)
logging.getLogger('paramiko').setLevel(logging.DEBUG)

logger = logging.getLogger()
logger.setLevel(logging.WARNING)


class Entry(object):
    children: list = []
    connection: fabric.Connection = None
    distinct: bool = False
    hostname: str = ''
    parent: str = None

    def __init__(self, hostname='', connection=None, distinct=False):
        self.connection = connection
        self.distinct = distinct
        self.hostname = hostname

    def close(self):
        # Walk child connections, closing each
        # Close our connection
        # Remove our entry from the children list of our parent
        # If parent's children list is empty AND distinct != True, call parent's close() function
        # Remove our entry from the connection list
        pass


class ConnectionRegistry(UserDict):
    def connect(self, hostname, distinct=True):
        # If the hostname already exists in the registry, return its connection value
        if hostname in self.data:
            return self.data[hostname].connection

        # Add a ConnectionRegistry entry for this host
        self.data[hostname]: Entry = Entry(hostname=hostname, connection=None, distinct=distinct)

        ssh_config = fabric.config.SSHConfig().from_path('.sshconfig')
        fab_config = fabric.Config(ssh_config=ssh_config)
        fab_config.load_base_conf_files()

        # If a ProxyJump gateway is configured, connect to it, add it to the connection registry,
        # add our hostname as an entry in the children list, and pass its connection as the
        # gateway for the current connection.
        gateway = None
        if 'proxyjump' in ssh_config.lookup(hostname):
            gateway_hostname = ssh_config.lookup(hostname)['proxyjump']
            gateway = self.connect(gateway_hostname, distinct=False)
            self.data[gateway_hostname].children.append(hostname)

        self.data[hostname].connection = fabric.Connection(hostname, gateway=gateway)
        return self.data[hostname].connection

    def __disconnect__(self, hostname):
        """Recursively disconnect hostname and its children

        :param hostname: The hostname to disconnect from
        :type hostname: str
        """
        if hostname in self.data:
            # Recurse through the children of this connection, and disconnect each of them.
            for child_name in self.data[hostname].children:
                self.__disconnect__(hostname)

            # Handle our parent if we have one
            parent = self.data[hostname].parent
            if parent:
                # Remove ourselves from our parent's children list
                self.data[parent].children.remove(hostname)

            # Disconnect the connection for hostname
            self.data[hostname].connection.close()

    def disconnect(self, hostname):
        """Disconnect from hostname, its children, and clean up idle connections"""
        if hostname in self.data:
            # Disconnect the connection for hostname and its children
            self.__disconnect__(hostname)

            # Remove our hostname from our predecessor's children list
            parent = self.data[hostname].parent
            if parent:
                # Recursively close our predecessors if they're no longer in use
                if not self.data[parent].children and not self.data[parent].distinct:
                    self.disconnect(parent)

        # Clean up idle connections
        self.disconnect_idle()

    def disconnect_idle(self):
        """Close connections that were made as proxies and are no longer needed"""
        for hostname in self.data:
            if not self.data[hostname].children and not self.data[hostname].distinct:
                logger.info(f'Disconnecting idle connection for {hostname}')
                self.__disconnect__(hostname)


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
        c: fabric.Connection = connections.connect(hostname)
        c.connect_timeout=DEFAULT_TIMEOUT

        # c.load_host_keys('sherman_host_keys')
        # c.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        # c.connect(hostname, 22, username, timeout=10, compress=True)
        # c.save_host_keys('sherman_host_keys')

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

# except paramiko.AuthenticationException as ex:
#   logger.error(f'Error: Authentication error for {c}. {ex}')
#   return
# except paramiko.BadHostKeyException as ex:
#   print(f'Error: Bad host key for {hostname}. {ex}')
#   return
# except paramiko.SSHException as ex:
#   print(f'Error: SSH exception for {hostname}. {ex}')
#   return
# except socket.error as ex:
#   print(f'Error: Socket error for {hostname}. {ex}')
#   return
# finally:
#   # Close the SSH connection
#   close_connection(hostname)


connections = ConnectionRegistry()


if __name__ == '__main__':
    host_list = []
    # TODO:
    #   Use Fabric Group management to handle a pool of devices
    #     * fabric.group.ThreadingGroup
    #   Retrieve results from commands and write to local per-server log files

    # TODO: When user is NONE, use the SSH config, then fall back to current OS user.
    # TODO: If user _is_ specified, use it before SSH config.
    ap = argparse.ArgumentParser(description='Collect SMART data from remote hosts.')
    ap.add_argument('-d', '--debug', action='store_true', help='Enable diagnostic output.')
    ap.add_argument('-H', '--hostfile', nargs='?', type=str, help='File containing a list of hosts.')
    ap.add_argument('hosts', nargs='*', type=str, help='One or more hosts to poll.')
    ap.add_argument('-l', '--logpath', nargs='?', type=str, help='Path to output host log files.')
    ap.add_argument('-p', '--parallel', type=int, default=10, help='Path to output host log files.')
    ap.add_argument('-u', '--user', type=str, default=getpass.getuser(), help='Remote host username.')
    args = ap.parse_args()

    if args.logpath is not None and args.logpath != '':
        if not os.path.isdir(args.logpath):
            print(f'Error: Log path {args.logpath} does not exist.')
            sys.exit(1)

    if args.hostfile is not None:
        # A file of hosts was specified on the command line
        with open(args.hostfile, 'r') as host_file:
            host_lines = host_file.readlines()
            for host_line in host_lines:
                host_list.append(host_line.strip())
    elif args.hosts:
        # A list of hosts was specified on the command line
        host_list = args.hosts.copy()
    else:
        # The command line list is empty, and there was no host file specified
        print('Error: You must specify a host, or a file containing a list of hosts.')
        ap.print_help()
        sys.exit(1)

    if args.parallel < 1:
        print(f'Error: Parallel must be greater than 0.')
        ap.print_help()
        sys.exit(1)
    client("server.domain.tld", "tom")
