#!/usr/bin/env python3

import argparse

import fabric
import getpass
import logging
import multiprocessing as mp
import os
import paramiko
import re
import socket
import sys


logging.basicConfig(level=logging.DEBUG)
logging.getLogger(__name__).setLevel(logging.DEBUG)
logging.getLogger('paramiko').setLevel(logging.DEBUG)


DEFAULT_TIMEOUT = 10.0
DEFAULT_PORT = 22
PROMPT_SUDO_RE = r'\[sudo\] password for '
PROMPT_2FA_RE = r'Duo two-factor login'

# Cache for host connections
connection_registry = {
    'gateway.host.tld': {
        'connection': fabric.Connection,
        'parent': None,
        'children': ['proxy.host.tld', 'some_other.host.tld']
    },
    'proxy.host.tld': {
        'connection': fabric.Connection,
        'parent': 'gateway.host.tld',
        'children': ['example.host.tld']
    },
    'example.host.tld': {
        'connection': fabric.Connection,
        'parent': 'proxy.host.tld'
    },
    'some_other.host.tld': {
        'connection': fabric.Connection,
        'parent': 'gateway.host.tld'
    }
}

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()
logger.setLevel(logging.WARNING)


def close_connection(hostname: str):
    """
    Close the connection for the specified host. If the connection has child connections, iterate through them,
    calling this function recursively. Remove our child entry if we have a parent connection (gateway/proxy).
    Finally, remove our connection entry from connection_registry.

    :param hostname: Host name of the connected host.
    :type hostname: str
    """
    try:
        children = connection_registry[hostname]['children']
        if children:
            for child in children:
                close_connection(child)
    except KeyError:
        pass

    try:
        parent = connection_registry[hostname]['parent']
        if parent:
            connection_registry[parent]['children'].remove(hostname)
    except KeyError:
        pass

    try:
        connection = connection_registry[hostname]['connection']
        connection.close()
        del(connection_registry[hostname])
    except KeyError:
        pass


def open_connection(hostname: str):
    """
    Open a connection for the specified host. If the host has a ProxyJump server specified, connect through that proxy
     and add a a child entry to its children list. Finally, add our connection entry to connection_registry.

    :param hostname: Host name of the desired host.
    :type hostname: str
    :return A Connection for the specified hostname
    :rtype fabric.Connection
    """
    if hostname in connection_registry:
        return connection_registry[hostname]['connection']

    ssh_config = fabric.config.SSHConfig().from_path('.sshconfig')
    fab_config = fabric.Config(ssh_config=ssh_config)
    fab_config.load_base_conf_files()

    # If a ProxyJump gateway is configured, pass it as the gateway for the current connection.
    # Cache the gateway connection so we can reuse it for future host connections
    gateway = None
    gateway_hostname = ''
    if 'proxyjump' in ssh_config.lookup(hostname):
        gateway_hostname = ssh_config.lookup(hostname)['proxyjump']
        gateway = open_connection(gateway_hostname)
        connection_registry[gateway_hostname]['children'].append(hostname)

    connection = fabric.Connection(hostname, gateway=gateway)
    connection_registry[hostname] = {'children': [], 'parent': gateway_hostname, 'connection': connection}
    return connection_registry[hostname]['connection']


def fab_smartctl(c: fabric.Connection, logpath: str = None):
    device_pattern = r'(sd[a-z]+)\n'
    device_re = re.compile(device_pattern)
    scsi_devices = []

    sftp = c.sftp()
    dev_contents = sftp.listdir('/dev')
    scsi_devices = device_re.findall('\n'.join(dev_contents))
    sftp.close()

    for scsi_device in scsi_devices:
        output = ''

        logging.info(f'Polling /dev/{scsi_device}')
        r = c.sudo(f'/usr/sbin/smartctl -x /dev/{scsi_device}')


def client(hostname, username, logpath):
    c = open_connection(hostname)
    if c is None:
        print(f'Connection to {hostname} failed.')
        return

    try:
        fab_smartctl(c, logpath=logpath)
    except paramiko.AuthenticationException as ex:
        print(f'Error: Authentication error for {username}@{hostname}. {ex}')
        return
    except paramiko.BadHostKeyException as ex:
        print(f'Error: Bad host key for {hostname}. {ex}')
        return
    except paramiko.SSHException as ex:
        print(f'Error: SSH exception for {hostname}. {ex}')
        return
    except socket.error as ex:
        print(f'Error: Socket error for {hostname}. {ex}')
        return
    finally:
        # Close the SSH connection
        close_connection(hostname)


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

    worker_pool = mp.Pool(processes=args.parallel)
    [worker_pool.apply(client, args=(host, args.user, args.logpath,)) for host in host_list]

    # TODO: Parallelize the host connections by creating worker pools and submitting jobs
    # for host in host_list:
    #     client(hostname=host, username=args.user, logpath=args.logpath)
