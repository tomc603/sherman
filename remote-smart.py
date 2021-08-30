#!/usr/bin/env python3

import argparse
import getpass
import logging
import multiprocessing as mp
import os

import invoke
import paramiko
import re
import socket
import sys

import fabric as fab

logging.basicConfig(level=logging.DEBUG)
logging.getLogger(__name__).setLevel(logging.DEBUG)
logging.getLogger('paramiko').setLevel(logging.DEBUG)


DEFAULT_TIMEOUT = 10.0
DEFAULT_PORT = 22
open_connections = {}
PROMPT_SUDO_RE = r'\[sudo\] password for '
PROMPT_2FA_RE = r'Passcode or option.*'
#Duo two-factor login for tcameron
#
#Enter a passcode or select one of the following options:
#
#1. Duo Push to XXX-XXX-0124
#
#Passcode or option (1-1): 1
SERVER_SUDO_PASSWORD = None


def connect_host(hostname, username):
    parent_connection = None
    ssh_config = paramiko.SSHConfig()
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy)
    c.specified_remote_hostname = hostname

    try:
        ssh_config = paramiko.SSHConfig.from_path(
            os.path.abspath(os.path.expanduser(os.path.expandvars('~/.ssh/config')))
        )
    except FileNotFoundError as ex:
        pass

    client_ssh_config = ssh_config.lookup(hostname)
    connect_parameters = config_to_connect_params(client_ssh_config)

    # Always override the username if one is specified on the command line
    if username is not None and username != "":
        client_ssh_config['username'] = username

    if 'proxyjump' in client_ssh_config:
        proxy_connection = connect_host(client_ssh_config['proxyjump'], username=username)
        proxy_channel = proxy_connection.get_transport().open_channel(
            'direct-tcpip',
            (client_ssh_config['hostname'], client_ssh_config['port']),
            ('', 0),
            timeout=client_ssh_config['timeout']
        )
        client_ssh_config['sock'] = proxy_channel

    if 'proxycommand' in client_ssh_config:
        proxy_channel = paramiko.ProxyCommand(client_ssh_config['proxycommand'])
        client_ssh_config['sock'] = proxy_channel

    if 'sock' in client_ssh_config and client_ssh_config['sock'] is None:
        # A Proxy has been configured, but no proxy connecion has been configured
        # so bail out now and report the error.
        print(f'Error: Proxy connection for {hostname} has failed.')
        return None

    try:
        c.load_system_host_keys()
        # TODO: Create the keys file if it doesn't exist
        # c.load_host_keys('sherman_host_keys')
        c.connect(**connect_parameters)
    except paramiko.AuthenticationException as ex:
        print(f'Error: Authentication error for {username}@{hostname}. {ex}')
        return None
    except paramiko.BadHostKeyException as ex:
        print(f'Error: Bad host key for {hostname}. {ex}')
        return None
    except paramiko.SSHException as ex:
        print(f'Error: SSH exception for {hostname}. {ex}')
        return None
    except socket.error as ex:
        print(f'Error: Socket error for {hostname}. {ex}')
        return None

    return c


def fab_connect(hostname, username=None):
    global SERVER_SUDO_PASSWORD

    if SERVER_SUDO_PASSWORD is None:
        SERVER_SUDO_PASSWORD = getpass.getpass("Server SUDO password: ")

    responder_sudo = invoke.Responder(
        pattern=PROMPT_SUDO_RE,
        response=f'{SERVER_SUDO_PASSWORD}\n'
    )
    responder_2fa = invoke.Responder(
        pattern=PROMPT_2FA_RE,
        response='1\n'
    )

    config = fab.Config()
    config['run']['watchers'].append(responder_sudo)
    config['run']['watchers'].append(responder_2fa)

    c = fab.Connection(hostname, config=config)
    return c


def fab_smartctl(c: fab.Connection, password: str = None, logpath: str = None):
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
        result = c.run(f'sudo /usr/sbin/smartctl -x /dev/{scsi_device}', echo=False)
        if result.return_code == 0:
            print(result.stdout)
        else:
            logging.warn(f'Command existed with {result.return_code}\nSTDERR: {result.stderr}\nSTDOUT: {result.stdout}')


def client(hostname, username, logpath):
    # c = connect_host(hostname, username)
    c = fab_connect(hostname)
    if c is None:
        print(f'Connection to {hostname} failed.')
        return

    try:
        fab_smartctl(c, logpath=logpath)
        # server_smartctl(c=c, logpath=logpath)
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
        c.close()


if __name__ == '__main__':
    host_list = []
    # TODO:
    #   Use Fabric sudo helper to execute commands as sudo
    #   Use Fabric Group management to handle a pool of devices
    #     * fabric.group.ThreadingGroup
    #   Use Config(override) to set sudo password in the Config
    #   Validate that chained ProxyJump hosts work as configured
    #   Retrieve results from commands and write to files

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
