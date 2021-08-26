#!/usr/bin/env python3

import argparse
import getpass
import multiprocessing as mp
import os
import paramiko
import re
import socket
import sys

from paramiko.py3compat import u


DEFAULT_TIMEOUT = 10.0
DEFAULT_PORT = 22
open_connections = {}


def config_to_connect_params(cfg) -> dict:
    """
    Convert openssh configuration parameters to paramiko's expected naming convention

    :param cfg: Openssh configuration returned by .lookup()
    :type param: dict
    :return: Returns a sanitized dictionary of configuration parameters
    """
    result = {}

    if 'hostname' in cfg:
        result['hostname'] = cfg['hostname']

    if 'port' in cfg:
        result['port'] = int(cfg['port'])
    else:
        result['port'] = DEFAULT_PORT

    # If no username is specified in the ssh config, use the current logged in username
    if 'user' in cfg:
        result['username'] = cfg['user']
    else:
        result['username'] = getpass.getuser()

    if 'identityfile' in cfg:
        result['key_filename'] = cfg['identityfile']
        translated_key = 'key_filename'

    if 'connecttimeout' in cfg:
        timeout_val = float(cfg['connecttimeout'])
        result['timeout'] = timeout_val
        result['banner_timeout'] = timeout_val
        result['auth_timeout'] = timeout_val
    else:
        result['timeout'] = DEFAULT_TIMEOUT
        result['banner_timeout'] = DEFAULT_TIMEOUT
        result['auth_timeout'] = DEFAULT_TIMEOUT

    if 'forwardagent' in cfg:
        result['allow_agent'] = (cfg['forwardagent'] == 'yes')

    if 'compression' in cfg:
        result['compress'] = (cfg['compression'] == 'yes')

    if 'gssapikeyexchange' in cfg:
        result['gss_auth'] = (cfg['gssapikeyexchange'] == 'yes')

    if 'gssapiauthentication' in cfg:
        result['gss_kex'] = (cfg['gssapiauthentication'] == 'yes')

    if 'gssapidelegatecredentials' in cfg:
        result['gss_deleg_creds'] = (cfg['gssapidelegatecredentials'] == 'yes')

    return result


def connect_host(hostname, username):
    parent_connection = None
    ssh_config = paramiko.config.SSHConfig()
    c = paramiko.SSHClient()
    c.specified_remote_hostname = hostname

    try:
        ssh_config = paramiko.config.SSHConfig.from_path(
            os.path.abspath(os.path.expanduser(os.path.expandvars('~/.ssh/config')))
        )
    except FileNotFoundError as ex:
        pass


    # Connect to one host through a proxy host using a Transport
    # paramiko.transport.Transport()
    # c.get_transport().connect()

    client_ssh_config = ssh_config.lookup(hostname)
    connect_parameters = config_to_connect_params(client_ssh_config)

    # Always override the username if one is specified on the command line
    if username is not None and username != "":
        client_ssh_config['username'] = username

    if 'proxyjump' in client_ssh_config:
        parent_connection = connect_host(client_ssh_config['proxyjump'], username=username)
        trans = parent_connection.get_transport()
        client_ssh_config['sock'] = trans

    if 'proxycommand' in client_ssh_config:
        pc = paramiko.proxy.ProxyCommand(client_ssh_config['proxycommand'])
        client_ssh_config['sock'] = pc

    c.load_system_host_keys()
    # TODO: Create the keys file if it doesn't exist
    # c.load_host_keys('sherman_host_keys')

    c.set_missing_host_key_policy(paramiko.AutoAddPolicy)
    c.connect(**connect_parameters)

    return c


def server_smartctl(c: paramiko.client.SSHClient, logpath):
    device_pattern = r'(sd[a-z]+)\n'
    device_re = re.compile(device_pattern)
    scsi_devices = []

    # Get a list of devices in /dev/sd*
    try:
        sftp = c.open_sftp()
        dev_contents = sftp.listdir('/dev')
        scsi_devices = device_re.findall('\n'.join(dev_contents))
        sftp.close()
    except paramiko.ssh_exception.SSHException as ex:
        print(f'Error: SSH exception while opening SFTP channel to {c.specified_remote_hostname}. {ex}')

    # Run smartctl for each device
    try:
        for scsi_device in scsi_devices:
            stdin, stdout, stderr = c.exec_command(f'sudo /usr/sbin/smartctl -x /dev/{scsi_device}')
            stdin.close()
            status = stdout.channel.recv_exit_status()
            print(f'Status: {status}')

            if logpath is not None and logpath != '':
                with open(os.path.join(logpath, f'{c.specified_remote_hostname}.{scsi_device}.log'), 'w') as output_file:
                    output_file.write(u(stdout.read()))
            else:
                print(u(stdout.read()))

            errors = u(stderr.read())
            if len(errors) > 0:
                print(f'Error:\n{errors}')
            stdout.close()
            stderr.close()

    except paramiko.ssh_exception.SSHException as ex:
        print(f'Error: SSH exception while running remote command on {c.specified_remote_hostname}. {ex}')


def client(hostname, username, logpath):
    c = paramiko.SSHClient()
    c.remote_hostname = hostname

    try:
        ssh_config = paramiko.config.SSHConfig.from_path(
            os.path.abspath(os.path.expanduser(os.path.expandvars('~/.ssh/config')))
        )

        c.load_system_host_keys()

        # Create the keys file if it doesn't exist
        # c.load_host_keys('sherman_host_keys')
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        c.connect(hostname, 22, username, timeout=10, compress=True)
        # c.save_host_keys('sherman_host_keys')

        server_smartctl(c=c, logpath=logpath)
    except paramiko.ssh_exception.AuthenticationException as ex:
        print(f'Error: Authentication error for {username}@{hostname}. {ex}')
        return
    except paramiko.ssh_exception.BadHostKeyException as ex:
        print(f'Error: Bad host key for {hostname}. {ex}')
        return
    except paramiko.ssh_exception.SSHException as ex:
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
