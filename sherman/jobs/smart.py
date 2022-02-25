#!/usr/bin/env python3

import logging
import re

import fabric

logging.basicConfig(level=logging.DEBUG)
logging.getLogger(__name__).setLevel(logging.DEBUG)
logger = logging.getLogger()
logger.setLevel(logging.WARNING)


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


def run(c: fabric.Connection, logpath):
    fab_smartctl(c, logpath=logpath)


if __name__ == '__main__':
    print('This package can not be called directly')
