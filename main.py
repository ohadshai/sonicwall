import sys
import logging
import urllib3
import ipaddress
import click
from dataclasses import dataclass
from typing import List

from sonicwall_client import SonicWallClient
from network_info import Mode

urllib3.disable_warnings()
logger = logging.getLogger()
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
logger.addHandler(handler)


def ip_parser(ips) -> List[ipaddress.ip_network]:
    ips = ips.split(", ")
    return [ipaddress.ip_network(ip) for ip in ips]


@dataclass
class Credential(object):
    ip: str = None
    port: int = None
    user: str = None
    password: str = None


def credential_parser(credentials):
    credentials = credentials.split(", ")
    credentials = list(zip(credentials[0:len(credentials):3],
                           credentials[1:len(credentials):3],
                           credentials[2:len(credentials):3]))
    credential_objs = []
    for credential in credentials:
        ip, port = credential[0].split(':')
        ipaddress.ip_address(ip)
        if not 0 < int(port) < 65535:
            raise ValueError("Port of firewall needs to be at maximum of 65535")
        credential_objs.append(Credential(ip, int(port), credential[1], credential[2]))

    return credential_objs


@click.command()
@click.argument('mode', type=click.Choice([m.value for m in Mode]))
@click.option('-swcreds', type=credential_parser, required=True, help='SonicWall creds: IP:PORT, USER, PASSWORD')
@click.option('-ips', type=ip_parser, required=True, help='ips to block with "," seprated')
def action(swcreds, ips, mode):
    for swcred in swcreds:
        s = SonicWallClient(swcred.ip, swcred.port, swcred.user, swcred.password)
        s.login()
        logger.info("Logged in successfully")
        if mode in (Mode.blockexternal.value, Mode.blockinternal):
            s.block_ips(mode, ips)
            logger.info("Blocking ip/s finished successfully")
        else:
            s.unblock_ips(mode, ips)
            logger.info("Unblocking ip/s finished successfully")


if __name__ == "__main__":
    action()
