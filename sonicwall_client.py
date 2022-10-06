import uuid
import ipaddress
import requests
import json
import logging
import copy
from collections import OrderedDict
from requests.auth import HTTPDigestAuth
from typing import List, Union
from requests.exceptions import HTTPError
from strenum import StrEnum
from enum import auto

from network_info import ADDRESS_OBJECT_TEMPLATE, MODE_INFO, ADDRESS_GROUP_TEMPLATE, \
    SECURITY_POLICY_TEMPLATE

logger = logging.getLogger()


class Method(StrEnum):
    POST = auto()
    GET = auto()
    PUT = auto()
    DELETE = auto()
    PATCH = auto()


class SonicWallClient:
    """
    A class represting a connection to a SonicWALL Appliance.

    Attributes:
    -----------
    hostname : str
        IP Address or Hostname of Appliance
    port : int
        TCP Port used for HTTPS Management
    username : str
        Username of admin-level user
    password : str
        Password of admin-level user

    """

    def __init__(self, hostname: str, port: int, username: str, password: str):
        self.base_url = 'https://{}:{}/api/sonicos'.format(
            hostname, str(port))
        self.auth = HTTPDigestAuth(username, password)
        self.headers = OrderedDict([
            ('Accept', 'application/json'),
            ('Content-Type', 'application/json'),
            ('Accept-Encoding', 'application/json'),
            ('Charset', 'UTF-8')])
        self._config_override = {"override": True}
        self._client = requests.session()
        self._default_version = 7

    @property
    def version(self):
        res = self._send_request(Method.GET, uri='version')
        try:
            return int(res.json()['firmware_version'].split()[-1][0])
        except:
            logger.warning(f"Couldn't get firewall's version. assuming version number {self._default_version}")
            return self._default_version

    def _get_reason(self, response):
        if isinstance(response.reason, bytes):
            # We attempt to decode utf-8 first because some servers
            # choose to localize their reason strings. If the string
            # isn't utf-8, we fall back to iso-8859-1 for all other
            # encodings. (See PR #3538)
            try:
                reason = response.reason.decode("utf-8")
            except UnicodeDecodeError:
                reason = response.reason.decode("iso-8859-1")
        else:
            reason = response.reason
        return reason

    def raise_for_status(self, response):
        """Raises :class:`HTTPError`, if one occurred."""

        http_error_msg = ""
        if getattr(response, 'text'):
            try:
                res = response.json()
                reason = json.dumps(res['status']['info'])
            except Exception:
                reason = self._get_reason(response)
        else:
            reason = self._get_reason(response)
        if 400 <= response.status_code < 500:
            http_error_msg = (
                f"{response.status_code} Client Error: {reason} for url: {response.url}"
            )

        elif 500 <= response.status_code < 600:
            http_error_msg = (
                f"{response.status_code} Server Error: {reason} for url: {response.url}"
            )

        if http_error_msg:
            raise HTTPError(http_error_msg, response=response)

    def _send_request(self, method, uri, headers=None, params=None, data=None, files=None, verify=False, **kwargs):
        url = f"{self.base_url}/{uri}"
        self.headers.update(headers or {})
        try:
            data = data and json.dumps(data)
        except:
            data = json.dumps({})
        response = self._client.request(method, url, headers=self.headers, params=params, data=data, files=files,
                                        verify=verify, auth=self.auth, **kwargs)

        self.raise_for_status(response)
        return response

    def login(self):
        """
        Login to the SonicWALL Appliance

        Keyword arguments:
        ------------------
        authmethod : str
            Either 'Basic' or 'Digest' (Defaults to Digest)
            HTTP Basic auth requires this to be enabled on your Appliance which is not enabled by default
        """
        return self._send_request(Method.POST.value, uri='auth', data=self._config_override)

    def logout(self):
        return self._send_request(Method.DELETE.value, uri='auth')

    def set_config_mode(self):
        """
        ** Gen7 Only
        Preempt the other user, set self to config mode.
        """
        return self._send_request(Method.POST.value, 'config-mode')

    def commit(self):
        """
        Commits all pending changes to the running and startup config
        """
        return self._send_request(Method.POST.value, uri='config/pending')

    def get_policies(self, ipversion='ipv4'):
        """
        Get all policies
        :param ipversion:
        :return:
        """
        uri = ''
        if self.version == 6:
            uri = 'access-rules'
        if self.version == 7:
            uri = 'security-policies'
        uri = f"{uri}/{ipversion}"
        res = self._send_request(Method.GET.value, uri=uri)
        return res.json()['security_policies']

    def get_policy(self, name, ipversion='ipv4'):
        """
        Get Policy by name
        :param name:
        :param ipversion:
        :return:
        """
        for policy in self.get_policies():
            if policy[ipversion]['name'] == name:
                return policy

    def create_policy(self, policy_info: dict, ipversion: str ='ipv4'):
        """
        Create new policy with the relevant 'policy_info
        :param policy_info:
        :param ipversion:
        :return:
        """
        if not policy_info:
            return
        policy_name = policy_info[ipversion]['name']
        policy = self.get_policy(policy_name)
        if policy:
            logger.info(f"Policy name: '{policy_name}' already exists")
            return
        if self.version == 6:
            uri = 'access-rules'
            data = {
                'access_rules': [policy_info]
            }
        else:
            # version 7 and above
            uri = 'security-policies'
            data = {
                'security_policies': [policy_info]
            }
        uri = f"{uri}/{ipversion}"
        res = self._send_request(Method.POST.value, uri=uri, data=data)
        self.commit()
        return res

    def delete_policy(self, policy_name: str, ipversion: str = 'ipv4'):
        """
        Delete policy according to name
        :param policy_name:
        :param ipversion:
        :return:
        """
        policy = self.get_policy(policy_name)
        controller = 'access-rules' if self.version == 6 else 'security-policies'
        uri = f"{controller}/{ipversion}/uuid/{policy[ipversion]['uuid']}"
        res = self._send_request(Method.DELETE.value, uri=uri)
        self.commit()
        return res

    def get_address_groups(self, ipversion='ipv4'):
        """
        Get all address groups according to 'ipversion'
        :param ipversion:
        :return:
        """
        res = self._send_request(Method.GET.value, uri=f'address-groups/{ipversion}')
        return res.json()['address_groups']

    def get_address_group(self, name, ipversion: str = 'ipv4'):
        """
        Get address group by name
        :param name:
        :param ipversion:
        :return:
        """
        for address_group in self.get_address_groups():
            if address_group[ipversion]['name'] == name:
                return address_group

    def create_address_group(self, group_info: dict, ipversion: str = 'ipv4'):
        """
        Create Address group according to 'group_info'
        :param group_info:
        :param ipversion:
        :return:
        """
        if not group_info:
            return

        data = {
            "address_groups": [group_info]
        }
        address_objects = group_info[ipversion]['address_object'].get(ipversion)
        if not address_objects:
            del group_info[ipversion]['address_object']
        group_name = group_info[ipversion]['name']
        address_group = self.get_address_group(group_name)
        if not address_group:
            res = self._send_request(Method.POST.value, uri=f'address-groups/{ipversion}', data=data)
            logger.info(f"Created new group: {group_name}")
        else:
            logger.info(f"Group name: '{group_name}' already exists")
            res = self._send_request(Method.PATCH.value, uri=f'address-groups/{ipversion}', data=data)
        self.commit()
        return res

    def delete_address_group(self, name: str, ipversion: str = 'ipv4'):
        """
        Delete address group according to name
        :param name:
        :param ipversion:
        :return:
        """
        res = self._send_request(Method.DELETE.value, uri=f'address-groups/{ipversion}/name/{name}')
        self.commit()
        return res

    def get_address_objects(self, ipversion: str = 'ipv4'):
        """
        Get all address objects according to 'ipversion'
        :param ipversion:
        :return:
        """
        res = self._send_request(Method.GET.value, uri=f'address-objects/{ipversion}')
        return res.json()['address_objects']

    def get_address_object(self, name: str, ipversion='ipv4'):
        """
        Get address object by name
        :param name:
        :param ipversion:
        :return:
        """
        for address_object in self.get_address_objects():
            if address_object[ipversion]['name'] == name:
                return address_object

    def create_address_objects(self, object_info: List[dict], ipversion: str = 'ipv4'):
        """
        Create address object according to 'object_info'
        :param object_info:
        :param ipversion:
        :return:
        """
        if not object_info:
            return
        data = {
            "address_objects": object_info
        }
        res = self._send_request(Method.POST.value, uri=f'address-objects/{ipversion}', data=data)
        self.commit()
        return res

    def delete_address_object(self, name: str, ipversion: str = 'ipv4'):
        """
        Delete address object according to name
        :param name:
        :param ipversion:
        :return:
        """
        res = self._send_request(Method.DELETE.value, uri=f'address-objects/{ipversion}/name/{name}')
        self.commit()
        return res

    def create_block_address_objects(self, mode: str, ips: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]],
                                     ipversion: str = 'ipv4') -> List[dict]:
        """
        Create block address objects according to mode (blockexternal|blockinternal) and ips
        :param mode:
        :param ips:
        :return:
        """
        new_address_objects = []
        existing_address_objects = []
        for ip in ips:
            address_object_name = MODE_INFO[mode]["address_object_name"].format(ip.network_address)
            address_object = self.get_address_object(address_object_name)
            if not address_object:
                logger.info(f"Creating new address object with the name: '{address_object_name}'")
                address_object = copy.deepcopy(ADDRESS_OBJECT_TEMPLATE)
                address_object[ipversion].update({
                    "name": address_object_name,
                    "zone": MODE_INFO[mode]["object_zone"],
                    "host": {"ip": str(ip.network_address)}
                })
                new_address_objects.append(address_object)
            else:
                existing_address_objects.append(address_object)
                logger.info(f"Address object with the name: '{address_object_name}' already exists")
        self.create_address_objects(new_address_objects)
        return new_address_objects + existing_address_objects

    def create_block_address_group(self, mode, address_objects: List[dict], ipversion: str = 'ipv4'):
        """
        Create block address group according to mode (blockexternal|blockinternal) and address_objects
        :param mode:
        :param address_objects:
        :return:
        """
        address_group = copy.deepcopy(ADDRESS_GROUP_TEMPLATE)
        address_group[ipversion].update({
            "name": MODE_INFO[mode]["address_group_name"],
            "address_object": {ipversion: [{"name": address_object[ipversion]['name']} for address_object in
                                                           address_objects]}
        })
        self.create_address_group(address_group)

    def create_block_policy(self, mode, ipversion: str = 'ipv4'):
        """
        Create block policy according to mode (blockexternal|blockinternal)
        :param mode:
        :return:
        """
        policy_name = MODE_INFO[mode]["policy_name"]
        policy = copy.deepcopy(SECURITY_POLICY_TEMPLATE)
        policy[ipversion].update({
            "name": policy_name,
            "uuid": str(uuid.uuid4()),
            "from": MODE_INFO[mode]["policy_from_zone"],
            "to": MODE_INFO[mode]["policy_to_zone"],
            "source": {"address": MODE_INFO[mode]["policy_source_address"]},
            "destination": {"address": MODE_INFO[mode]["policy_destination_address"]}
        })
        self.create_policy(policy, ipversion=ipversion)

    def delete_block_address_objects(self, mode: str, ips: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]], ipversion: str = 'ipv4'):
        """
        Delete block address objects according to mode (blockexternal|blockinternal) and ips
        :param mode:
        :param ips:
        :return:
        """
        for ip in ips:
            address_object_name = MODE_INFO[mode]["address_object_name"].format(ip.network_address)
            address_object = self.get_address_object(address_object_name, ipversion=ipversion)
            if address_object:
                self.delete_address_object(address_object_name, ipversion=ipversion)
                logger.info(f"Unblocked ip '{ip.network_address}'")
            else:
                logger.info(f"ip '{ip}' doesn't exists")

    def block_ips(self, mode: str, ips: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]], ipversion: str = 'ipv4'):
        """
        Block all ips given according to mode (blockexternal|blockinternal) and ips:
            1. Create address objects for all ips
            2. Create/Update address group with the relevant address objects names
            3. Create policy (if does not exists) with the relevant group address name
        :param mode:
        :param ips:
        :return:
        """
        address_objects = self.create_block_address_objects(mode, ips, ipversion=ipversion)
        self.create_block_address_group(mode, address_objects, ipversion=ipversion)
        self.create_block_policy(mode)

    def unblock_ips(self, mode: str, ips: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]], ipversion: str = 'ipv4'):
        """
        Unblock all ip given:
            1. Delete all address objects with the relevant ips
            2. If address group is empty -> remove policy and afterwards group
        :param mode:
        :param ips:
        :return:
        """
        block_mode = mode.replace('un', '')
        self.delete_block_address_objects(block_mode, ips, ipversion=ipversion)
        address_group_name = MODE_INFO[block_mode]["address_group_name"]
        address_group = self.get_address_group(address_group_name, ipversion=ipversion)
        if address_group and not address_group[ipversion].get('address_object'):
            logger.info(f"Address group '{address_group_name}' is empty. Removing policy '{MODE_INFO[block_mode]['policy_name']}' and address group '{address_group_name}'")
            self.delete_policy(MODE_INFO[block_mode]["policy_name"], ipversion=ipversion)
            self.delete_address_group(address_group_name, ipversion=ipversion)
