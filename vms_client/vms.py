from ast import Raise
from base64 import b64decode, b64encode
from datetime import datetime, timedelta
import json
import sys
import os
from attrs import exceptions

import dateutil.parser
import nacl.public
import nacl.encoding
import nacl.utils
import requests
import re


def verify_email(email):
    regex = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    if type(email) is not str:
        raise ValueError("Invalid email.")
    if not re.fullmatch(regex, email):
        raise ValueError("Invalid email.")
    return True


class Client:
    """Class client to communicate with the Exodus API.

    This module allows to connect and interact with the
    Exodus Intelligence API.

    Example initiate connection:

        >>> from vms.client import Client
        >>> exodus_api = Client('email', 'password', 'private_key')

    Note: See help(Client) for more information.

    """

    url = "https://vpx.exodusintel.com/"

    def __init__(self, email, password, key=None) -> None:
        if verify_email(email):
            self.email = email
        self.session = requests.Session()
        self.password = password
        self.private_key = key
        self.token = self.get_access_token()

    def get_access_token(self):
        """Obtain access token.

        Args:
            self (object): Class instance.

        Returns:
            str: The token or None
        """
        r = self.session.post(
            self.url + "vpx-api/v1/login",
            json={"email": self.email, "password": self.password},
        )
        if r.status_code != 200:
            raise requests.exceptions.ConnectionError(
                "Could not authenticate!"
            )
        return r.json()["access_token"]

    def get_bronco_public_key(self):
        """Get server public key.

        Returns:
            str: A string representation of a public key.
        """
        try:
            key = self.session.get(
                self.url + "vpx-api/v1/bronco-public-key"
            ).json()["data"]["public_key"]
        except:
            raise requests.exceptions.InvalidURL
        return key

    def decrypt_bronco_in_report(self, report, bronco_public_key):
        """Decrypt the content of a report using a private and public key.

        Args:
            report (object): The encrypted message.
            bronco_public_key (str): The public key

        Returns:
            dict: A dictionary object representing the report.
        """
        ciphertext = b64decode(report["bronco"])
        nonce = ciphertext[0:24]
        ciphertext = ciphertext[24:]
        unseal_box = nacl.public.Box(
            nacl.public.PrivateKey(b64decode(self.private_key_b64)),
            nacl.public.PublicKey(b64decode(bronco_public_key)),
        )
        plaintext = unseal_box.decrypt(ciphertext, nonce)
        report["bronco"] = json.loads(plaintext)
        return report

    def handle_reset_option(self, reset):
        """Reset number of days.

        Args:
            reset (int): Number of days in the past to reset

        Returns:
            datetime:  A date

        """
        if reset is None:
            return None

        # First, try to load reset as an integer indicating the number of days
        # in the past to reset to
        try:
            reset = int(reset)
            return datetime.utcnow() - timedelta(days=reset)
        except ValueError:
            pass

        # Try to load reset as a ISO8601 datetime
        try:
            reset = dateutil.parser.isoparse(reset)
        except:
            raise ValueError(
                f"Did not recognize '{reset}' as a legitimate ISO8601 datetime"
            )

    def get_vuln(self, identifier):
        """Get a Vulnerability by identifier or cve.

        ie: x.get_vuln('CVE-2020-9456') or x.get_vuln('XI-00048890') both
        refer to the same vulnerability.

        Args:
            identifier (str): String representation of vulnerability id.

        Returns:
            dict or exception: Returns either a report in json format or an exception
        """
        r = self.session.get(self.url + f"vpx-api/v1/vuln/for/{identifier}")
        try:
            if r.json()["ok"]:
                return r.json()
        except:
            raise KeyError

    def get_recent_vulns(self, reset=1):
        """Get a list of recent vulnerabilities.

        Args:
            reset (int): Number of days in the past to reset.

        Returns:
            dict or None: Returns a list of vulnerabilities or None.
        """
        if reset:
            reset = self.handle_reset_option(reset)

        # self.get_access_token()

        params = {}
        if reset:
            params = {"reset": reset.isoformat()}
            # print(f"Resetting stream marker to {reset}")

        r = self.session.get(
            self.url + "vpx-api/v1/vulns/recent", params=params
        )
        # print(json.dumps(r.json(), indent=2))
        return r.json()

    def get_recent_reports(self, reset=1):
        """Get list of recent reports.

        Args:
            reset (int): Number of days in the past to reset.

        Returns:
            dict or None: Returns a list of reports or None.
        """

        if reset:
            reset = self.handle_reset_option(reset)

        # self.get_access_token()

        params = {}
        if reset:
            reset = reset.isoformat()
            params = {"reset": reset}
            # print(f"Resetting stream marker to {reset}")

        try:
            r = self.session.get(
                self.url + "vpx-api/v1/reports/recent", params=params
            )
            # print(r.json())
            r = r.json()
        except:
            raise requests.exceptions.InvalidURL("Unable to connect to API")

        try:
            if self.private_key and r["ok"]:
                bronco_public_key = self.get_bronco_public_key()
                r["data"]["items"] = [
                    self.decrypt_bronco_in_report(report, bronco_public_key)
                    for report in r["data"]["items"]
                ]
                # print(json.dumps(r, indent=2))
                return r
        except KeyError:
            raise KeyError("No Recent Reports")
        return None

    def get_report(self, identifier):
        """Get a report by identifier.

        Args:
            identifier (str): String representation of report id.

        Returns:
            dict or None: Returns either a report in json format or None
        """
        # self.get_access_token()

        r = self.session.get(self.url + f"vpx-api/v1/report/{identifier}")
        if r.status_code == 404:
            return {
                "msg": f"Couldn't find a report for {identifier}",
                "status": r.status_code,
                "data": None,
            }
        elif r.status_code != 200:
            return {
                "msg": f"Something went wrong for {identifier}",
                "status": r.status_code,
                "data": None,
            }

        r = r.json()

        if self.private_key:
            bronco_public_key = self.get_bronco_public_key()
            self.decrypt_bronco_in_report(r["data"], bronco_public_key)

        return r

    def get_vulns_by_day(self):
        """Get vulnerabilities by day.

        Returns:
            dict or None: Returns <TODO>
        """
        # self.get_access_token()
        try:
            r = self.session.get(self.url + "vpx-api/v1/aggr/vulns/by/day")
        except:
            raise requests.exceptions.InvalidURL
        return r.json()

    def generate_key_pair(self):
        """Generate a Key Pair.

        Returns:
            tuple: Returns a key pair (sk, pk).
        """
        # Login
        # self.get_access_token()

        # Get the CSRF token from the session cookies

        csrf_token = [
            c.value
            for c in self.session.cookies
            if c.name == "csrf_access_token"
        ][0]

        # Generate a public/private key pair
        secret_key = nacl.public.PrivateKey.generate()
        public_key = secret_key.public_key

        # Propose the public key
        r = self.session.post(
            self.url + "vpx-api/v1/pubkey",
            headers={"X-CSRF-TOKEN": csrf_token},
            json={
                "key": public_key.encode(nacl.encoding.Base64Encoder).decode(
                    "utf-8"
                )
            },
        )
        if r.status_code != 200:
            print(f"Couldn't set public key, status code {r.status_code}")
            sys.exit()
        challenge = b64decode(r.json()["data"]["challenge"])

        # Send the challenge response
        unseal_box = nacl.public.SealedBox(secret_key)
        challenge_response = unseal_box.decrypt(challenge)
        r = self.session.post(
            self.url + "vpx-api/v1/pubkey",
            headers={"X-CSRF-TOKEN": csrf_token},
            json={
                "challenge_response": b64encode(challenge_response).decode(
                    "utf-8"
                )
            },
        )
        if r.status_code != 200:
            print(f"Couldn't confirm public key, status code {r.status_code}")
            sys.exit()

        return (
            public_key.encode(nacl.encoding.Base64Encoder).decode("utf-8"),
            secret_key.encode(nacl.encoding.Base64Encoder).decode("utf-8"),
        )


email = os.environ.get("XI_EMAIL")
password = os.environ.get("XI_PASS")
key = os.environ.get("XI_KEY")

# a = Client(email, password, key)
