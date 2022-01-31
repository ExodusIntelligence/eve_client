import datetime
import string
import unittest
from asyncio import exceptions
from unittest import mock

import requests
import requests_mock

from vms_client import __version__, vms


class TestVmsClient(unittest.TestCase):
    url = "https://vpx.exodusintel.com"
    email = "test@test.com"
    password = "SuperP@ss"  # noqa
    private_key = "MyPrivateKey"

    with mock.patch(
        "vms_client.vms.Client.get_access_token", return_value="-access_token-"
    ) as _:
        client = vms.Client(email, password, private_key)

    def test_version(self):
        self.assertEqual(__version__, "0.1.3")

    def testClassValidArguments(self):
        self.assertTrue(vms.verify_email("test00@test.com"))
        self.assertTrue(vms.verify_email("00@test.com"))

    def testClassInvalidArguments(self):
        self.assertRaises(ValueError, vms.verify_email, ".com")
        self.assertRaises(ValueError, vms.verify_email, 5j)

    @requests_mock.Mocker()
    def test_get_access_token(self, mock_session):
        json = {
            "email": self.email,
            "password": self.password,
            "access_token": "-access_token-",
        }

        mock_session.register_uri(
            "POST",
            f"{self.url}/vpx-api/v1/login",
            [
                {"json": json, "status_code": 200},
                {"json": json, "status_code": 201},
            ],
        )

        self.assertEqual(
            vms.Client.get_access_token(self.client), "-access_token-"
        )
        self.assertRaises(
            requests.exceptions.ConnectionError,
            vms.Client.get_access_token,
            self.client,
        )

    @requests_mock.Mocker()
    def test_Get_Bronco_Public_Key(self, mock_session):
        mock_session.register_uri(
            "GET",
            f"{self.url}/vpx-api/v1/bronco-public-key",
            json={
                "data": {"public_key": string.ascii_lowercase},
                "errmsg": None,
                "ok": True,
            },
            status_code=404,
        )
        response = vms.Client.get_bronco_public_key(self.client)

        self.assertEqual(response, string.ascii_lowercase)

    @requests_mock.Mocker()
    def test_Get_Bronco_Public_Key_Raises(self, mock_session):
        mock_session.register_uri(
            "GET",
            f"{self.url}/vpx-api/v1/bronco-public-key",
            exc=requests.exceptions.ConnectionError,
        )
        self.assertRaises(
            SystemExit,
            vms.Client.get_bronco_public_key,
            self.client,
        )

    @mock.patch("vms_client.vms.b64decode", return_value="DecodeMessage")
    @mock.patch("vms_client.vms.nacl", return_value="SomeBox")
    @mock.patch(
        "vms_client.vms.json.loads",
        return_value="ReportContentPlainText",
    )
    def test_decrypt_bronco_in_report(self, mock_loads, mock_Box, mock_decode):
        report = {"bronco": "TheSecretMessage"}
        self.client.private_key_b64 = ""
        self.assertEqual(
            vms.Client.decrypt_bronco_in_report(
                self.client, report, "PublicKey"
            ),
            {"bronco": "ReportContentPlainText"},
        )

    def test_handle_reset_option(self):
        reset = 1
        response = vms.Client.handle_reset_option(self.client, reset)
        self.assertGreaterEqual(
            datetime.datetime.now(),
            response,
        )

    def test_handle_reset_option_None(self):
        reset = None
        self.assertEqual(
            vms.Client.handle_reset_option(self.client, reset), reset
        )

    def test_handle_reset_option_Raises(self):
        reset = "2022-10-DD"
        self.assertRaises(
            SystemExit, vms.Client.handle_reset_option, self.client, reset
        )

    @requests_mock.Mocker()
    def test_get_vuln(self, mock_session):
        identifier = "cve12345"
        mock_session.register_uri(
            "GET",
            f"{self.url}/vpx-api/v1/vuln/for/{identifier}",
            [{"json": {"ok": "ok"}}, {"json": {}}],
        )
        response = vms.Client.get_vuln(self.client, identifier)
        self.assertEqual(response, {"ok": "ok"})
        self.assertRaises(
            SystemExit, vms.Client.get_vuln, self.client, identifier
        )

    @requests_mock.Mocker()
    def test_get_recent_vulns(self, mock_session):
        mock_session.register_uri(
            "GET",
            f"{self.url}/vpx-api/v1/vulns/recent",
            [{"json": {"ok": "ok"}}],
        )

        response = vms.Client.get_recent_vulns(self.client)
        self.assertEqual(response, {"ok": "ok"})

    @mock.patch(
        "vms_client.vms.Client.get_bronco_public_key",
        return_value="BroncoPublicKey",
    )
    @requests_mock.Mocker()
    def test_get_recent_reports(
        self,
        mock_bronco_public_key,
        mock_session,
    ):
        reset = 11
        mock_session.register_uri(
            "GET",
            f"{self.url}/vpx-api/v1/reports/recent",
            [
                {"json": {"ok": "ok", "data": {"items": {}}}},
                {"json": {}},
            ],
        )
        vms.Client.get_recent_reports(self.client, reset)

        self.assertRaises(
            SystemExit, vms.Client.get_recent_reports, self.client, reset
        )

        mock_session.register_uri(
            "GET",
            f"{self.url}/vpx-api/v1/reports/recent",
            exc=requests.exceptions.ConnectionError,
        )
        self.assertRaises(
            SystemExit,
            vms.Client.get_recent_reports,
            self.client,
        )

        mock_session.register_uri(
            "GET",
            f"{self.url}/vpx-api/v1/reports/recent",
            json={"ok": "ok"},
        )

        self.client.private_key = None
        self.assertEqual(vms.Client.get_recent_reports(self.client), None)

    @mock.patch(
        "vms_client.vms.Client.get_bronco_public_key",
        return_value=string.ascii_lowercase,
    )
    @mock.patch(
        "vms_client.vms.Client.decrypt_bronco_in_report", return_value={}
    )
    @requests_mock.Mocker()
    def test_get_report(
        self,
        mock_decrypt_bronco_in_report,
        mock_get_bronco_public_key,
        mock_session,
    ):
        identifier = "cve12345"
        mock_session.register_uri(
            "GET",
            f"{self.url}/vpx-api/v1/report/{identifier}",
            json={"data": {}},
        )
        self.client.private_key = "MyPrivateKey"
        response = vms.Client.get_report(self.client, identifier)

        self.assertEqual(response, {"data": {}})

    @mock.patch(
        "vms_client.vms.Client.get_bronco_public_key",
        return_value=string.ascii_lowercase,
    )
    @requests_mock.Mocker()
    def test_get_report_fail(self, mock_get_bronco_public_key, mock_session):
        identifier = "cve12345"
        self.get_bronco_public_key = mock_get_bronco_public_key
        mock_session.register_uri(
            "GET",
            f"{self.url}/vpx-api/v1/report/{identifier}",
            [{"status_code": 404}, {"status_code": 201}],
        )

        response = vms.Client.get_report(self.client, identifier)
        self.assertEqual(
            response,
            {
                "msg": f"Couldn't find a report for {identifier}",
                "status": 404,
                "data": None,
            },
        )

        response = vms.Client.get_report(self.client, identifier)
        self.assertEqual(
            response,
            {
                "msg": f"Something went wrong for {identifier}",
                "status": 201,
                "data": None,
            },
        )

    @requests_mock.Mocker()
    def test_get_vulns_by_day(self, mock_session):
        mock_session.register_uri(
            "GET",
            f"{self.url}/vpx-api/v1/aggr/vulns/by/day",
            json={},
        )

        response = vms.Client.get_vulns_by_day(self.client)
        self.assertEqual(response, {})

    @requests_mock.Mocker()
    def test_get_vulns_by_day_fail(self, mock_session):
        mock_session.register_uri(
            "GET",
            f"{self.url}/vpx-api/v1/aggr/vulns/by/day",
            exc=requests.exceptions.ConnectionError,
        )
        self.assertRaises(
            SystemExit,
            vms.Client.get_vulns_by_day,
            self.client,
        )

    # @mock.patch(
    #     "vms_client.vms.nacl",
    #     return_value=dict(),
    # )
    @mock.patch(
        "vms_client.vms.b64decode",
        return_value="SomeValue",
    )
    @mock.patch(
        "vms_client.vms.b64encode",
        return_value=b"SomeOtherValue",
    )
    @mock.patch(
        "vms_client.vms.nacl.public.SealedBox",
        return_value=mock.MagicMock(),
    )
    @requests_mock.Mocker()
    def test_generate_key_pair(
        self, mock_sealedbox, mock_b64encode, mock_b64decode, mock_session
    ):
        self.client.session.cookies.set("csrf_access_token", "MyToken")
        mock_session.register_uri(
            "POST",
            f"{self.url}/vpx-api/v1/pubkey",
            [
                {
                    "json": {"data": {"challenge": "MyChallenge"}},
                    "status_code": 200,
                },
                {
                    "json": {"data": {"challenge": "MyChallenge"}},
                    "status_code": 200,
                },
                {
                    "json": {"data": {"challenge": "MyChallenge"}},
                    "status_code": 201,
                },
                {
                    "json": {"data": {"challenge": "MyChallenge"}},
                    "status_code": 200,
                },
                {
                    "json": {"data": {"challenge": "MyChallenge"}},
                    "status_code": 201,
                },
            ],
        )

        vms.Client.generate_key_pair(self.client)
        self.assertRaises(
            exceptions.InvalidStateError,
            vms.Client.generate_key_pair,
            self.client,
        )
        self.assertRaises(
            exceptions.InvalidStateError,
            vms.Client.generate_key_pair,
            self.client,
        )
