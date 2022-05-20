import datetime
import string
import unittest
from asyncio import exceptions
from unittest import mock

import requests
import requests_mock

from eve_client import __version__, eve


class TestEVEClient(unittest.TestCase):
    url = "https://vpx.exodusintel.com"
    email = "test@test.com"
    password = "SuperP@ss"  # noqa
    private_key = "MyPrivateKey"

    with mock.patch(
        "eve_client.eve.EVEClient.get_access_token",
        return_value="-access_token-",
    ) as _:
        client = eve.EVEClient(email, password, private_key)

    def test_version(self):
        self.assertEqual(__version__, "1.0.1-alpha.1")

    def test_url(self):
        url = "vpx.exodusintel.com"
        with mock.patch(
            "eve_client.eve.EVEClient.get_access_token",
            return_value="-access_token-",
        ) as _:
            eve.EVEClient(
                self.email, self.password, self.private_key, url
            )

    def testClassValidArguments(self):
        self.assertTrue(eve.verify_email("test00@test.com"))
        self.assertTrue(eve.verify_email("00@test.com"))

    def testClassInvalidArguments(self):
        self.assertRaises(ValueError, eve.verify_email, ".com")
        self.assertRaises(ValueError, eve.verify_email, 5j)

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
            eve.EVEClient.get_access_token(self.client), "-access_token-"
        )
        self.assertRaises(
            requests.exceptions.ConnectionError,
            eve.EVEClient.get_access_token,
            self.client,
        )

    @requests_mock.Mocker()
    def test_get_bronco_public_key(self, mock_session):
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
        response = eve.EVEClient.get_bronco_public_key(self.client)

        self.assertEqual(response, string.ascii_lowercase)

    @requests_mock.Mocker()
    def test_get_bronco_public_key_raises(self, mock_session):
        mock_session.register_uri(
            "GET",
            f"{self.url}/vpx-api/v1/bronco-public-key",
            exc=requests.exceptions.ConnectionError,
        )
        response = eve.EVEClient.get_bronco_public_key(self.client)
        self.assertLogs(level="warning")
        self.assertEqual(response, None)

    @mock.patch(
        "eve_client.eve.b64decode",
        return_value="DecodedMessage",
    )
    @mock.patch(
        "eve_client.eve.nacl",
        return_value="SomeBox",
    )
    @mock.patch(
        "eve_client.eve.json.loads",
        return_value="ReportContentPlainText",
    )
    def test_decrypt_bronco_in_report(self, mock_loads, mock_Box, mock_decode):
        report = {"bronco": "TheSecretMessage"}
        self.client.private_key_b64 = ""
        self.assertEqual(
            eve.EVEClient.decrypt_bronco_in_report(
                self.client, report, "PublicKey"
            ),
            {"bronco": "ReportContentPlainText"},
        )
        mock_decode.side_effect = ["abc", KeyError]
        self.assertRaises(
            KeyError,
            eve.EVEClient.decrypt_bronco_in_report,
            self.client,
            report,
            "PublicKey",
        )

    def test_handle_reset_option(self):
        reset = 1
        response = eve.EVEClient.handle_reset_option(self.client, reset)
        self.assertGreaterEqual(
            datetime.datetime.now(),
            response,
        )

    def test_handle_reset_option_iso(self):
        reset = "2022-03-03"
        self.assertEqual(
            str(eve.EVEClient.handle_reset_option(self.client, reset).date()),
            reset,
        )

    def test_handle_reset_option_None(self):
        reset = None
        self.assertEqual(
            eve.EVEClient.handle_reset_option(self.client, reset), reset
        )

    def test_handle_reset_option_logs(self):
        reset = "2022-10-DD"
        eve.EVEClient.handle_reset_option(self.client, reset)
        self.assertLogs(level="warning")

    @requests_mock.Mocker()
    def test_get_vuln(self, mock_session):
        identifier = "cve12345"
        mock_session.register_uri(
            "GET",
            f"{self.url}/vpx-api/v1/vuln/for/{identifier}",
            [{"json": {"ok": "ok"}}, {"json": {}}],
        )
        response = eve.EVEClient.get_vuln(self.client, identifier)
        self.assertEqual(response["ok"], "ok")
        self.assertLogs(level="error")

        response = eve.EVEClient.get_vuln(self.client, identifier)
        self.assertEqual(response["ok"], False)

    @requests_mock.Mocker()
    def test_get_recent_vulns(self, mock_session):
        mock_session.register_uri(
            "GET",
            f"{self.url}/vpx-api/v1/vulns/recent",
            [
                {"json": {"ok": "ok"}},
            ],
        )

        response = eve.EVEClient.get_recent_vulns(self.client, 5)
        self.assertEqual(response["ok"], "ok")
        self.assertLogs(level="error")

    @requests_mock.Mocker()
    def test_get_recent_vulns_failed(self, mock_session):
        mock_session.register_uri(
            "GET",
            f"{self.url}/vpx-api/v1/vulns/recent",
            status_code=404,
        )
        eve.EVEClient.get_recent_vulns(self.client, 5)
        self.assertLogs(level="error")

    @mock.patch(
        "eve_client.eve.EVEClient.get_bronco_public_key",
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
                {"json": {"ok": "ok", "data": {"items": {}}}},
                {"json": {"ok": "ok", "data": {}}},
                {"json": {}},
            ],
        )
        eve.EVEClient.get_recent_reports(self.client, reset)

        mock_session.register_uri(
            "GET", f"{self.url}/vpx-api/v1/reports/recent", status_code=404
        )
        eve.EVEClient.get_recent_reports(self.client, reset)
        self.assertLogs(level="error")

        mock_session.register_uri(
            "GET",
            f"{self.url}/vpx-api/v1/reports/recent",
            json={"ok": "ok"},
        )

        eve.EVEClient.get_recent_reports(self.client)
        self.assertLogs(level="warning")

        self.client.private_key = None
        self.assertEqual(
            eve.EVEClient.get_recent_reports(self.client)["ok"], "ok"
        )

    @mock.patch(
        "eve_client.eve.EVEClient.get_bronco_public_key",
        return_value=string.ascii_lowercase,
    )
    @mock.patch(
        "eve_client.eve.EVEClient.decrypt_bronco_in_report", return_value={}
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
        response = eve.EVEClient.get_report(self.client, identifier)

        self.assertEqual(response, {"data": {}})

        mock_session.register_uri(
            "GET",
            f"{self.url}/vpx-api/v1/report/{identifier}",
            status_code=404,
        )
        eve.EVEClient.get_report(self.client, identifier)
        self.assertLogs(level="error")

    @mock.patch(
        "eve_client.eve.EVEClient.get_bronco_public_key",
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

        response = eve.EVEClient.get_report(self.client, identifier)
        self.assertEqual(
            response,
            {
                "errmsg": f"404: Couldn't find a report for {identifier}",
                "ok": False,
                "data": {},
            },
        )

        response = eve.EVEClient.get_report(self.client, identifier)
        self.assertEqual(
            response,
            {
                "errmsg": f"201: Couldn't find a report for {identifier}",
                "ok": False,
                "data": {},
            },
        )

    @requests_mock.Mocker()
    def test_get_vulns_by_day(self, mock_session):
        mock_session.register_uri(
            "GET",
            f"{self.url}/vpx-api/v1/aggr/vulns/by/day",
            json={},
        )

        response = eve.EVEClient.get_vulns_by_day(self.client)
        self.assertEqual(response, {})

        mock_session.register_uri(
            "GET",
            f"{self.url}/vpx-api/v1/aggr/vulns/by/day",
            status_code=404,
        )

        response = eve.EVEClient.get_vulns_by_day(self.client)
        self.assertLogs(level="error")

    @mock.patch(
        "eve_client.eve.b64decode",
        return_value="SomeValue",
    )
    @mock.patch(
        "eve_client.eve.b64encode",
        return_value=b"SomeOtherValue",
    )
    @mock.patch(
        "eve_client.eve.nacl.public.SealedBox",
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

        eve.EVEClient.generate_key_pair(self.client)
        self.assertRaises(
            exceptions.InvalidStateError,
            eve.EVEClient.generate_key_pair,
            self.client,
        )
        self.assertRaises(
            exceptions.InvalidStateError,
            eve.EVEClient.generate_key_pair,
            self.client,
        )
