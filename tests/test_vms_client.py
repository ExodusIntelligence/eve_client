import datetime
import string
import unittest
from unittest.mock import patch

import requests
import requests_mock

from vms_client import __version__, vms


class TestVMSClient(unittest.TestCase):
    url = "mock://vpx.exodusintel.com/"
    email = "123@abc.com"
    password = "abc12345"
    private_key = string.ascii_lowercase

    session = requests.Session()

    @patch("vms_client.vms.Client.get_access_token", return_value="abc")
    def test_init(self, mock_get_access_token):
        response = vms.Client(self.email, self.password, self.private_key)
        self.assertEqual(response.token, "abc")

    @requests_mock.Mocker()
    def test_get_access_token(self, mock_session):
        json = {
            "email": self.email,
            "password": self.password,
            "access_token": "abc",
        }

        mock_session.register_uri(
            "POST",
            f"{self.url}vpx-api/v1/login",
            [
                {"json": json, "status_code": 200},
                {"json": json, "status_code": 201},
            ],
        )
        response = vms.Client.get_access_token(self)
        self.assertEqual(response, "abc")
        self.assertRaises(
            requests.exceptions.ConnectionError,
            vms.Client.get_access_token,
            self,
        )

    def test_version(self):
        self.assertEqual(__version__, "0.1.3")

    def testClassValidArguments(self):
        self.assertTrue(vms.verify_email("test00@test.com"))
        self.assertTrue(vms.verify_email("00@test.com"))

    def testClassInvalidArguments(self):
        self.assertRaises(ValueError, vms.verify_email, ".com")
        self.assertRaises(ValueError, vms.verify_email, 5j)

    @requests_mock.Mocker()
    def testGet_Bronco_Public_Key(self, mock_session):
        mock_session.register_uri(
            "GET",
            f"{self.url}vpx-api/v1/bronco-public-key",
            json={
                "data": {"public_key": string.ascii_lowercase},
                "errmsg": None,
                "ok": True,
            },
            status_code=404,
        )
        response = vms.Client.get_bronco_public_key(self)

        self.assertEqual(response, string.ascii_lowercase)

    @requests_mock.Mocker()
    def testFail_Get_Bronco_Public_Key(self, mock_session):
        mock_session.register_uri(
            "GET",
            f"{self.url}vpx-api/v1/bronco-public-key",
            exc=requests.exceptions.InvalidURL,
        )
        self.assertRaises(
            requests.exceptions.InvalidURL,
            vms.Client.get_bronco_public_key,
            self,
        )

    def test_Decrypt_Bronco_In_Report(self):
        pass

    def test_handle_reset_option(self):
        reset = 1
        response = vms.Client.handle_reset_option(self, reset)
        self.assertGreaterEqual(
            datetime.datetime.now(),
            response,
        )

        # Test Reset None
        reset = None
        response = vms.Client.handle_reset_option(self, reset)
        self.assertEqual(response, reset)

        # Test Reset as YYYY-MM-DD
        reset = "2022-10"
        response = vms.Client.handle_reset_option(self, reset)

        # Test Raise Value Error
        reset = "2022-10-DD"
        self.assertRaises(
            ValueError, vms.Client.handle_reset_option, self, reset
        )

    @requests_mock.Mocker()
    def test_get_vuln(self, mock_session):
        identifier = "cve12345"
        mock_session.register_uri(
            "GET",
            f"{self.url}vpx-api/v1/vuln/for/{identifier}",
            [{"json": {"ok": "ok"}}, {"json": {}}],
        )
        response = vms.Client.get_vuln(self, identifier)
        self.assertEqual(response, {"ok": "ok"})
        self.assertRaises(KeyError, vms.Client.get_vuln, self, identifier)

    @patch(
        "vms_client.vms.Client.handle_reset_option",
        return_value=datetime.datetime.now(),
    )
    @requests_mock.Mocker()
    def test_get_recent_vulns(self, mock_handled_reset_option, mock_session):
        self.handle_reset_option = mock_handled_reset_option
        mock_session.register_uri(
            "GET",
            f"{self.url}vpx-api/v1/vulns/recent",
            [{"json": {"ok": "ok"}}],
        )

        response = vms.Client.get_recent_vulns(self)
        self.assertEqual(response, {"ok": "ok"})

    @patch(
        "vms_client.vms.Client.get_bronco_public_key",
        return_value=string.ascii_lowercase,
    )
    @patch(
        "vms_client.vms.Client.handle_reset_option",
        return_value=datetime.datetime.now(),
    )
    @requests_mock.Mocker()
    def test_get_recent_reports(
        self,
        mock_handle_reset_option,
        mock_get_bronco_public_key,
        mock_session,
    ):
        self.get_bronco_public_key = mock_get_bronco_public_key
        self.handle_reset_option = mock_handle_reset_option
        self.private_key = string.ascii_lowercase
        reset = "2022/02/22"
        mock_session.register_uri(
            "GET",
            f"{self.url}vpx-api/v1/reports/recent",
            [
                {"json": {"ok": "ok", "data": {"items": {}}}},
                {"json": {}},
            ],
        )

        response = vms.Client.get_recent_reports(self, reset)

        self.assertRaises(KeyError, vms.Client.get_recent_reports, self, reset)

        mock_session.register_uri(
            "GET",
            f"{self.url}vpx-api/v1/reports/recent",
            exc=requests.exceptions.InvalidURL,
        )
        self.assertRaises(
            requests.exceptions.InvalidURL,
            vms.Client.get_recent_reports,
            self,
        )
        mock_session.register_uri(
            "GET",
            f"{self.url}vpx-api/v1/reports/recent",
            json={},
        )
        # Test no private_key
        self.private_key = None
        response = vms.Client.get_recent_reports(self)
        self.assertEqual(response, None)

    @patch(
        "vms_client.vms.Client.get_bronco_public_key",
        return_value=string.ascii_lowercase,
    )
    @patch("vms_client.vms.Client.decrypt_bronco_in_report", return_value={})
    @requests_mock.Mocker()
    def test_get_report(
        self,
        mock_decrypt_bronco_in_report,
        mock_get_bronco_public_key,
        mock_session,
    ):
        self.get_bronco_public_key = mock_get_bronco_public_key
        self.decrypt_bronco_in_report = mock_decrypt_bronco_in_report
        identifier = "cve12345"
        mock_session.register_uri(
            "GET",
            f"{self.url}vpx-api/v1/report/{identifier}",
            json={"data": {}},
        )

        response = vms.Client.get_report(self, identifier)

        self.assertEqual(response, {"data": {}})

    @patch(
        "vms_client.vms.Client.get_bronco_public_key",
        return_value=string.ascii_lowercase,
    )
    @requests_mock.Mocker()
    def test_get_report_fail(self, mock_get_bronco_public_key, mock_session):
        identifier = "cve12345"
        self.get_bronco_public_key = mock_get_bronco_public_key
        mock_session.register_uri(
            "GET",
            f"{self.url}vpx-api/v1/report/{identifier}",
            [{"status_code": 404}, {"status_code": 201}],
        )

        response = vms.Client.get_report(self, identifier)
        self.assertEqual(
            response,
            {
                "msg": f"Couldn't find a report for {identifier}",
                "status": 404,
                "data": None,
            },
        )

        response = vms.Client.get_report(self, identifier)
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
            f"{self.url}vpx-api/v1/aggr/vulns/by/day",
            json={},
        )

        response = vms.Client.get_vulns_by_day(self)
        self.assertEqual(response, {})

    @requests_mock.Mocker()
    def test_get_vulns_by_day_fail(self, mock_session):
        mock_session.register_uri(
            "GET",
            f"{self.url}vpx-api/v1/aggr/vulns/by/day",
            exc=requests.exceptions.InvalidURL,
        )
        self.assertRaises(
            requests.exceptions.InvalidURL, vms.Client.get_vulns_by_day, self
        )

    # @patch(
    #     "vms_client.vms.nacl.public.PrivateKey.generate",
    #     return_value=string.ascii_lowercase,
    # )
    # @requests_mock.Mocker()
    # def test_generate_key_pair(
    #     self, mock_naclPublicPrivateKeyGenerate, mock_session
    # ):
    #     mock_session.get(f"{self.url}vpx-api/v1/pubkey")

    #     response = vms.Client.generate_key_pair(self)
    #     pass
