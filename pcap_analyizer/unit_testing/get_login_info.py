import unittest
from scapy.layers import http
from main import get_login_info


class TestGetLoginInfo(unittest.TestCase):

    def test_get_login_info_with_http_request_and_raw_data(self):
        # Create a mock packet with HTTPRequest and Raw layers
        mock_packet = http.HTTPRequest() / http.Raw(load=b'username=admin&password=123456')

        # Call the function with the mock packet
        login_info = get_login_info(mock_packet)

        # Assert that the login info is returned correctly
        self.assertEqual(login_info, b'username=admin&password=123456')

    def test_get_login_info_without_http_request(self):
        # Create a mock packet without HTTPRequest layer
        mock_packet = http.Raw(load=b'username=admin&password=123456')

        # Call the function with the mock packet
        login_info = get_login_info(mock_packet)

        # Assert that None is returned when there's no HTTPRequest layer
        self.assertIsNone(login_info)

    def test_get_login_info_without_raw_data(self):
        # Create a mock packet with HTTPRequest but without Raw layer
        mock_packet = http.HTTPRequest()

        # Call the function with the mock packet
        login_info = get_login_info(mock_packet)

        # Assert that None is returned when there's no Raw layer
        self.assertIsNone(login_info)

if __name__ == '__main__':
    unittest.main()
