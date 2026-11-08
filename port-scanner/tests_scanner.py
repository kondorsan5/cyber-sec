import unittest
import socket

from unittest.mock import patch


class TestCheckPort(unittest.TestCase):

    @patch("scanner.socket.socket")
    def test_gaierror(self, mock_socket):

        mock_sock = mock_socket.return_value.__enter__.return_value

        mock_sock.connect_ex.side_effect = socket.gaierror(
            "Name or service not known"
        )

    if __name__ == "__main__":
        unittest.main()