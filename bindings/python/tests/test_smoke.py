# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).

import unittest

from libfcp_python import Connection, Signer, verify_envelope


class NativeSmokeTest(unittest.TestCase):
    def test_offer_actions_are_ordered_and_signed(self) -> None:
        with Signer() as local, Signer() as remote:
            with Connection(local, bytes([3]) * 32, bytes([7]) * 16, remote.public_identity) as connection:
                connection.begin_offer(bytes([9]) * 32, b"opaque-offer")
                self.assertEqual(connection.take_action().kind, 5)
                envelope = connection.take_action()
                self.assertIsNotNone(envelope)
                self.assertEqual(envelope.kind, 1)
                verify_envelope(envelope.payload)
                self.assertIsNone(connection.take_action())


if __name__ == "__main__":
    unittest.main()
