import unittest


class TestPacket(unittest.TestCase):

    def test_ibeacon_advertisement_packet(self):
        from beacontools.packet_types import packet, ibeacon
        beacon = ibeacon.IBeaconAdvertisement(
            {"uuid": b"\xdb\xd1\x4e\xd0\xf5\x73\x44\x88\x9b\x98\x24\x00\xbd\x86\x24\x27",
             "major": 0x0,
             "minor": 0x1,
             "tx_power": -42})
        self.assertIsInstance(beacon, packet.BasePacket)
