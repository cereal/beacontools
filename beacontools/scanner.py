"""Classes responsible for Beacon scanning."""
import threading
import struct
import logging
import contextlib
import itertools
try:
    zip = itertools.izip
    map = itertools.imap
except AttributeError:  # python3
    pass
from importlib import import_module

from .const import (ScannerMode, ScanType, ScanFilter, BluetoothAddressType,
                    LE_META_EVENT, OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE,
                    OCF_LE_SET_SCAN_PARAMETERS, EVT_LE_ADVERTISING_REPORT,
                    MS_FRACTION_DIVIDER,)
from .packet_types import (EddystoneUIDFrame, EddystoneURLFrame, EddystoneEIDFrame,
                           EddystoneEncryptedTLMFrame, EddystoneTLMFrame,)
from .device_filters import BtAddrFilter, DeviceFilter
from .utils import to_int, bin_to_int, get_mode


_LOGGER = logging.getLogger(__name__)
_LOGGER.setLevel(logging.DEBUG)


# pylint: disable=no-member,too-many-arguments
class Scanner(threading.Thread):

    @staticmethod
    def validate_filters(fltrs, cls):
        if fltrs is None:
            return
        elif not isinstance(fltrs, list):
            fltrs = [fltrs]

        for fltr in fltrs:
            if not isinstance(fltr, cls):
                raise ValueError("{} is not an instance of {}".format(fltr, cls))

    def __init__(self, callback, bt_device_id=0, device_filter=None, packet_filter=None):
        if callable(callback):
            self._cb = callback
        else:
            raise ValueError("callback is not a callable object!")
        from .packet_types import BasePacket
        super(Scanner, self).__init__()
        self._bt_device_id = bt_device_id
        self._device_filter = Scanner.validate_filters(device_filter, DeviceFilter)
        self._packet_filter = Scanner.validate_filters(packet_filter, BasePacket)
        self._btlib = import_module("bluetooth._bluetooth")  # bluez
        self._socket = None
        self._mode = get_mode(self._device_filter)
        self._eddystone_mappings = []
        # events
        self._consuming = threading.Event()
        self._resourceless = threading.Event()
        self._resourceless.set()

    def run(self):
        """Continously scan for BLE advertisements."""
        self._consuming.set()
        with contextlib.closing(self._btlib.hci_open_dev(self._bt_device_id)) as socket:
            self._socket = socket
            self._resourceless.clear()

            fltr = self._btlib.hci_filter_new()
            self._btlib.hci_filter_all_events(fltr)
            self._btlib.hci_filter_set_ptype(fltr, self._btlib.HCI_EVENT_PKT)
            self._socket.setsockopt(self._btlib.SOL_HCI, self._btlib.HCI_FILTER, fltr)

            self.set_scan_parameters()
            self.toggle_scan(True)

            while self._consuming.is_set():
                pkt = self._socket.recv(255)
                event = to_int(pkt[1])
                subevent = to_int(pkt[3])
                if event == LE_META_EVENT and subevent == EVT_LE_ADVERTISING_REPORT:
                    # we have an BLE advertisement
                    self.process_packet(pkt)
            self.toggle_scan(False)
            self._socket = None
        self._resourceless.set()

    def stop(self, blocking=False):
        self._consuming.clear()
        if blocking:
            self._resourceless.wait()

    def set_scan_parameters(self, scan_type=ScanType.ACTIVE, interval_ms=10, window_ms=10,
                            mac_type=BluetoothAddressType.RANDOM, filter_type=ScanFilter.ALL):
        """"sets the le scan parameters
            type     - ScanType.(PASSIVE|ACTIVE)
            interval - ms between scans (valid range 2.5ms - 10240ms)
                  !note: when interval and window are equal, the scan runs continuos
            window   - ms scan duration (valid range 2.5ms - 10240ms)
            own_type - Bluetooth address type BluetoothAddressType.(PUBLIC|RANDOM)
                       PUBLIC = use device Bluetooth MAC address
                       RANDOM = generate and use a random MAC address
            filter   - ScanFilter.(ALL|WHITELIST_ONLY) only ALL is supported, which will
                       return all fetched bluetooth packets (WHITELIST_ONLY is not supported,
                       because OCF_LE_ADD_DEVICE_TO_WHITE_LIST command is not implemented)"""
        interval_fractions = interval_ms / MS_FRACTION_DIVIDER
        if interval_fractions < 0x0004 or interval_fractions > 0x4000:
            raise ValueError(
                "Invalid interval given {}, must be in range of 2.5ms to 10240ms!".format(
                    interval_fractions))

        window_fractions = window_ms / MS_FRACTION_DIVIDER
        if window_fractions < 0x0004 or window_fractions > 0x4000:
            raise ValueError(
                "Invalid window given {}, must be in range of 2.5ms to 10240ms!".format(
                    window_fractions))

        if not self._resourceless.is_set():
            scan_parameter_pkg = struct.pack(
                ">BHHBB",
                scan_type,
                interval_fractions,
                window_fractions,
                mac_type,
                filter_type)
            self._btlib.hci_send_cmd(self._socket, OGF_LE_CTL, OCF_LE_SET_SCAN_PARAMETERS,
                                     scan_parameter_pkg)
            return
        raise RuntimeError("Couldn't send hci command, seems we are resourceless")

    def toggle_scan(self, enable, filter_duplicates=False):
        """ Enable and disable BLE scanning.
            enable            - boolean value to enable/disable scanner
            filter_duplicates - boolean value to enable/disable filter, that
                                omits duplicated packets"""
        if not self._resourceless.is_set():
            command = struct.pack(">BB", enable, filter_duplicates)
            self._btlib.hci_send_cmd(self._socket, OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE, command)
            return
        raise RuntimeError("Couldn't send hci command, seems we are resourceless")

    def _one_of_packet_filter(self, packet, fltrs=None):
        """matches the packet one of our packet filters?"""
        if fltrs is None:
            fltrs = self._packet_filter
        return any(map(
            lambda x: isinstance(*x),
            zip(itertools.cycle(packet), fltrs)))

    def process_packet(self, pkt):
        """Parse the packet and call callback if one of the filters matches."""
        # check if this could be a valid packet before parsing
        # this reduces the CPU load significantly
        from .parser import parse_packet
        from .utils import bt_addr_to_string
        if not (
                ((self._mode & ScannerMode.MODE_IBEACON) and (pkt[19:23] == b"\x4c\x00\x02\x15")) or
                ((self._mode & ScannerMode.MODE_EDDYSTONE) and (pkt[19:21] == b"\xaa\xfe")) or
                ((self._mode & ScannerMode.MODE_ESTIMOTE) and (pkt[19:21] == b"\x9a\xfe"))):
            return

        bt_addr = bt_addr_to_string(pkt[7:13])
        rssi = bin_to_int(pkt[-1])
        # strip bluetooth address and parse packet
        packet = parse_packet(pkt[14:-1])

        # return if packet was not an beacon advertisement
        if not packet:
            return

        # we need to remeber which eddystone beacon has which bt address
        # because the TLM and URL frames do not contain the namespace and instance
        self.save_bt_addr(packet, bt_addr)
        # properties holds the identifying information for a beacon
        # e.g. instance and namespace for eddystone; uuid, major, minor for iBeacon
        properties = self.get_properties(packet, bt_addr)

        if self._device_filter is None and self._packet_filter is None:
            # no filters selected
            self._cb(bt_addr, rssi, packet, properties)

        elif self._device_filter is None:
            # filter by packet type
            # if is_one_of(packet, self.packet_filter):
            if self._one_of_packet_filters(packet):
                self._cb(bt_addr, rssi, packet, properties)
        else:
            # filter by device and packet type
            if self._packet_filter and not self._one_of_packet_filters(packet):
                # return if packet filter does not match
                return

            # iterate over filters and call .matches() on each
            for fltr in self._device_filter:
                if isinstance(fltr, BtAddrFilter):
                    if fltr.matches({'bt_addr': bt_addr}):
                        self._cb(bt_addr, rssi, packet, properties)
                        return
                elif fltr.matches(properties):
                    self._cb(bt_addr, rssi, packet, properties)
                    return

    def save_bt_addr(self, packet, bt_addr):
        """Add to the list of mappings."""
        if isinstance(packet, EddystoneUIDFrame):
            # remove out old mapping
            new_mappings = [m for m in self._eddystone_mappings if m[0] != bt_addr]
            new_mappings.append((bt_addr, packet.properties))
            self._eddystone_mappings = new_mappings

    def get_properties(self, packet, bt_addr):
        """Get properties of beacon depending on type."""
        if self._one_of_packet_filters(
                packet, [EddystoneTLMFrame, EddystoneURLFrame,
                         EddystoneEncryptedTLMFrame, EddystoneEIDFrame]):
            # here we retrieve the namespace and instance which corresponds to the
            # eddystone beacon with this bt address
            return self.properties_from_mapping(bt_addr)
        else:
            return packet.properties

    def properties_from_mapping(self, bt_addr):
        """Retrieve properties (namespace, instance) for the specified bt address."""
        for addr, properties in self._eddystone_mappings:
            if addr == bt_addr:
                return properties
        return None


if __name__ == '__main__':
    def cb(a, b, c, d):
        print a, b, c, d
    scnr = Scanner(cb)
    scnr.start()
    raw_input(">")
    scnr.stop(True)
