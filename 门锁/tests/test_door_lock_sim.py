import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import door_lock_sim as simulator
from door_lock_sim import (
    Acr122tDevice,
    ApduResult,
    AppConfig,
    ConfigurationError,
    SectorConfig,
    _close_connection,
    _try_connect,
    load_config,
    scan_card,
)


OK = ApduResult((), 0x90, 0x00)
FAIL = ApduResult((), 0x63, 0x00)


class FakeDevice:
    """按 (块号, Key 类型) 控制认证和读取结果的模拟读卡器。"""

    def __init__(self, auth_failures=None, read_failures=None):
        self.auth_failures = set(auth_failures or [])
        self.read_failures = set(read_failures or [])
        self.current_key_type = None

    def get_uid(self):
        return ApduResult((0x01, 0x02, 0x03, 0x04), 0x90, 0x00)

    def load_key(self, key_type, key):
        self.current_key_type = key_type
        return OK

    def authenticate(self, block, key_type):
        self.current_key_type = key_type
        if (block, key_type) in self.auth_failures:
            return FAIL
        return OK

    def read_block(self, block):
        if (block, self.current_key_type) in self.read_failures:
            return FAIL
        return ApduResult(tuple([block] * 16), 0x90, 0x00)


class ShortReadDevice(FakeDevice):
    def read_block(self, block):
        return ApduResult((0x00, 0x01), 0x90, 0x00)


class RecordingConnection:
    def __init__(self):
        self.apdus = []

    def transmit(self, apdu):
        self.apdus.append(apdu)
        return [], 0x90, 0x00


class LifecycleConnection:
    def __init__(self, connect_error=None):
        self.connect_error = connect_error
        self.connect_disposition = None
        self.disconnected = False
        self.released = False

    def connect(self, disposition=None):
        self.connect_disposition = disposition
        if self.connect_error is not None:
            raise self.connect_error

    def disconnect(self):
        self.disconnected = True

    def release(self):
        self.released = True


class LifecycleSource:
    def __init__(self, connection):
        self.connection = connection

    def createConnection(self):
        return self.connection


class MonitoringConnection(LifecycleConnection):
    def __init__(self, uid):
        super().__init__()
        self.uid = uid

    def getATR(self):
        return [0x3B, 0x00]

    def transmit(self, apdu):
        if apdu[:2] == [0xFF, 0xCA]:
            return self.uid, 0x90, 0x00
        if apdu[:2] == [0xFF, 0xB0]:
            return [apdu[3]] * 16, 0x90, 0x00
        return [], 0x90, 0x00


class MonitoringCard(LifecycleSource):
    def __init__(self, uid):
        super().__init__(MonitoringConnection(uid))
        self.reader = "Fake ACR122T"
        self.atr = [0x3B, 0x00]


class FakeCardObserver:
    pass


class FakeCardMonitor:
    cards = [MonitoringCard([1, 2, 3, 4]), MonitoringCard([5, 6, 7, 8])]

    def __init__(self):
        self.observer_deleted = False
        self.stopped = False

    def addObserver(self, observer):
        observer.update(self, ([self.cards[0]], []))
        observer.update(self, ([], [self.cards[0]]))
        observer.update(self, ([self.cards[1]], []))

    def deleteObserver(self, observer):
        self.observer_deleted = True

    def stop(self):
        self.stopped = True


def sector(number, required, auth):
    return SectorConfig(
        sector=number,
        required=required,
        auth=auth,
        key_a=bytes.fromhex("A0A1A2A3A4A5") if auth in {"a", "both"} else None,
        key_b=bytes.fromhex("B0B1B2B3B4B5") if auth in {"b", "both"} else None,
    )


class ApduTests(unittest.TestCase):
    def test_official_acr122t_apdu_shapes(self):
        connection = RecordingConnection()
        device = Acr122tDevice(connection)

        device.get_uid()
        device.load_key("A", bytes.fromhex("FFFFFFFFFFFF"))
        device.authenticate(4, "A")
        device.read_block(4)

        self.assertEqual(connection.apdus[0], [0xFF, 0xCA, 0, 0, 0])
        self.assertEqual(
            connection.apdus[1],
            [0xFF, 0x82, 0, 0, 6, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        )
        self.assertEqual(
            connection.apdus[2],
            [0xFF, 0x86, 0, 0, 5, 1, 0, 4, 0x60, 0],
        )
        self.assertEqual(connection.apdus[3], [0xFF, 0xB0, 0, 4, 0x10])


class ConnectionLifecycleTests(unittest.TestCase):
    def test_successful_connection_is_explicitly_closed_and_released(self):
        connection = LifecycleConnection()
        source = LifecycleSource(connection)

        connected = _try_connect(source, (RuntimeError,), disconnect_disposition=2)
        self.assertIs(connected, connection)
        self.assertEqual(connection.connect_disposition, 2)

        _close_connection(connection)
        self.assertTrue(connection.disconnected)
        self.assertTrue(connection.released)

    def test_failed_connection_also_releases_context(self):
        connection = LifecycleConnection(connect_error=RuntimeError("no card"))
        source = LifecycleSource(connection)

        connected = _try_connect(source, (RuntimeError,), disconnect_disposition=2)

        self.assertIsNone(connected)
        self.assertTrue(connection.disconnected)
        self.assertTrue(connection.released)

    def test_continuous_mode_processes_and_releases_two_cards(self):
        config = AppConfig("ACR122", 0.05, (sector(0, True, "a"),))
        captured_uids = []

        def collect_two_then_stop(result):
            captured_uids.append(result["uid"])
            if len(captured_uids) == 2:
                raise KeyboardInterrupt

        with (
            patch.object(simulator, "_select_reader", return_value="Fake ACR122T"),
            patch.object(
                simulator,
                "_load_pcsc",
                return_value=(None, (RuntimeError,), FakeCardMonitor, FakeCardObserver, 2),
            ),
            patch.object(simulator, "print_result", side_effect=collect_two_then_stop),
            self.assertRaises(KeyboardInterrupt),
        ):
            simulator.run_loop(config, json_log=None, once=False)

        self.assertEqual(captured_uids, ["01020304", "05060708"])
        for card in FakeCardMonitor.cards:
            self.assertTrue(card.connection.disconnected)
            self.assertTrue(card.connection.released)


class DecisionTests(unittest.TestCase):
    def test_both_policy_requires_a_and_b(self):
        config = AppConfig("ACR122", 0.1, (sector(1, True, "both"),))
        device = FakeDevice(auth_failures={(4, "B")})

        result = scan_card(device, config, "Fake ACR122T", [0x3B, 0x00])

        self.assertTrue(result["sectors"][0]["authentication"]["A"]["ok"])
        self.assertFalse(result["sectors"][0]["authentication"]["B"]["ok"])
        self.assertFalse(result["decision"]["authorized"])
        self.assertEqual(result["decision"]["failed_required_sectors"], [1])

    def test_optional_auth_failure_does_not_reject(self):
        config = AppConfig(
            "ACR122",
            0.1,
            (sector(0, True, "a"), sector(2, False, "b")),
        )
        device = FakeDevice(auth_failures={(8, "B")})

        result = scan_card(device, config, "Fake ACR122T", [0x3B, 0x00])

        self.assertTrue(result["decision"]["authorized"])
        self.assertFalse(result["sectors"][1]["auth_passed"])

    def test_read_failure_is_marked_but_does_not_reject(self):
        config = AppConfig("ACR122", 0.1, (sector(0, True, "a"),))
        device = FakeDevice(read_failures={(2, "A")})

        result = scan_card(device, config, "Fake ACR122T", [0x3B, 0x00])

        self.assertTrue(result["decision"]["authorized"])
        self.assertFalse(result["sectors"][0]["read_complete"])
        self.assertFalse(result["sectors"][0]["blocks"][2]["read_ok"])

    def test_result_never_serializes_keys(self):
        secret = bytes.fromhex("DEADBEEFCAFE")
        configured_sector = SectorConfig(0, True, "a", secret, None)
        config = AppConfig("ACR122", 0.1, (configured_sector,))

        result = scan_card(FakeDevice(), config, "Fake ACR122T", [0x3B, 0x00])
        serialized = json.dumps(result)

        self.assertNotIn("DEADBEEFCAFE", serialized.upper())

    def test_short_success_response_is_still_a_read_failure(self):
        config = AppConfig("ACR122", 0.1, (sector(0, True, "a"),))

        result = scan_card(ShortReadDevice(), config, "Fake ACR122T", [0x3B, 0x00])

        first_block = result["sectors"][0]["blocks"][0]
        self.assertFalse(first_block["read_ok"])
        self.assertEqual(first_block["attempts"][0]["read"]["data_length"], 2)


class ConfigurationTests(unittest.TestCase):
    def _write_config(self, data):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "config.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_loads_and_sorts_valid_sectors(self):
        path = self._write_config(
            {
                "reader": {"name_contains": "ACR122", "poll_interval_ms": 250},
                "sectors": [
                    {
                        "sector": 2,
                        "required": False,
                        "auth": "B",
                        "key_b": "FF FF FF FF FF FF",
                    },
                    {
                        "sector": 0,
                        "required": True,
                        "auth": "both",
                        "key_a": "A0A1A2A3A4A5",
                        "key_b": "B0:B1:B2:B3:B4:B5",
                    },
                ],
            }
        )

        config = load_config(path)

        self.assertEqual([item.sector for item in config.sectors], [0, 2])
        self.assertEqual(config.sectors[0].required_key_types, ("A", "B"))
        self.assertEqual(config.poll_interval_seconds, 0.25)

    def test_rejects_missing_required_key(self):
        path = self._write_config(
            {
                "sectors": [
                    {"sector": 0, "required": True, "auth": "both", "key_a": "FFFFFFFFFFFF"}
                ]
            }
        )

        with self.assertRaises(ConfigurationError):
            load_config(path)


if __name__ == "__main__":
    unittest.main()
