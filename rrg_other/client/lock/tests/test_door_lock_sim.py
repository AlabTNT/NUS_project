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

    def __init__(self, auth_failures=None, read_failures=None, accepted_keys=None):
        self.auth_failures = set(auth_failures or [])
        self.read_failures = set(read_failures or [])
        self.accepted_keys = dict(accepted_keys or {})
        self.current_key_type = None
        self.current_key = None
        self.load_calls = []
        self.auth_calls = []
        self.read_calls = []

    def get_uid(self):
        return ApduResult((0x01, 0x02, 0x03, 0x04), 0x90, 0x00)

    def load_key(self, key_type, key):
        self.load_calls.append((key_type, key))
        self.current_key_type = key_type
        self.current_key = key
        return OK

    def ensure_key_loaded(self, key_type, key):
        cached = getattr(self, "loaded_keys", {}).get(key_type) == key
        if cached:
            self.current_key_type = key_type
            self.current_key = key
            return OK, True
        if not hasattr(self, "loaded_keys"):
            self.loaded_keys = {}
        result = self.load_key(key_type, key)
        if result.ok:
            self.loaded_keys[key_type] = key
        return result, False

    def authenticate(self, block, key_type):
        self.auth_calls.append((block, key_type))
        self.current_key_type = key_type
        if (block, key_type) in self.auth_failures:
            return FAIL
        if (
            key_type in self.accepted_keys
            and self.current_key != self.accepted_keys[key_type]
        ):
            return FAIL
        return OK

    def read_block(self, block):
        self.read_calls.append((block, self.current_key_type))
        if (block, self.current_key_type) in self.read_failures:
            return FAIL
        return ApduResult(tuple([block] * 16), 0x90, 0x00)


class ShortReadDevice(FakeDevice):
    def read_block(self, block):
        self.read_calls.append((block, self.current_key_type))
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


class FakePcscApi:
    SCARD_S_SUCCESS = 0
    SCARD_SCOPE_USER = 0
    SCARD_SHARE_DIRECT = 3
    SCARD_PROTOCOL_UNDEFINED = 0
    SCARD_LEAVE_CARD = 0

    def __init__(
        self,
        response=(0xD5, 0x33, 0x90, 0x00),
        control_result=0,
    ):
        self.response = response
        self.control_result = control_result
        self.reader_name = None
        self.share_mode = None
        self.protocol = None
        self.control_code = None
        self.command = None
        self.picc_parameter = 0xFF
        self.disconnected = False
        self.context_released = False

    def SCardEstablishContext(self, scope):
        return self.SCARD_S_SUCCESS, 100

    def SCardConnect(self, context, reader_name, share_mode, protocol):
        self.reader_name = reader_name
        self.share_mode = share_mode
        self.protocol = protocol
        return self.SCARD_S_SUCCESS, 200, self.SCARD_PROTOCOL_UNDEFINED

    @staticmethod
    def SCARD_CTL_CODE(code):
        return code

    def SCardControl(self, card_handle, control_code, command):
        self.control_code = control_code
        self.command = command
        if self.control_result != self.SCARD_S_SUCCESS:
            return self.control_result, list(self.response)
        if command[:3] == [0xFF, 0x00, 0x50]:
            return self.SCARD_S_SUCCESS, [0x90, self.picc_parameter]
        if command[:3] == [0xFF, 0x00, 0x51]:
            self.picc_parameter = command[3]
            return self.SCARD_S_SUCCESS, [0x90, self.picc_parameter]
        return self.SCARD_S_SUCCESS, list(self.response)

    def SCardDisconnect(self, card_handle, disposition):
        self.disconnected = True
        return self.SCARD_S_SUCCESS

    def SCardReleaseContext(self, context):
        self.context_released = True
        return self.SCARD_S_SUCCESS

    @staticmethod
    def SCardGetErrorMessage(result):
        return f"error {result}"


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
    current = None

    def __init__(self):
        self.observer_deleted = False
        self.stopped = False
        self.observer = None
        self.next_card = 0
        FakeCardMonitor.current = self

    def addObserver(self, observer):
        self.observer = observer

    def emit_next_card(self):
        card = self.cards[self.next_card]
        self.next_card += 1
        self.observer.update(self, ([card], []))

    def deleteObserver(self, observer):
        self.observer_deleted = True

    def stop(self):
        self.stopped = True


class FakeStandbySession:
    instances = []

    def __init__(self):
        self.power_changes = [False]
        self.closed = False
        FakeStandbySession.instances.append(self)

    def set_power(self, enabled):
        self.power_changes.append(enabled)

    def wake(self):
        self.power_changes.append(True)

    def close(self):
        self.closed = True


def sector(number, required, auth, selected=(True, True, True)):
    expected = tuple(
        (bytes([number * 4 + relative_block] * 16),)
        if enabled
        else ()
        for relative_block, enabled in enumerate(selected)
    )
    return SectorConfig(
        sector=number,
        required=required,
        auth=auth,
        key_a=(bytes.fromhex("A0A1A2A3A4A5"),) if auth in {"a", "both"} else (),
        key_b=(bytes.fromhex("B0B1B2B3B4B5"),) if auth in {"b", "both"} else (),
        read_blocks=selected,
        expected_data=expected,
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

    def test_device_key_cache_skips_duplicate_load_apdu(self):
        connection = RecordingConnection()
        device = Acr122tDevice(connection)
        key = bytes.fromhex("FFFFFFFFFFFF")

        first_result, first_cached = device.ensure_key_loaded("A", key)
        second_result, second_cached = device.ensure_key_loaded("A", key)

        self.assertTrue(first_result.ok)
        self.assertFalse(first_cached)
        self.assertTrue(second_result.ok)
        self.assertTrue(second_cached)
        self.assertEqual(len(connection.apdus), 1)


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
        connections = [
            MonitoringConnection([1, 2, 3, 4]),
            MonitoringConnection([5, 6, 7, 8]),
        ]
        FakeStandbySession.instances = []

        def collect_two_then_stop(result):
            captured_uids.append(result["uid"])

        with (
            patch.object(simulator, "_select_reader", return_value="Fake ACR122T"),
            patch.object(
                simulator,
                "_load_pcsc",
                return_value=(None, (RuntimeError,), FakeCardMonitor, FakeCardObserver, 2),
            ),
            patch.object(
                simulator,
                "_enter_antenna_standby",
                side_effect=lambda reader: FakeStandbySession(),
            ),
            patch.object(
                simulator,
                "_wait_for_space",
                side_effect=[True, True, KeyboardInterrupt],
            ),
            patch.object(simulator, "_try_connect", side_effect=connections),
            patch.object(simulator, "print_result", side_effect=collect_two_then_stop),
            self.assertRaises(KeyboardInterrupt),
        ):
            simulator.run_loop(config, json_log=None, once=False)

        self.assertEqual(captured_uids, ["01020304", "05060708"])
        for connection in connections:
            self.assertTrue(connection.disconnected)
            self.assertTrue(connection.released)
        self.assertEqual(len(FakeStandbySession.instances), 3)
        self.assertTrue(all(item.closed for item in FakeStandbySession.instances))
        self.assertEqual(
            FakeStandbySession.instances[0].power_changes,
            [False, True],
        )


class AntennaControlTests(unittest.TestCase):
    def test_standby_uses_cardless_direct_connection_and_releases_handles(self):
        api = FakePcscApi()

        simulator._set_antenna_power(
            "Fake ACR122T",
            False,
            pcsc_api=api,
        )

        self.assertEqual(api.reader_name, "Fake ACR122T")
        self.assertEqual(api.share_mode, api.SCARD_SHARE_DIRECT)
        self.assertEqual(api.protocol, api.SCARD_PROTOCOL_UNDEFINED)
        self.assertEqual(api.control_code, 3500)
        self.assertEqual(api.command, simulator.ANTENNA_POWER_OFF)
        self.assertTrue(api.disconnected)
        self.assertTrue(api.context_released)

    def test_standby_keeps_direct_handle_open_until_explicit_close(self):
        api = FakePcscApi()

        session = simulator._enter_antenna_standby(
            "Fake ACR122T",
            pcsc_api=api,
        )

        self.assertEqual(api.command, simulator.ANTENNA_POWER_OFF)
        self.assertEqual(api.picc_parameter, 0x7F)
        self.assertFalse(api.disconnected)
        self.assertFalse(api.context_released)

        session.close()
        self.assertEqual(api.picc_parameter, 0xFF)
        self.assertTrue(api.disconnected)
        self.assertTrue(api.context_released)

    def test_wake_restores_auto_polling_without_duplicate_rf_on(self):
        api = FakePcscApi()
        session = simulator._enter_antenna_standby(
            "Fake ACR122T",
            pcsc_api=api,
        )

        session.wake()

        self.assertEqual(api.picc_parameter, 0xFF)
        self.assertEqual(api.command, [0xFF, 0x00, 0x51, 0xFF, 0x00])
        session.close()

    def test_space_starts_scan_and_q_exits(self):
        keys = iter(["x", " "])
        self.assertTrue(simulator._wait_for_space(lambda: next(keys)))
        self.assertFalse(simulator._wait_for_space(lambda: "q"))

    def test_control_failure_still_releases_reader_and_context(self):
        api = FakePcscApi(control_result=-1)

        with self.assertRaises(simulator.PcscUnavailableError):
            simulator._set_antenna_power(
                "Fake ACR122T",
                False,
                pcsc_api=api,
            )

        self.assertTrue(api.disconnected)
        self.assertTrue(api.context_released)


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

    def test_required_read_failure_rejects(self):
        config = AppConfig("ACR122", 0.1, (sector(0, True, "a"),))
        device = FakeDevice(read_failures={(2, "A")})

        result = scan_card(device, config, "Fake ACR122T", [0x3B, 0x00])

        self.assertFalse(result["decision"]["authorized"])
        self.assertFalse(result["sectors"][0]["read_complete"])
        self.assertFalse(result["sectors"][0]["blocks"][2]["read_ok"])
        self.assertEqual(
            result["decision"]["failed_required_data"],
            [{"sector": 0, "block": 2, "reason": "read_failed"}],
        )

    def test_optional_data_failure_does_not_reject(self):
        configured_sectors = (
            sector(0, True, "a", selected=(False, False, False)),
            sector(1, False, "a"),
        )
        config = AppConfig("ACR122", 0.1, configured_sectors)
        device = FakeDevice(read_failures={(5, "A")})

        result = scan_card(device, config, "Fake ACR122T", [0x3B, 0x00])

        self.assertTrue(result["decision"]["authorized"])
        self.assertFalse(result["sectors"][1]["verification_passed"])

    def test_result_never_serializes_keys(self):
        secret = bytes.fromhex("DEADBEEFCAFE")
        configured_sector = SectorConfig(
            0,
            True,
            "a",
            (secret,),
            (),
            (False, False, False),
            ((), (), ()),
        )
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

    def test_single_key_authenticates_once_then_reads_selected_blocks(self):
        config = AppConfig("ACR122", 0.1, (sector(3, True, "a"),))
        device = FakeDevice()

        result = scan_card(device, config, "Fake ACR122T", [0x3B, 0x00])

        self.assertTrue(result["decision"]["authorized"])
        self.assertEqual(len(device.load_calls), 1)
        self.assertEqual(device.auth_calls, [(12, "A")])
        self.assertEqual(
            device.read_calls,
            [(12, "A"), (13, "A"), (14, "A")],
        )

    def test_both_policy_reauthenticates_only_for_failed_blocks(self):
        config = AppConfig("ACR122", 0.1, (sector(1, True, "both"),))
        device = FakeDevice(read_failures={(6, "B")})

        result = scan_card(device, config, "Fake ACR122T", [0x3B, 0x00])

        self.assertTrue(result["decision"]["authorized"])
        self.assertTrue(result["sectors"][0]["read_complete"])
        self.assertEqual(len(device.load_calls), 2)
        self.assertEqual(device.auth_calls, [(4, "A"), (4, "B"), (4, "A")])
        self.assertEqual(device.read_calls[-1], (6, "A"))

    def test_same_key_is_loaded_once_across_multiple_sectors(self):
        config = AppConfig(
            "ACR122",
            0.1,
            (sector(0, True, "a"), sector(1, True, "a")),
        )
        device = FakeDevice()

        result = scan_card(device, config, "Fake ACR122T", [0x3B, 0x00])

        self.assertTrue(result["decision"]["authorized"])
        self.assertEqual(len(device.load_calls), 1)
        self.assertEqual(device.auth_calls, [(0, "A"), (4, "A")])
        self.assertEqual(len(device.read_calls), 6)

    def test_data_must_match_one_complete_candidate(self):
        matching = bytes([0x00] * 16)
        alternative = bytes([0xAA] * 16)
        configured_sector = SectorConfig(
            0,
            True,
            "a",
            (bytes.fromhex("A0A1A2A3A4A5"),),
            (),
            (True, False, False),
            ((alternative, matching), (), ()),
        )
        config = AppConfig("ACR122", 0.1, (configured_sector,))

        result = scan_card(FakeDevice(), config, "Fake ACR122T", [0x3B, 0x00])

        block = result["sectors"][0]["blocks"][0]
        self.assertTrue(result["decision"]["authorized"])
        self.assertTrue(block["data_match"])
        self.assertEqual(block["matched_data_candidate"], 2)

    def test_required_data_mismatch_rejects(self):
        configured_sector = SectorConfig(
            0,
            True,
            "a",
            (bytes.fromhex("A0A1A2A3A4A5"),),
            (),
            (True, False, False),
            ((bytes([0xFF] * 16),), (), ()),
        )
        config = AppConfig("ACR122", 0.1, (configured_sector,))

        result = scan_card(FakeDevice(), config, "Fake ACR122T", [0x3B, 0x00])

        self.assertFalse(result["decision"]["authorized"])
        self.assertEqual(
            result["decision"]["failed_required_data"],
            [{"sector": 0, "block": 0, "reason": "data_mismatch"}],
        )

    def test_candidate_keys_are_tried_in_order_without_logging_values(self):
        wrong_key = bytes.fromhex("FFFFFFFFFFFF")
        matching_key = bytes.fromhex("A0A1A2A3A4A5")
        configured_sector = SectorConfig(
            0,
            True,
            "a",
            (wrong_key, matching_key),
            (),
            (False, False, False),
            ((), (), ()),
        )
        config = AppConfig("ACR122", 0.1, (configured_sector,))
        device = FakeDevice(accepted_keys={"A": matching_key})

        result = scan_card(device, config, "Fake ACR122T", [0x3B, 0x00])
        serialized = json.dumps(result)

        authentication = result["sectors"][0]["authentication"]["A"]
        self.assertTrue(result["decision"]["authorized"])
        self.assertEqual(authentication["matched_candidate"], 2)
        self.assertEqual(len(authentication["attempts"]), 2)
        self.assertNotIn(wrong_key.hex().upper(), serialized.upper())
        self.assertNotIn(matching_key.hex().upper(), serialized.upper())


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
                        "key_a": "FFFFFFFFFFFF/A0A1A2A3A4A5",
                        "key_b": "B0:B1:B2:B3:B4:B5",
                        "block0": True,
                        "block0_data": (
                            "00000000000000000000000000000000/"
                            "11111111111111111111111111111111"
                        ),
                    },
                ],
            }
        )

        config = load_config(path)

        self.assertEqual([item.sector for item in config.sectors], [0, 2])
        self.assertEqual(config.sectors[0].required_key_types, ("A", "B"))
        self.assertEqual(len(config.sectors[0].key_a), 2)
        self.assertEqual(config.sectors[0].selected_blocks, (0,))
        self.assertEqual(len(config.sectors[0].expected_for(0)), 2)
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

    def test_rejects_selected_block_without_expected_data(self):
        path = self._write_config(
            {
                "sectors": [
                    {
                        "sector": 0,
                        "required": True,
                        "auth": "A",
                        "key_a": "FFFFFFFFFFFF",
                        "block0": True,
                    }
                ]
            }
        )

        with self.assertRaises(ConfigurationError):
            load_config(path)

    def test_rejects_expected_data_that_is_not_16_bytes(self):
        path = self._write_config(
            {
                "sectors": [
                    {
                        "sector": 0,
                        "required": True,
                        "auth": "A",
                        "key_a": "FFFFFFFFFFFF",
                        "block0": True,
                        "block0_data": "00112233",
                    }
                ]
            }
        )

        with self.assertRaises(ConfigurationError):
            load_config(path)


if __name__ == "__main__":
    unittest.main()
