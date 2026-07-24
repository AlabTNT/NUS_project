#!/usr/bin/env python3
"""使用 ACR122T/PCSC 模拟 MIFARE Classic 1K 门锁读卡流程。

支持候选密钥、选定数据块的多候选精确匹配，以及按空格开启一次射频的待机模式。
程序只执行读取操作，不会向卡片写入数据。MIFARE Classic 的 Crypto1 三次认证
由 ACR122T 与卡片完成；PC/SC 接口只返回认证结果。
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Protocol, Sequence


SUCCESS_STATUS = (0x90, 0x00)
KEY_TYPE_CODE = {"A": 0x60, "B": 0x61}
KEY_SLOT = {"A": 0x00, "B": 0x01}
ANTENNA_POWER_OFF = [0xFF, 0x00, 0x00, 0x00, 0x04, 0xD4, 0x32, 0x01, 0x00]
ANTENNA_POWER_ON = [0xFF, 0x00, 0x00, 0x00, 0x04, 0xD4, 0x32, 0x01, 0x01]


class ConfigurationError(ValueError):
    """配置文件内容不合法。"""


class PcscUnavailableError(RuntimeError):
    """Windows PC/SC 或 pyscard 不可用。"""


class CardConnection(Protocol):
    """pyscard 连接对象所需的最小接口，便于无硬件单元测试。"""

    def transmit(self, apdu: list[int]) -> tuple[list[int], int, int]:
        """发送一条 APDU。"""


@dataclass(frozen=True)
class ApduResult:
    """一次 APDU 交互的标准化结果。"""

    data: tuple[int, ...]
    sw1: int | None
    sw2: int | None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and (self.sw1, self.sw2) == SUCCESS_STATUS

    @property
    def status(self) -> str | None:
        if self.sw1 is None or self.sw2 is None:
            return None
        return f"{self.sw1:02X}{self.sw2:02X}"

    def summary(self) -> dict[str, Any]:
        result: dict[str, Any] = {"ok": self.ok, "status": self.status}
        if self.error:
            result["error"] = self.error
        return result


@dataclass(frozen=True)
class SectorConfig:
    """一个 MIFARE Classic 1K 扇区的认证配置。"""

    sector: int
    required: bool
    auth: str
    key_a: tuple[bytes, ...]
    key_b: tuple[bytes, ...]
    read_blocks: tuple[bool, bool, bool]
    expected_data: tuple[
        tuple[bytes, ...],
        tuple[bytes, ...],
        tuple[bytes, ...],
    ]

    @property
    def required_key_types(self) -> tuple[str, ...]:
        if self.auth == "both":
            return ("A", "B")
        return (self.auth.upper(),)

    def keys_for(self, key_type: str) -> tuple[bytes, ...]:
        return self.key_a if key_type == "A" else self.key_b

    @property
    def selected_blocks(self) -> tuple[int, ...]:
        return tuple(index for index, enabled in enumerate(self.read_blocks) if enabled)

    def expected_for(self, relative_block: int) -> tuple[bytes, ...]:
        return self.expected_data[relative_block]


@dataclass(frozen=True)
class AppConfig:
    """已校验的程序配置。"""

    reader_name_contains: str
    poll_interval_seconds: float
    sectors: tuple[SectorConfig, ...]


class Acr122tDevice:
    """ACR122T 的 MIFARE Classic PC/SC APDU 封装。"""

    def __init__(self, connection: CardConnection):
        self.connection = connection
        self._loaded_keys: dict[str, bytes] = {}
        self.command_count = 0

    def _transmit(self, apdu: list[int]) -> ApduResult:
        self.command_count += 1
        try:
            data, sw1, sw2 = self.connection.transmit(apdu)
            return ApduResult(tuple(data), sw1, sw2)
        except Exception as exc:  # pyscard 在拔卡时可能抛出多种后端异常。
            return ApduResult((), None, None, f"{type(exc).__name__}: {exc}")

    def get_uid(self) -> ApduResult:
        # Le=00 表示请求完整 UID，兼容 4/7/10 字节 UID。
        return self._transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])

    def load_key(self, key_type: str, key: bytes) -> ApduResult:
        slot = KEY_SLOT[key_type]
        return self._transmit([0xFF, 0x82, 0x00, slot, 0x06, *key])

    def ensure_key_loaded(self, key_type: str, key: bytes) -> tuple[ApduResult, bool]:
        """仅当对应槽位中的密钥发生变化时才发送 Load Key APDU。"""

        if self._loaded_keys.get(key_type) == key:
            return ApduResult((), 0x90, 0x00), True

        result = self.load_key(key_type, key)
        if result.ok:
            self._loaded_keys[key_type] = key
        return result, False

    def authenticate(self, block: int, key_type: str) -> ApduResult:
        return self._transmit(
            [
                0xFF,
                0x86,
                0x00,
                0x00,
                0x05,
                0x01,
                0x00,
                block,
                KEY_TYPE_CODE[key_type],
                KEY_SLOT[key_type],
            ]
        )

    def read_block(self, block: int) -> ApduResult:
        return self._transmit([0xFF, 0xB0, 0x00, block, 0x10])


def _parse_hex_candidates(
    value: Any,
    field_name: str,
    byte_length: int,
) -> tuple[bytes, ...]:
    """解析以 / 分隔的一个或多个定长十六进制候选值。"""

    if value is None:
        return ()
    if not isinstance(value, str):
        raise ConfigurationError(f"{field_name} 必须是字符串或 null")

    parts = value.split("/")
    if not parts or any(not part.strip() for part in parts):
        raise ConfigurationError(f"{field_name} 的 / 两侧都必须包含候选值")

    candidates: list[bytes] = []
    for candidate_index, part in enumerate(parts, start=1):
        normalized = part.replace(" ", "").replace(":", "").replace("-", "")
        candidate_name = f"{field_name} 的第 {candidate_index} 个候选值"
        if len(normalized) != byte_length * 2:
            raise ConfigurationError(
                f"{candidate_name} 必须恰好包含 {byte_length} 字节"
            )
        try:
            candidate = bytes.fromhex(normalized)
        except ValueError as exc:
            raise ConfigurationError(f"{candidate_name} 含有非十六进制字符") from exc
        if candidate not in candidates:
            candidates.append(candidate)
    return tuple(candidates)


def load_config(path: Path) -> AppConfig:
    """读取并严格校验 JSON 配置。"""

    try:
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as exc:
        raise ConfigurationError(f"找不到配置文件：{path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigurationError(
            f"配置文件 JSON 格式错误（第 {exc.lineno} 行，第 {exc.colno} 列）：{exc.msg}"
        ) from exc

    if not isinstance(raw, dict):
        raise ConfigurationError("配置文件根节点必须是 JSON 对象")

    reader = raw.get("reader", {})
    if not isinstance(reader, dict):
        raise ConfigurationError("reader 必须是 JSON 对象")
    name_contains = reader.get("name_contains", "ACR122")
    if not isinstance(name_contains, str):
        raise ConfigurationError("reader.name_contains 必须是字符串")
    poll_ms = reader.get("poll_interval_ms", 300)
    if not isinstance(poll_ms, int) or not 50 <= poll_ms <= 10_000:
        raise ConfigurationError("reader.poll_interval_ms 必须是 50 到 10000 的整数")

    raw_sectors = raw.get("sectors")
    if not isinstance(raw_sectors, list) or not raw_sectors:
        raise ConfigurationError("sectors 必须是非空数组")

    sectors: list[SectorConfig] = []
    seen: set[int] = set()
    for index, item in enumerate(raw_sectors):
        prefix = f"sectors[{index}]"
        if not isinstance(item, dict):
            raise ConfigurationError(f"{prefix} 必须是 JSON 对象")

        sector = item.get("sector")
        if not isinstance(sector, int) or isinstance(sector, bool) or not 0 <= sector <= 15:
            raise ConfigurationError(f"{prefix}.sector 必须是 0 到 15 的整数")
        if sector in seen:
            raise ConfigurationError(f"扇区 {sector} 重复配置")
        seen.add(sector)

        required = item.get("required", False)
        if not isinstance(required, bool):
            raise ConfigurationError(f"{prefix}.required 必须是 true 或 false")

        auth = item.get("auth")
        if not isinstance(auth, str) or auth.lower() not in {"a", "b", "both"}:
            raise ConfigurationError(f"{prefix}.auth 必须是 A、B 或 both")
        auth = auth.lower()

        key_a = _parse_hex_candidates(item.get("key_a"), f"{prefix}.key_a", 6)
        key_b = _parse_hex_candidates(item.get("key_b"), f"{prefix}.key_b", 6)
        if auth in {"a", "both"} and not key_a:
            raise ConfigurationError(f"{prefix} 的认证策略需要 key_a")
        if auth in {"b", "both"} and not key_b:
            raise ConfigurationError(f"{prefix} 的认证策略需要 key_b")

        read_blocks: list[bool] = []
        expected_data: list[tuple[bytes, ...]] = []
        for relative_block in range(3):
            block_field = f"block{relative_block}"
            data_field = f"{block_field}_data"
            enabled = item.get(block_field, False)
            if not isinstance(enabled, bool):
                raise ConfigurationError(f"{prefix}.{block_field} 必须是 true 或 false")

            candidates = _parse_hex_candidates(
                item.get(data_field),
                f"{prefix}.{data_field}",
                16,
            )
            if enabled and not candidates:
                raise ConfigurationError(
                    f"{prefix}.{block_field}=true 时必须提供 {data_field}"
                )
            if not enabled and candidates:
                raise ConfigurationError(
                    f"{prefix}.{block_field}=false 时 {data_field} 必须是 null 或省略"
                )
            read_blocks.append(enabled)
            expected_data.append(candidates)

        sectors.append(
            SectorConfig(
                sector,
                required,
                auth,
                key_a,
                key_b,
                tuple(read_blocks),  # type: ignore[arg-type]
                tuple(expected_data),  # type: ignore[arg-type]
            )
        )

    if not any(sector.required for sector in sectors):
        raise ConfigurationError("至少要把一个扇区设置为 required=true")

    return AppConfig(
        reader_name_contains=name_contains,
        poll_interval_seconds=poll_ms / 1000.0,
        sectors=tuple(sorted(sectors, key=lambda item: item.sector)),
    )


def _hex(data: Sequence[int]) -> str:
    return "".join(f"{value:02X}" for value in data)


def _authenticate_candidates(
    device: Acr122tDevice,
    sector: SectorConfig,
    block: int,
    key_type: str,
) -> dict[str, Any]:
    """依次尝试候选密钥，只记录命中的候选序号而不记录密钥值。"""

    attempts: list[dict[str, Any]] = []
    for candidate_index, key in enumerate(sector.keys_for(key_type), start=1):
        loaded, cached = device.ensure_key_loaded(key_type, key)
        load_summary = loaded.summary()
        load_summary["cached"] = cached
        attempt: dict[str, Any] = {
            "candidate_index": candidate_index,
            "load_key": load_summary,
        }
        if not loaded.ok:
            attempt["authenticate"] = {
                "ok": False,
                "status": None,
                "skipped": True,
            }
            attempts.append(attempt)
            continue

        authenticated = device.authenticate(block, key_type)
        attempt["authenticate"] = authenticated.summary()
        attempts.append(attempt)
        if authenticated.ok:
            return {
                "ok": True,
                "matched_candidate": candidate_index,
                "attempts": attempts,
            }

    return {
        "ok": False,
        "matched_candidate": None,
        "attempts": attempts,
    }


def _read_sector_blocks(
    device: Acr122tDevice,
    sector: SectorConfig,
    first_block: int,
    usable_keys: Sequence[str],
    active_key: str | None,
) -> list[dict[str, Any]]:
    """读取选定数据块，并与该块的多个 16 字节候选值精确比较。"""

    blocks: list[dict[str, Any]] = [
        {
            "sector": sector.sector,
            "block": relative_block,
            "absolute_block": first_block + relative_block,
            "read_ok": False,
            "data_hex": None,
            "data_match": False,
            "matched_data_candidate": None,
            "verification_passed": False,
            "used_key": None,
            "attempts": [],
        }
        for relative_block in sector.selected_blocks
    ]

    # 优先复用初始化验证后仍处于活动状态的密钥，避免额外认证。
    read_order = list(usable_keys)
    if active_key in read_order:
        read_order.remove(active_key)
        read_order.insert(0, active_key)

    for key_type in read_order:
        unread_blocks = [block for block in blocks if not block["read_ok"]]
        if not unread_blocks:
            break

        if active_key == key_type:
            session_authentication: dict[str, Any] = {
                "ok": True,
                "reused_initial_authentication": True,
            }
        else:
            # 密钥在扇区初始验证时已经装入 A/B 独立槽位，只需重新认证一次。
            authenticated = device.authenticate(first_block, key_type)
            session_authentication = {
                "ok": authenticated.ok,
                "load_key": {
                    "ok": True,
                    "status": None,
                    "skipped": True,
                    "reason": "key already loaded in reader slot",
                },
                "authenticate": authenticated.summary(),
            }
            active_key = key_type if authenticated.ok else None

        if not session_authentication["ok"]:
            for block in unread_blocks:
                block["attempts"].append(
                    {
                        "key_type": key_type,
                        "authentication": session_authentication,
                        "read": {"ok": False, "status": None, "skipped": True},
                    }
                )
            continue

        for block in unread_blocks:
            read_result = device.read_block(block["absolute_block"])
            read_summary = read_result.summary()
            read_summary["data_length"] = len(read_result.data)
            read_success = read_result.ok and len(read_result.data) == 16
            if read_result.ok and not read_success:
                read_summary["ok"] = False
                read_summary["error"] = "返回数据不是 16 字节"

            block["attempts"].append(
                {
                    "key_type": key_type,
                    "authentication": session_authentication,
                    "read": read_summary,
                }
            )
            if read_success:
                actual_data = bytes(read_result.data)
                expected_candidates = sector.expected_for(block["block"])
                matched_candidate = next(
                    (
                        index
                        for index, candidate in enumerate(
                            expected_candidates,
                            start=1,
                        )
                        if candidate == actual_data
                    ),
                    None,
                )
                block["read_ok"] = True
                block["data_hex"] = _hex(actual_data)
                block["data_match"] = matched_candidate is not None
                block["matched_data_candidate"] = matched_candidate
                block["verification_passed"] = matched_candidate is not None
                block["used_key"] = key_type

    return blocks


def scan_card(
    device: Acr122tDevice,
    config: AppConfig,
    reader_name: str,
    atr: Sequence[int],
) -> dict[str, Any]:
    """认证并读取当前卡片，返回不包含密钥的结构化采集结果。"""

    started = time.perf_counter()
    result: dict[str, Any] = {
        "schema_version": 2,
        "capture_id": str(uuid.uuid4()),
        "timestamp": datetime.now().astimezone().isoformat(timespec="milliseconds"),
        "reader": reader_name,
        "atr": _hex(atr),
        "uid": None,
        "expected_card_type": "MIFARE Classic 1K",
        "authentication_protocol": "MIFARE Classic Crypto1 three-pass authentication",
        "challenge_visibility": "performed inside reader/card; nonce transcript is not exposed by PC/SC",
        "sectors": [],
    }

    uid_result = device.get_uid()
    result["uid_command"] = uid_result.summary()
    uid_ok = uid_result.ok and len(uid_result.data) in {4, 7, 10}
    if uid_ok:
        result["uid"] = _hex(uid_result.data)
    elif uid_result.ok:
        result["uid_command"]["ok"] = False
        result["uid_command"]["error"] = "UID 长度不是 4、7 或 10 字节"

    failed_required: list[int] = []
    failed_required_auth: list[int] = []
    failed_required_data: list[dict[str, Any]] = []
    for sector in config.sectors:
        sector_started = time.perf_counter()
        first_block = sector.sector * 4
        authentication: dict[str, Any] = {}
        usable_keys: list[str] = []
        active_key: str | None = None

        for key_type in sector.required_key_types:
            auth_result = _authenticate_candidates(device, sector, first_block, key_type)
            authentication[key_type] = auth_result
            if auth_result["ok"]:
                usable_keys.append(key_type)
                active_key = key_type
            else:
                # 一次失败的认证后不能假定此前的 Crypto1 会话仍然有效。
                active_key = None

        auth_passed = all(
            authentication[key_type]["ok"] for key_type in sector.required_key_types
        )
        blocks = _read_sector_blocks(
            device,
            sector,
            first_block,
            usable_keys,
            active_key,
        )
        data_passed = all(block["verification_passed"] for block in blocks)
        verification_passed = auth_passed and data_passed
        sector_result = {
            "sector": sector.sector,
            "required": sector.required,
            "auth_policy": sector.auth,
            "selected_blocks": list(sector.selected_blocks),
            "authentication": authentication,
            "auth_passed": auth_passed,
            "data_passed": data_passed,
            "verification_passed": verification_passed,
            "read_complete": all(block["read_ok"] for block in blocks),
            "blocks": blocks,
            "duration_ms": round(
                (time.perf_counter() - sector_started) * 1000,
                3,
            ),
        }
        result["sectors"].append(sector_result)
        if sector.required and not verification_passed:
            failed_required.append(sector.sector)
            if not auth_passed:
                failed_required_auth.append(sector.sector)
            failed_required_data.extend(
                {
                    "sector": sector.sector,
                    "block": block["block"],
                    "reason": (
                        "read_failed"
                        if not block["read_ok"]
                        else "data_mismatch"
                    ),
                }
                for block in blocks
                if not block["verification_passed"]
            )

    authorized = uid_ok and not failed_required
    if not uid_ok:
        reason = "无法读取卡片 UID"
    elif failed_required_auth:
        reason = "必需扇区密钥认证失败"
    elif failed_required_data:
        reason = "必需扇区数据检验失败"
    else:
        reason = "所有必需扇区均通过密钥和数据检验"

    result["decision"] = {
        "authorized": authorized,
        "reason": reason,
        "required_sectors": [item.sector for item in config.sectors if item.required],
        "failed_required_sectors": failed_required,
        "failed_required_auth_sectors": failed_required_auth,
        "failed_required_data": failed_required_data,
        "optional_failures_do_not_change_decision": True,
    }
    result["duration_ms"] = round((time.perf_counter() - started) * 1000, 3)
    result["apdu_count"] = getattr(device, "command_count", None)
    return result


def print_result(result: dict[str, Any]) -> None:
    """把一次刷卡结果输出为便于人工查看的中文文本。"""

    print("\n" + "=" * 72)
    print(f"时间: {result['timestamp']}")
    print(f"读卡器: {result['reader']}")
    print(f"UID: {result['uid'] or '<读取失败>'}    ATR: {result['atr']}")

    for sector in result["sectors"]:
        requirement = "必需" if sector["required"] else "可选"
        auth_state = "通过" if sector["auth_passed"] else "失败"
        data_state = "通过" if sector["data_passed"] else "失败"
        print(
            f"扇区 {sector['sector']:02d} [{requirement}] "
            f"策略={sector['auth_policy']} 认证={auth_state} "
            f"数据检验={data_state} "
            f"耗时={sector['duration_ms']:.3f} ms"
        )
        for key_type, authentication in sector["authentication"].items():
            attempts = authentication["attempts"]
            last_status = (
                attempts[-1]["authenticate"].get("status")
                if attempts
                else None
            )
            status = last_status or "----"
            matched = authentication["matched_candidate"]
            matched_text = f" 候选#{matched}" if matched is not None else ""
            print(
                f"  Key {key_type}: "
                f"{'成功' if authentication['ok'] else '失败'}"
                f"{matched_text} SW={status}"
            )
        for block in sector["blocks"]:
            if block["read_ok"]:
                if block["data_match"]:
                    verification = (
                        f"匹配候选#{block['matched_data_candidate']}"
                    )
                else:
                    verification = "数据不匹配"
                print(
                    f"  block {block['block']}: {block['data_hex']} "
                    f"(Key {block['used_key']}，{verification})"
                )
            else:
                print(f"  block {block['block']}: <读取失败>")

    decision = result["decision"]
    state = "允许开门" if decision["authorized"] else "拒绝开门"
    print(f"结果: {state} - {decision['reason']}")
    apdu_count = result.get("apdu_count")
    apdu_text = f"，APDU={apdu_count}" if apdu_count is not None else ""
    print(f"耗时: {result['duration_ms']:.3f} ms{apdu_text}")


def append_jsonl(path: Path, result: dict[str, Any]) -> None:
    """将一次刷卡结果原子化为单行 JSON 并追加到 JSONL 文件。"""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        json.dump(result, handle, ensure_ascii=False, separators=(",", ":"))
        handle.write("\n")


def _load_pcsc() -> tuple[
    Any,
    tuple[type[BaseException], ...],
    Any,
    Any,
    int,
]:
    """延迟加载 pyscard，让配置校验和测试无需安装硬件依赖。"""

    try:
        from smartcard.Exceptions import (  # type: ignore[import-not-found]
            CardConnectionException,
            NoCardException,
        )
        from smartcard.CardMonitoring import (  # type: ignore[import-not-found]
            CardMonitor,
            CardObserver,
        )
        from smartcard.System import readers  # type: ignore[import-not-found]
        from smartcard.scard import SCARD_UNPOWER_CARD  # type: ignore[import-not-found]
    except ImportError as exc:
        raise PcscUnavailableError(
            "未安装 pyscard。请执行：python -m pip install -r requirements.txt"
        ) from exc
    return (
        readers,
        (CardConnectionException, NoCardException),
        CardMonitor,
        CardObserver,
        SCARD_UNPOWER_CARD,
    )


def list_reader_names() -> list[str]:
    readers_function, _, _, _, _ = _load_pcsc()
    return [str(reader) for reader in readers_function()]


def _select_reader(config: AppConfig) -> Any:
    readers_function, _, _, _, _ = _load_pcsc()
    available = list(readers_function())
    matches = [
        reader
        for reader in available
        if config.reader_name_contains.lower() in str(reader).lower()
    ]
    if not matches:
        names = ", ".join(str(reader) for reader in available) or "<无>"
        raise PcscUnavailableError(
            f"找不到名称包含 {config.reader_name_contains!r} 的读卡器。当前读卡器：{names}"
        )
    if len(matches) > 1:
        names = ", ".join(str(reader) for reader in matches)
        raise PcscUnavailableError(
            f"匹配到多个读卡器：{names}。请把 reader.name_contains 配置得更精确。"
        )
    return matches[0]


def _close_connection(connection: Any) -> None:
    """断开卡片并释放 PC/SC 上下文；每条退出路径都必须调用。"""

    try:
        connection.disconnect()
    except Exception:
        pass
    try:
        connection.release()
    except Exception:
        pass


class _AntennaDirectSession:
    """保持无卡 Direct handle，防止驱动在待机时重新开启射频轮询。"""

    def __init__(self, reader: Any, pcsc_api: Any | None = None):
        if pcsc_api is None:
            try:
                import smartcard.scard as pcsc_api  # type: ignore[import-not-found]
            except ImportError as exc:
                raise PcscUnavailableError(
                    "未安装 pyscard。请执行：python -m pip install -r requirements.txt"
                ) from exc

        self.reader = reader
        self.pcsc_api = pcsc_api
        self.context: Any | None = None
        self.card_handle: Any | None = None
        self.closed = False
        self.original_picc_parameter: int | None = None
        self.picc_parameter_changed = False
        self._open()

    def _require_success(self, result_code: int, operation: str) -> None:
        if result_code == self.pcsc_api.SCARD_S_SUCCESS:
            return
        try:
            detail = self.pcsc_api.SCardGetErrorMessage(result_code)
        except Exception:
            detail = "未知 WinSCard 错误"
        unsigned_code = result_code & 0xFFFFFFFF
        raise PcscUnavailableError(
            f"ACR122T Direct 控制失败：{operation}："
            f"{detail} (0x{unsigned_code:08X})"
        )

    def _open(self) -> None:
        try:
            result, self.context = self.pcsc_api.SCardEstablishContext(
                self.pcsc_api.SCARD_SCOPE_USER
            )
            self._require_success(result, "SCardEstablishContext")

            # Direct 模式必须使用协议 0，场内没有卡时仍可占用并控制读卡器。
            result, self.card_handle, _ = self.pcsc_api.SCardConnect(
                self.context,
                str(self.reader),
                self.pcsc_api.SCARD_SHARE_DIRECT,
                getattr(self.pcsc_api, "SCARD_PROTOCOL_UNDEFINED", 0),
            )
            self._require_success(result, "SCardConnect(SCARD_SHARE_DIRECT)")
        except Exception:
            self.close()
            raise

    def _send_control(self, command: list[int], operation: str) -> tuple[int, ...]:
        if self.closed or self.card_handle is None:
            raise PcscUnavailableError("ACR122T Direct handle 已关闭")

        try:
            control_code = self.pcsc_api.SCARD_CTL_CODE(3500)
            result, response_data = self.pcsc_api.SCardControl(
                self.card_handle,
                control_code,
                command,
            )
            self._require_success(result, f"SCardControl({operation})")
        except PcscUnavailableError:
            raise
        except Exception as exc:
            raise PcscUnavailableError(
                f"ACR122T {operation}失败：{type(exc).__name__}: {exc}"
            ) from exc
        return tuple(response_data)

    def get_picc_operating_parameter(self) -> int:
        response = self._send_control(
            [0xFF, 0x00, 0x50, 0x00, 0x00],
            "读取 PICC Operating Parameter",
        )
        # ACR122T 实机响应为 90h + 当前参数，例如 90 FF。
        if len(response) != 2 or response[0] != 0x90:
            response_hex = _hex(response) or "<空响应>"
            raise PcscUnavailableError(
                "无法读取 ACR122T PICC Operating Parameter："
                f"读卡器返回 {response_hex}"
            )
        return response[1]

    def set_picc_operating_parameter(self, parameter: int) -> None:
        response = self._send_control(
            [0xFF, 0x00, 0x51, parameter, 0x00],
            "设置 PICC Operating Parameter",
        )
        if response != (0x90, parameter):
            response_hex = _hex(response) or "<空响应>"
            raise PcscUnavailableError(
                "无法设置 ACR122T PICC Operating Parameter："
                f"读卡器返回 {response_hex}"
            )

    def set_power(self, enabled: bool) -> None:
        command = ANTENNA_POWER_ON if enabled else ANTENNA_POWER_OFF
        action = "开启" if enabled else "关闭"
        response = self._send_control(command, f"{action}射频")

        # ACR122T 实机成功响应为 D5 33 90 00。尾部 63 00 表示操作失败。
        if (
            len(response) < 4
            or response[:2] != (0xD5, 0x33)
            or response[-2:] != (0x90, 0x00)
        ):
            response_hex = _hex(response) or "<空响应>"
            raise PcscUnavailableError(
                f"无法{action} ACR122T 射频场：读卡器返回 {response_hex}"
            )

    def enter_standby(self) -> None:
        """关闭固件自动轮询和射频，并保留恢复所需的原始参数。"""

        if self.original_picc_parameter is None:
            self.original_picc_parameter = self.get_picc_operating_parameter()
        standby_parameter = self.original_picc_parameter & 0x7F
        self.set_picc_operating_parameter(standby_parameter)
        self.picc_parameter_changed = True
        self.set_power(False)

    def wake(self) -> None:
        """恢复进入待机前的轮询参数；自动轮询会自行开启射频。"""

        if self.original_picc_parameter is None:
            raise PcscUnavailableError("缺少待机前的 PICC Operating Parameter")
        self.set_picc_operating_parameter(self.original_picc_parameter)
        self.picc_parameter_changed = False

    def close(self) -> None:
        if self.closed:
            return
        if (
            self.picc_parameter_changed
            and self.card_handle is not None
            and self.original_picc_parameter is not None
        ):
            try:
                self.set_picc_operating_parameter(self.original_picc_parameter)
            except PcscUnavailableError:
                pass
            self.picc_parameter_changed = False
        self.closed = True
        if self.card_handle is not None:
            try:
                self.pcsc_api.SCardDisconnect(
                    self.card_handle,
                    self.pcsc_api.SCARD_LEAVE_CARD,
                )
            except Exception:
                pass
            self.card_handle = None
        if self.context is not None:
            try:
                self.pcsc_api.SCardReleaseContext(self.context)
            except Exception:
                pass
            self.context = None


def _enter_antenna_standby(
    reader: Any,
    *,
    pcsc_api: Any | None = None,
) -> _AntennaDirectSession:
    """关闭射频并保持 Direct handle，直到下一次主动读卡。"""

    session = _AntennaDirectSession(reader, pcsc_api=pcsc_api)
    try:
        session.enter_standby()
        return session
    except Exception:
        session.close()
        raise


def _set_antenna_power(
    reader: Any,
    enabled: bool,
    *,
    pcsc_api: Any | None = None,
) -> None:
    """一次性开关射频；持续待机应使用 _enter_antenna_standby。"""

    session = _AntennaDirectSession(reader, pcsc_api=pcsc_api)
    try:
        session.set_power(enabled)
    finally:
        session.close()


def _wait_for_space(read_key: Callable[[], str] | None = None) -> bool:
    """等待无需回车的空格键；Q 或 Esc 表示退出。"""

    if read_key is None:
        try:
            import msvcrt
        except ImportError as exc:
            raise PcscUnavailableError("空格触发模式仅支持 Windows 控制台") from exc
        read_key = msvcrt.getwch

    while True:
        key = read_key()
        if key == " ":
            return True
        if key in {"q", "Q", "\x1b"}:
            return False
        if key in {"\x00", "\xe0"}:
            read_key()  # 丢弃方向键、功能键等扩展键的第二个字符。


def _try_connect(
    card_or_reader: Any,
    connection_errors: tuple[type[BaseException], ...],
    disconnect_disposition: int,
) -> Any | None:
    connection = None
    try:
        connection = card_or_reader.createConnection()
        # disconnect() 会采用此 disposition，使本次处理后射频状态被冷复位。
        connection.connect(disposition=disconnect_disposition)
        return connection
    except connection_errors:
        if connection is not None:
            _close_connection(connection)
        return None


def run_loop(config: AppConfig, json_log: Path | None, once: bool) -> None:
    """待机持有 Direct handle 并关闭射频；按空格后处理一张卡。"""

    reader = _select_reader(config)
    (
        _,
        connection_errors,
        _,
        _,
        unpower_card,
    ) = _load_pcsc()
    target_reader_name = str(reader)
    standby_session = _enter_antenna_standby(reader)
    print(f"使用读卡器: {reader}")
    print("射频已关闭并保持 Direct 占用。按空格键开始一次读卡，按 Q 或 Esc 退出。")

    try:
        while True:
            if not _wait_for_space():
                return

            standby_session.wake()
            standby_session.close()
            standby_session = None
            print("射频已开启，请放置卡片……")

            connection = None
            try:
                while connection is None:
                    connection = _try_connect(
                        reader,
                        connection_errors,
                        unpower_card,
                    )
                    if connection is None:
                        time.sleep(config.poll_interval_seconds)

                device = Acr122tDevice(connection)
                try:
                    atr = connection.getATR()
                except Exception:
                    atr = []
                result = scan_card(device, config, target_reader_name, atr)
                print_result(result)
                if json_log is not None:
                    append_jsonl(json_log, result)
                    print(f"JSONL 已追加: {json_log.resolve()}")
            finally:
                if connection is not None:
                    _close_connection(connection)

            standby_session = _enter_antenna_standby(reader)
            print("射频已关闭并保持 Direct 占用。")

            if once:
                return
            print("按空格键开始下一次读卡，按 Q 或 Esc 退出。")
    finally:
        if standby_session is None:
            try:
                emergency_session = _enter_antenna_standby(reader)
            except PcscUnavailableError as exc:
                print(f"警告: {exc}", file=sys.stderr)
            else:
                emergency_session.close()
        else:
            standby_session.close()


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="使用 ACR122T 模拟 MIFARE Classic 1K 门锁认证与读取流程"
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config.json"),
        help="JSON 配置路径（默认：config.json）",
    )
    parser.add_argument(
        "--json-log",
        type=Path,
        help="可选 JSONL 日志路径；每次刷卡追加一行",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="只处理一张卡后退出",
    )
    parser.add_argument(
        "--list-readers",
        action="store_true",
        help="列出 PC/SC 读卡器后退出（无需配置文件）",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_argument_parser().parse_args(argv)
    try:
        if args.list_readers:
            names = list_reader_names()
            if not names:
                print("未发现 PC/SC 读卡器。")
                return 1
            for index, name in enumerate(names):
                print(f"[{index}] {name}")
            return 0

        config = load_config(args.config)
        run_loop(config, args.json_log, args.once)
        return 0
    except (ConfigurationError, PcscUnavailableError) as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n已停止。")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
