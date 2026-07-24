#!/usr/bin/env python3
"""使用 ACR122T/PCSC 模拟 MIFARE Classic 1K 门锁读卡流程。

程序只执行读取操作，不会向卡片写入数据。MIFARE Classic 的 Crypto1
三次认证由 ACR122T 与卡片完成；PC/SC 接口只返回认证结果。
"""

from __future__ import annotations

import argparse
import json
import queue
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol, Sequence


SUCCESS_STATUS = (0x90, 0x00)
KEY_TYPE_CODE = {"A": 0x60, "B": 0x61}
KEY_SLOT = {"A": 0x00, "B": 0x01}


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
    key_a: bytes | None
    key_b: bytes | None

    @property
    def required_key_types(self) -> tuple[str, ...]:
        if self.auth == "both":
            return ("A", "B")
        return (self.auth.upper(),)

    def key_for(self, key_type: str) -> bytes:
        key = self.key_a if key_type == "A" else self.key_b
        if key is None:  # 配置加载时已经校验；这里用于类型收窄和防御。
            raise ConfigurationError(
                f"扇区 {self.sector} 缺少 Key {key_type}"
            )
        return key


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

    def _transmit(self, apdu: list[int]) -> ApduResult:
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


def _parse_key(value: Any, field_name: str) -> bytes | None:
    """把配置中的 12 位十六进制密钥转换为 6 字节。"""

    if value is None:
        return None
    if not isinstance(value, str):
        raise ConfigurationError(f"{field_name} 必须是字符串或 null")

    normalized = value.replace(" ", "").replace(":", "").replace("-", "")
    if len(normalized) != 12:
        raise ConfigurationError(f"{field_name} 必须恰好包含 6 字节（12 个十六进制字符）")
    try:
        return bytes.fromhex(normalized)
    except ValueError as exc:
        raise ConfigurationError(f"{field_name} 含有非十六进制字符") from exc


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

        key_a = _parse_key(item.get("key_a"), f"{prefix}.key_a")
        key_b = _parse_key(item.get("key_b"), f"{prefix}.key_b")
        if auth in {"a", "both"} and key_a is None:
            raise ConfigurationError(f"{prefix} 的认证策略需要 key_a")
        if auth in {"b", "both"} and key_b is None:
            raise ConfigurationError(f"{prefix} 的认证策略需要 key_b")

        sectors.append(SectorConfig(sector, required, auth, key_a, key_b))

    if not any(sector.required for sector in sectors):
        raise ConfigurationError("至少要把一个扇区设置为 required=true")

    return AppConfig(
        reader_name_contains=name_contains,
        poll_interval_seconds=poll_ms / 1000.0,
        sectors=tuple(sorted(sectors, key=lambda item: item.sector)),
    )


def _hex(data: Sequence[int]) -> str:
    return "".join(f"{value:02X}" for value in data)


def _authenticate_key(
    device: Acr122tDevice,
    sector: SectorConfig,
    block: int,
    key_type: str,
) -> dict[str, Any]:
    """加载一把密钥并完成一次原生 Crypto1 认证。"""

    loaded = device.load_key(key_type, sector.key_for(key_type))
    if not loaded.ok:
        return {
            "ok": False,
            "load_key": loaded.summary(),
            "authenticate": {"ok": False, "status": None, "skipped": True},
        }

    authenticated = device.authenticate(block, key_type)
    return {
        "ok": authenticated.ok,
        "load_key": loaded.summary(),
        "authenticate": authenticated.summary(),
    }


def _read_one_block(
    device: Acr122tDevice,
    sector: SectorConfig,
    block: int,
    usable_keys: Sequence[str],
) -> dict[str, Any]:
    """依次用已通过扇区验证的密钥尝试认证和读取一个块。"""

    attempts: list[dict[str, Any]] = []
    for key_type in usable_keys:
        # 每个块重新认证，确保上一次 Key A/Key B 验证不会污染当前读取状态。
        authentication = _authenticate_key(device, sector, block, key_type)
        attempt: dict[str, Any] = {
            "key_type": key_type,
            "authentication": authentication,
        }
        if not authentication["ok"]:
            attempt["read"] = {"ok": False, "status": None, "skipped": True}
            attempts.append(attempt)
            continue

        read_result = device.read_block(block)
        read_summary = read_result.summary()
        read_summary["data_length"] = len(read_result.data)
        read_success = read_result.ok and len(read_result.data) == 16
        if read_result.ok and not read_success:
            read_summary["ok"] = False
            read_summary["error"] = "返回数据不是 16 字节"
        attempt["read"] = read_summary
        attempts.append(attempt)
        if read_success:
            return {
                "block": block,
                "is_sector_trailer": block % 4 == 3,
                "read_ok": True,
                "data_hex": _hex(read_result.data),
                "used_key": key_type,
                "attempts": attempts,
            }

    return {
        "block": block,
        "is_sector_trailer": block % 4 == 3,
        "read_ok": False,
        "data_hex": None,
        "used_key": None,
        "attempts": attempts,
    }


def scan_card(
    device: Acr122tDevice,
    config: AppConfig,
    reader_name: str,
    atr: Sequence[int],
) -> dict[str, Any]:
    """认证并读取当前卡片，返回不包含密钥的结构化采集结果。"""

    started = time.perf_counter()
    result: dict[str, Any] = {
        "schema_version": 1,
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
    for sector in config.sectors:
        first_block = sector.sector * 4
        authentication: dict[str, Any] = {}
        usable_keys: list[str] = []

        for key_type in sector.required_key_types:
            auth_result = _authenticate_key(device, sector, first_block, key_type)
            authentication[key_type] = auth_result
            if auth_result["ok"]:
                usable_keys.append(key_type)

        auth_passed = all(
            authentication[key_type]["ok"] for key_type in sector.required_key_types
        )
        blocks = [
            _read_one_block(device, sector, block, usable_keys)
            for block in range(first_block, first_block + 4)
        ]
        sector_result = {
            "sector": sector.sector,
            "required": sector.required,
            "auth_policy": sector.auth,
            "authentication": authentication,
            "auth_passed": auth_passed,
            "read_complete": all(block["read_ok"] for block in blocks),
            "blocks": blocks,
        }
        result["sectors"].append(sector_result)
        if sector.required and not auth_passed:
            failed_required.append(sector.sector)

    authorized = uid_ok and not failed_required
    if not uid_ok:
        reason = "无法读取卡片 UID"
    elif failed_required:
        reason = "必需扇区认证失败"
    else:
        reason = "所有必需扇区均通过认证"

    result["decision"] = {
        "authorized": authorized,
        "reason": reason,
        "required_sectors": [item.sector for item in config.sectors if item.required],
        "failed_required_sectors": failed_required,
        "read_failures_do_not_change_decision": True,
    }
    result["duration_ms"] = round((time.perf_counter() - started) * 1000, 3)
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
        print(
            f"扇区 {sector['sector']:02d} [{requirement}] "
            f"策略={sector['auth_policy']} 认证={auth_state}"
        )
        for key_type, authentication in sector["authentication"].items():
            status = authentication["authenticate"].get("status") or "----"
            print(f"  Key {key_type}: {'成功' if authentication['ok'] else '失败'} SW={status}")
        for block in sector["blocks"]:
            trailer = " 尾块" if block["is_sector_trailer"] else ""
            if block["read_ok"]:
                print(
                    f"  块 {block['block']:02d}{trailer}: {block['data_hex']} "
                    f"(Key {block['used_key']})"
                )
            else:
                print(f"  块 {block['block']:02d}{trailer}: <读取失败>")

    decision = result["decision"]
    state = "允许开门" if decision["authorized"] else "拒绝开门"
    print(f"结果: {state} - {decision['reason']}")
    print(f"耗时: {result['duration_ms']:.3f} ms")


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
    """通过 CardMonitor 事件持续等待卡片，每次处理后立即释放连接。"""

    reader = _select_reader(config)
    (
        _,
        connection_errors,
        card_monitor_class,
        card_observer_class,
        unpower_card,
    ) = _load_pcsc()
    target_reader_name = str(reader)
    events: queue.Queue[tuple[str, Any]] = queue.Queue()

    class QueueingCardObserver(card_observer_class):
        """CardMonitor 回调只入队，实际 APDU 始终在主线程执行。"""

        def update(self, observable: Any, actions: tuple[list[Any], list[Any]]) -> None:
            added_cards, removed_cards = actions
            for card in added_cards:
                events.put(("added", card))
            for card in removed_cards:
                events.put(("removed", card))

    monitor = card_monitor_class()
    observer = QueueingCardObserver()
    monitor.addObserver(observer)
    print(f"使用读卡器: {reader}")
    print("请刷 MIFARE Classic 1K 卡。按 Ctrl+C 退出。")

    try:
        while True:
            try:
                event_type, card = events.get(timeout=config.poll_interval_seconds)
            except queue.Empty:
                continue

            if str(card.reader) != target_reader_name:
                continue
            if event_type == "removed":
                print("卡片已移开，等待下一张卡……")
                continue

            connection = _try_connect(card, connection_errors, unpower_card)
            if connection is None:
                print("检测到卡片，但连接失败；等待重新刷卡。", file=sys.stderr)
                continue

            try:
                device = Acr122tDevice(connection)
                try:
                    atr = connection.getATR()
                except Exception:
                    atr = getattr(card, "atr", [])
                result = scan_card(device, config, target_reader_name, atr)
                print_result(result)
                if json_log is not None:
                    append_jsonl(json_log, result)
                    print(f"JSONL 已追加: {json_log.resolve()}")
            finally:
                # 认证结束后不再用 GET UID 占用连接；立即断开并释放读卡器。
                _close_connection(connection)

            if once:
                return
    finally:
        monitor.deleteObserver(observer)
        stop_monitor = getattr(monitor, "stop", None)
        if callable(stop_monitor):
            stop_monitor()


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
