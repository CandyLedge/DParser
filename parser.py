import json
import struct
import logging
from pathlib import Path
from enum import Enum, auto
from typing import Dict, Any, Optional


# 配置日志记录
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DataType(Enum):
    SINT = auto()
    UINT = auto()
    FLOAT = auto()
    HEX = auto()

class ProtocolParser:
    def __init__(self, rules_dir: Optional[Path] = None):
        self.rules_dir = rules_dir or Path(__file__).parent / "rules"
        self.protocol_rules: Dict[str, dict] = {}  # 按规则名存储规则
        self.load_rules()

    def load_rules(self):
        """加载规则文件并生成映射"""
        self.protocol_rules.clear()
        if not self.rules_dir.exists():
            logging.warning(f"规则目录 {self.rules_dir} 不存在")
            return

        for file in self.rules_dir.glob("*.json"):
            try:
                self._load_rule_file(file)
            except Exception as e:
                logging.error(f"加载文件 {file.name} 失败: {str(e)}")

        logging.info(f"规则加载完成，当前加载的规则: {list(self.protocol_rules.keys())}")

    def _load_rule_file(self, file: Path):
        """加载并验证单个规则文件"""
        with open(file, "r", encoding="utf-8") as f:
            rule = json.load(f)
            required_fields = {"protocol_name", "total_bytes", "data_segments"}
            missing_fields = required_fields - set(rule.keys())

            if missing_fields:
                logging.warning(f"规则文件 {file.name} 缺少字段: {missing_fields}")
                return

            # 保存规则到 protocol_rules 中，键是规则名
            self.protocol_rules[rule["protocol_name"]] = rule
            logging.info(f"规则 {rule['protocol_name']} 加载成功")

    def parse(self, rule_name: str, payload: bytes) -> Dict[str, Any]:
        """根据规则名解析数据"""
        rule = self.protocol_rules.get(rule_name)
        if not rule:
            raise ValueError(f"未找到名为 '{rule_name}' 的规则")

        if len(payload) != rule["total_bytes"]:
            raise ValueError(f"数据长度不匹配，期望 {rule['total_bytes']} 字节，实际 {len(payload)} 字节")

        return self._parse_payload(payload, rule)

    def _parse_payload(self, payload: bytes, rule: dict) -> Dict[str, Any]:
        """解析数据体"""
        result = {}
        total_bits = rule["total_bytes"] * 8

        for segment in rule["data_segments"]:
            name = segment["name"]
            start_bit = segment["start_bit"]
            end_bit = segment["end_bit"]
            data_type = segment["data_type"]
            bit_length = end_bit - start_bit + 1

            if not (0 <= start_bit <= end_bit < total_bits):
                raise ValueError(f"字段 '{name}' 位范围超限 (0-{total_bits - 1}位)")

            first_byte = start_bit // 8
            last_byte = end_bit // 8
            bytes_to_read = payload[first_byte:last_byte + 1]
            value = int.from_bytes(bytes_to_read, byteorder="big", signed=False)
            shift = 8 * (last_byte - first_byte + 1) - (end_bit % 8 + 1)
            raw_value = (value >> shift) & ((1 << bit_length) - 1)

            result[name] = self._convert_data_type(raw_value, data_type, bit_length)

        return result

    def _convert_data_type(self, value: int, data_type: DataType, bit_length: int) -> Any:
        """根据数据类型进行转换"""
        if data_type == DataType.SINT and value & (1 << (bit_length - 1)):
            return value - (1 << bit_length)
        if data_type == DataType.FLOAT:
            return struct.unpack(">f", value.to_bytes(4, "big"))[0]
        if data_type == DataType.HEX:
            return value.to_bytes((value.bit_length() + 7) // 8, "big").hex().upper()
        return value