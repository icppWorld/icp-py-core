import unittest
import sys
import os
import json
from unittest.mock import patch, MagicMock

# Add src directory to path
project_root = os.path.join(os.path.dirname(__file__), '..')
src_path = os.path.join(project_root, 'src')
sys.path.insert(0, src_path)

# 导入待测模块
from icp_candid.did_loader import DIDLoader
from icp_candid.candid import Types, RecordClass, RecClass, FuncClass


class TestDIDLoader(unittest.TestCase):

    def setUp(self):
        self.loader = DIDLoader()

    @patch('icp_candid.did_loader.ic_candid_parser')
    def test_primitive_parsing(self, mock_parser):
        """测试基础类型的加载"""
        # [Actual Format] Use actual Rust parser format: {"type": "Prim", "value": "text"}
        mock_json = json.dumps({
            "env": [],
            "actor": {
                "methods": [{
                    "name": "greet",
                    "args": [{"type": "Prim", "value": "text"}],
                    "rets": [{"type": "Prim", "value": "bool"}],
                    "modes": ["query"]
                }]
            }
        })
        mock_parser.parse_did.return_value = mock_json

        result = self.loader.load_did_source("service : { ... }")

        methods = result["methods"]
        self.assertIn("greet", methods)

        func = methods["greet"]
        # did_loader 返回的是 Types.Func，即 FuncClass 实例
        self.assertIsInstance(func, FuncClass)
        self.assertEqual(len(func.args), 1)
        self.assertEqual(len(func.rets), 1)
        self.assertEqual(func.modes, ["query"])

    @patch('icp_candid.did_loader.ic_candid_parser')
    def test_record_parsing(self, mock_parser):
        """测试 Record 类型及字段转换"""
        # [Actual Format] Use actual Rust parser format
        mock_json = json.dumps({
            "env": [
                {
                    "name": "User",
                    "datatype": {
                        "type": "Record",
                        "value": [
                            ["name", {"type": "Prim", "value": "text"}],
                            ["age", {"type": "Prim", "value": "nat8"}]
                        ]
                    }
                }
            ],
            "actor": None
        })
        mock_parser.parse_did.return_value = mock_json

        self.loader.load_did_source("...")

        user_type = self.loader.type_env["User"]
        self.assertIsInstance(user_type, RecClass)

        # 解包 RecClass 检查内部 Record
        record = user_type.get_type()
        self.assertIsInstance(record, RecordClass)

        # 验证字段是否存在（需要通过哈希查找或内部 map 验证）
        # 由于 RecordClass 内部 key 是哈希后的，我们通过 encodeValue 侧面验证
        test_val = {"name": "Alice", "age": 20}
        try:
            record.encodeValue(test_val)
        except Exception as e:
            self.fail(f"Failed to encode record based on DID definition: {e}")

    @patch('icp_candid.did_loader.ic_candid_parser')
    def test_recursive_type(self, mock_parser):
        """测试递归类型的构建 (List)"""
        # [Actual Format] Use actual Rust parser format
        mock_json = json.dumps({
            "env": [
                {
                    "name": "List",
                    "datatype": {
                        "type": "Record",
                        "value": [
                            ["head", {"type": "Prim", "value": "int"}],
                            ["tail", {"type": "Opt", "value": {"type": "Id", "value": "List"}}]
                        ]
                    }
                }
            ],
            "actor": None
        })
        mock_parser.parse_did.return_value = mock_json

        self.loader.load_did_source("...")

        list_type = self.loader.type_env["List"]
        self.assertIsInstance(list_type, RecClass)

        # 验证递归引用
        # List -> Record -> Opt -> Id(List)
        record = list_type.get_type()
        # 找到 tail 字段
        # 注意：Record 内部字段是按 hash 存储的，这里简化验证逻辑
        # 只要能成功 covariant 校验递归数据结构，即说明构建成功

        recursive_data = {"head": 1, "tail": [{"head": 2, "tail": []}]}
        self.assertTrue(list_type.covariant(recursive_data))

    @patch('icp_candid.did_loader.ic_candid_parser')
    def test_tuple_handling(self, mock_parser):
        """测试 Tuple 识别逻辑 (数字键 Record)"""
        # [Actual Format] Use actual Rust parser format: {"type": "Record", "value": [["key", type], ...]}
        mock_json = json.dumps({
            "env": [
                {
                    "name": "Pair",
                    "datatype": {
                        "type": "Record",
                        "value": [
                            ["0", {"type": "Prim", "value": "nat"}],
                            ["1", {"type": "Prim", "value": "text"}]
                        ]
                    }
                }
            ],
            "actor": None
        })
        mock_parser.parse_did.return_value = mock_json

        self.loader.load_did_source("...")
        pair_type = self.loader.type_env["Pair"].get_type()

        # 验证是否识别为 Tuple
        self.assertTrue(pair_type.tryAsTuple())

        # 验证能否处理列表输入（通过 encodeValue，它支持列表输入）
        try:
            pair_type.encodeValue([10, "hello"])
        except Exception as e:
            self.fail(f"Failed to encode tuple from list: {e}")
        
        # 验证能否处理字典输入（使用数字键）
        self.assertTrue(pair_type.covariant({"0": 10, "1": "hello"}))


if __name__ == '__main__':
    unittest.main()
