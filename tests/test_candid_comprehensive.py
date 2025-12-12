import unittest
import sys
import os
import time
from binascii import hexlify

# Add src directory to path
project_root = os.path.join(os.path.dirname(__file__), '..')
src_path = os.path.join(project_root, 'src')
sys.path.insert(0, src_path)

from icp_candid.candid import encode, decode, Types, LEB128, Pipe


class TestLEB128(unittest.TestCase):
    """测试底层 LEB128 编码解码的正确性与鲁棒性"""

    def test_unsigned(self):
        cases = [
            (0, b"\x00"),
            (127, b"\x7f"),
            (128, b"\x80\x01"),
            (624485, b"\xe5\x8e\x26"),
            (2**64, b"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x02")  # 大数测试
        ]
        for val, expected in cases:
            self.assertEqual(LEB128.encode_u(val), expected)
            self.assertEqual(LEB128.decode_u(Pipe(expected)), val)

    def test_signed(self):
        cases = [
            (0, b"\x00"),
            (-1, b"\x7f"),
            (127, b"\xff\x00"),  # 需要 padding
            (-128, b"\x80\x7f"),
            (1, b"\x01"),
            (-123456, b"\xc0\xbb\x78")
        ]
        for val, expected in cases:
            self.assertEqual(LEB128.encode_i(val), expected)
            self.assertEqual(LEB128.decode_i(Pipe(expected)), val)

    def test_float_safety(self):
        """确保传入浮点数不会导致死循环"""
        # 应该被强转为 int
        self.assertEqual(LEB128.encode_u(12.5), b"\x0c")


class TestPrimitives(unittest.TestCase):
    """测试基础类型的编解码"""

    def test_basic_roundtrip(self):
        params = [
            {'type': Types.Bool, 'value': True},
            {'type': Types.Nat, 'value': 100},
            {'type': Types.Int, 'value': -100},
            {'type': Types.Text, 'value': "Hello 🚀"},  # UTF-8 check
            {'type': Types.Float64, 'value': 3.14159},
            {'type': Types.Principal, 'value': "aaaaa-aa"},  # Management
        ]

        encoded = encode(params)
        decoded = decode(encoded, [p['type'] for p in params])

        self.assertEqual(decoded[0]['value'], True)
        self.assertEqual(decoded[1]['value'], 100)
        self.assertEqual(decoded[2]['value'], -100)
        self.assertEqual(decoded[3]['value'], "Hello 🚀")
        self.assertAlmostEqual(decoded[4]['value'], 3.14159)
        self.assertEqual(decoded[5]['value'].bytes, b"")


class TestConstructedTypes(unittest.TestCase):
    """测试复杂构造类型"""

    def test_opt(self):
        # Opt Null
        enc = encode([{'type': Types.Opt(Types.Nat), 'value': []}])
        dec = decode(enc, [Types.Opt(Types.Nat)])
        self.assertEqual(dec[0]['value'], [])

        # Opt Value
        enc = encode([{'type': Types.Opt(Types.Nat), 'value': [10]}])
        dec = decode(enc, [Types.Opt(Types.Nat)])
        self.assertEqual(dec[0]['value'], [10])

    def test_record_hash_order(self):
        """验证 Record 字段是否按 Hash 排序"""
        # key "a" hash ~97, key "z" hash ~122
        # Wire order should be 'a' then 'z'
        t = Types.Record({'z': Types.Nat, 'a': Types.Nat})
        val = {'z': 1, 'a': 2}

        encoded = encode([{'type': t, 'value': val}])
        decoded = decode(encoded, [t])
        self.assertEqual(decoded[0]['value'], val)

    def test_variant(self):
        t = Types.Variant({'ok': Types.Text, 'err': Types.Nat})

        # Case Ok
        val_ok = {'ok': "Success"}
        dec_ok = decode(encode([{'type': t, 'value': val_ok}]), [t])
        self.assertEqual(dec_ok[0]['value'], val_ok)

        # Case Err
        val_err = {'err': 404}
        dec_err = decode(encode([{'type': t, 'value': val_err}]), [t])
        self.assertEqual(dec_err[0]['value'], val_err)


class TestPerformanceAndRegression(unittest.TestCase):
    """性能测试与 Bug 回归测试"""

    def test_blob_optimization(self):
        """性能: 验证 Vec Nat8 是否启用了内存直读直写"""
        # 1MB data
        data = b'\x01' * 1024 * 1024

        t0 = time.time()
        encoded = encode([{'type': Types.Vec(Types.Nat8), 'value': data}])
        t1 = time.time()

        print(f"\n[Perf] 1MB Blob Encode Time: {t1-t0:.5f}s")
        # 如果是纯循环处理，Python 通常需要 0.5s 以上
        self.assertLess(t1 - t0, 0.2, "Blob optimization seems inactive (too slow)")

        decoded = decode(encoded, [Types.Vec(Types.Nat8)])
        self.assertEqual(decoded[0]['value'], data)

    def test_vec_int8_crash_fix(self):
        """回归: 验证 Vec Int8 包含负数时是否会崩溃"""
        # Bug: bytes([-1]) throws ValueError.
        # Fix: Should use list comprehension for Int8.
        data = [-128, -1, 0, 1, 127]
        t = Types.Vec(Types.Int8)

        try:
            encoded = encode([{'type': t, 'value': data}])
            decoded = decode(encoded, [t])
            self.assertEqual(decoded[0]['value'], data)
        except ValueError as e:
            self.fail(f"Vec Int8 crashed on negative numbers: {e}")

    def test_service_double_tag_fix(self):
        """回归: 验证 Service 编码没有重复的 0x01 Tag"""
        # Service 应该直接代理 Principal 编码
        # Value: Empty principal (management) -> 0x01 (Tag) + 0x00 (Len)
        # 如果由 Service 再加一个 Tag，就会变成 0x01 0x01 0x00 (错误)

        encoded = encode([{'type': Types.Service({}), 'value': "aaaaa-aa"}])

        # DIDL (4) + TypeTable (1:0) + ArgLen (1:1) + TypeIndex (1) + VALUE
        # 取最后几个字节观察
        payload = encoded[-2:]
        self.assertEqual(payload, b"\x01\x00", f"Service has wrong bytes: {hexlify(encoded)}")


class TestRecursion(unittest.TestCase):
    """测试递归类型 (链表/树)"""

    def test_linked_list(self):
        # type Node = record { val: nat; next: opt Node }
        Node = Types.Rec()
        Node.fill(Types.Record({
            'val': Types.Nat,
            'next': Types.Opt(Node)
        }))

        # 1 -> 2 -> None
        data = {'val': 1, 'next': [{'val': 2, 'next': []}]}

        # 如果 TypeTable 索引逻辑有错，这里编码或解码会报错
        try:
            encoded = encode([{'type': Node, 'value': data}])
            decoded = decode(encoded, [Node])
        except IndexError:
            self.fail("Recursive encoding failed (Index out of bounds)")

        self.assertEqual(decoded[0]['value']['val'], 1)
        self.assertEqual(decoded[0]['value']['next'][0]['val'], 2)


if __name__ == '__main__':
    unittest.main()
