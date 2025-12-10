import re
from antlr4 import InputStream, CommonTokenStream
from antlr4.error.ErrorListener import ErrorListener

# 根据你的目录结构导入
from icp_candid.parser.DIDLexer import DIDLexer
from icp_candid.parser.DIDParser import DIDParser
from icp_candid.parser.DIDEmitter import DIDEmitter
from icp_candid import encode, decode, Types

class ThrowingErrorListener(ErrorListener):
    """
    自定义错误监听器，用于捕获 ANTLR 的语法错误并抛出 Python 异常，
    以便我们在 Canister 类中捕获并进行自动修复。
    """
    def syntaxError(self, recognizer, offendingSymbol, line, column, msg, e):
        raise ValueError(f"Line {line}:{column} - {msg}")

class Canister:
    def __init__(self, agent, canister_id, candid_str=None):
        self.agent = agent
        self.canister_id = canister_id
        self.candid_str = candid_str
        self.methods = {}
        self.actor = None
        
        if candid_str:
            self._parse_did_with_retry(candid_str)

    def _parse_did_with_retry(self, did_content):
        """
        尝试解析 DID 内容。如果遇到常见的逗号分隔符错误，则自动修复并重试。
        """
        try:
            # 第一次尝试：直接解析原始字符串
            self._parse_did(did_content)
        except ValueError as e:
            err_msg = str(e)
            # 检查是否是针对逗号的解析错误 ("mismatched input ','")
            if "mismatched input" in err_msg and "," in err_msg:
                # --- 修复逻辑 ---
                print(f"[Canister] Parsing failed on commas. Applying inline fix...")
                # 将函数参数列表中的逗号替换为分号，以适配 Parser 的缺陷
                fixed_content = self._sanitize_commas(did_content)
                try:
                    self._parse_did(fixed_content)
                    print("[Canister] Fixed and parsed successfully.")
                except Exception as e2:
                    # 如果修复后仍然失败，抛出原始错误
                    raise ValueError(f"Failed to parse Candid even after fix: {e2}")
            else:
                # 其他类型的语法错误直接抛出
                raise e

    def _sanitize_commas(self, content):
        """
        [关键修复]
        将 Candid 字符串中位于圆括号 () 内的逗号替换为分号。
        逻辑：Candid Parser 错误地期待分号作为参数分隔符，而标准是逗号。
        注意：这不会影响字符串字面量内部的内容。
        """
        chars = list(content)
        depth = 0
        in_string = False
        
        for i, char in enumerate(chars):
            # 处理字符串字面量，防止修改字符串内的逗号
            if char == '"':
                in_string = not in_string
            elif not in_string:
                # 追踪圆括号深度
                if char == '(':
                    depth += 1
                elif char == ')':
                    depth -= 1
                elif char == ',' and depth > 0:
                    # 如果在圆括号内遇到逗号，将其替换为分号
                    # 这将把 (text, text) 转换为 Parser 喜欢的 (text; text)
                    chars[i] = ';'
        
        return "".join(chars)

    def _parse_did(self, did):
        input_stream = InputStream(did)
        lexer = DIDLexer(input_stream)
        stream = CommonTokenStream(lexer)
        parser = DIDParser(stream)
        
        # 移除默认的 Console 输出，改用异常机制
        parser.removeErrorListeners()
        parser.addErrorListener(ThrowingErrorListener())

        # 解析入口
        tree = parser.program()

        # 生成 Actor
        emitter = DIDEmitter()
        
        # 使用 ParseTreeWalker 遍历
        from antlr4.tree.Tree import ParseTreeWalker
        walker = ParseTreeWalker()
        walker.walk(emitter, tree)

        # 获取生成的 actor 定义
        # 注意：这里兼容常见的 DIDEmitter 实现方法名
        if hasattr(emitter, 'getActor'):
            self.actor = emitter.getActor()
        elif hasattr(emitter, 'get_actor'):
            self.actor = emitter.get_actor()
        else:
            # 某些实现可能直接将结果存储在 emitter.actor 中
            self.actor = getattr(emitter, 'actor', {})

        # 动态绑定方法到 Canister 实例
        for name, method_type in self.actor.items():
            self.methods[name] = method_type
            setattr(self, name, self._create_method(name, method_type))

    def _create_method(self, name, method_type):
        def method(*args, **kwargs):
            # 1. 获取参数类型和返回类型
            arg_types = method_type.get('args', [])
            ret_types = method_type.get('rets', [])
            
            # 2. 构造符合 encode 要求的参数列表
            processed_args = []
            for i, val in enumerate(args):
                if i < len(arg_types):
                    processed_args.append({'type': arg_types[i], 'value': val})
            
            # 3. 序列化参数
            encoded_args = encode(processed_args)

            # 4. 判断是 Query 还是 Update 调用
            annotations = method_type.get('modes', []) # 或者 'annotations'
            is_query = 'query' in annotations

            # 5. 执行网络请求
            if is_query:
                res = self.agent.query_raw(self.canister_id, name, encoded_args)
            else:
                res = self.agent.update_raw(self.canister_id, name, encoded_args)
            
            # 6. 反序列化返回值
            return decode(res, ret_types)
            
        return method

    def __getattr__(self, name):
        if name in self.methods:
            return getattr(self, name)
        raise AttributeError(f"'Canister' object has no attribute '{name}'")