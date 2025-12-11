import sys

# 检查是否使用真实网络调用（默认使用 Mock 模式进行测试）
# 设置为 True 可以使用真实网络调用（需要网络连接）
USE_REAL_NETWORK = False

# 导入当前项目的接口
from icp_agent import Agent, Client
from icp_identity import Identity
from icp_canister import Canister
from icp_candid import encode, Types

# --- 配置 ---
CANISTER_ID = "ryjl3-tyaaa-aaaaa-aaaba-cai" # ICP Ledger
ACCOUNT_HEX = "4874711516b70ef0f88a7ecd47baa266c4a554850ea6373e72cd4c43756ba8e2"

# 你的完整 Ledger DID
LEDGER_DID = """
type Account = record { owner : principal; subaccount : opt blob };
type AccountBalanceArgs = record { account : text };
type AccountIdentifierByteBuf = record { account : blob };
type Allowance = record { from_account_id : text; to_spender_id : text; allowance : Tokens; expires_at : opt nat64; };
type AllowanceArgs = record { account : Account; spender : Account };
type Allowance_1 = record { allowance : nat; expires_at : opt nat64 };
type ApproveArgs = record { fee : opt nat; memo : opt blob; from_subaccount : opt blob; created_at_time : opt nat64; amount : nat; expected_allowance : opt nat; expires_at : opt nat64; spender : Account; };
type ApproveError = variant { GenericError : record { message : text; error_code : nat }; TemporarilyUnavailable; Duplicate : record { duplicate_of : nat }; BadFee : record { expected_fee : nat }; AllowanceChanged : record { current_allowance : nat }; CreatedInFuture : record { ledger_time : nat64 }; TooOld; Expired : record { ledger_time : nat64 }; InsufficientFunds : record { balance : nat }; };
type ArchiveInfo = record { canister_id : principal };
type ArchiveOptions = record { num_blocks_to_archive : nat64; max_transactions_per_response : opt nat64; trigger_threshold : nat64; more_controller_ids : opt vec principal; max_message_size_bytes : opt nat64; cycles_for_archive_creation : opt nat64; node_max_memory_size_bytes : opt nat64; controller_id : principal; };
type ArchivedBlocksRange = record { callback : func (GetBlocksArgs) -> (Result_4) query; start : nat64; length : nat64; };
type ArchivedEncodedBlocksRange = record { callback : func (GetBlocksArgs) -> (Result_5) query; start : nat64; length : nat64; };
type Archives = record { archives : vec ArchiveInfo };
type BlockRange = record { blocks : vec CandidBlock };
type CandidBlock = record { transaction : CandidTransaction; timestamp : TimeStamp; parent_hash : opt blob; };
type CandidOperation = variant { Approve : record { fee : Tokens; from : blob; allowance_e8s : int; allowance : Tokens; expected_allowance : opt Tokens; expires_at : opt TimeStamp; spender : blob; }; Burn : record { from : blob; amount : Tokens; spender : opt blob }; Mint : record { to : blob; amount : Tokens }; Transfer : record { to : blob; fee : Tokens; from : blob; amount : Tokens; spender : opt blob; }; };
type CandidTransaction = record { memo : nat64; icrc1_memo : opt blob; operation : opt CandidOperation; created_at_time : TimeStamp; };
type ConsentInfo = record { metadata : ConsentMessageMetadata; consent_message : ConsentMessage; };
type ConsentMessage = variant { FieldsDisplayMessage : FieldsDisplay; GenericDisplayMessage : text; };
type ConsentMessageMetadata = record { utc_offset_minutes : opt int16; language : text; };
type ConsentMessageRequest = record { arg : blob; method : text; user_preferences : ConsentMessageSpec; };
type ConsentMessageSpec = record { metadata : ConsentMessageMetadata; device_spec : opt DisplayMessageType; };
type Decimals = record { decimals : nat32 };
type DisplayMessageType = variant { GenericDisplay; FieldsDisplay };
type Duration = record { secs : nat64; nanos : nat32 };
type ErrorInfo = record { description : text };
type FeatureFlags = record { icrc2 : bool };
type FieldsDisplay = record { fields : vec record { text; Value }; intent : text; };
type GetAllowancesArgs = record { prev_spender_id : opt text; from_account_id : text; take : opt nat64; };
type GetBlocksArgs = record { start : nat64; length : nat64 };
type GetBlocksError = variant { BadFirstBlockIndex : record { requested_index : nat64; first_valid_index : nat64; }; Other : record { error_message : text; error_code : nat64; }; };
type Icrc21Error = variant { GenericError : record { description : text; error_code : nat }; InsufficientPayment : ErrorInfo; UnsupportedCanisterCall : ErrorInfo; ConsentMessageUnavailable : ErrorInfo; };
type InitArgs = record { send_whitelist : vec principal; token_symbol : opt text; transfer_fee : opt Tokens; minting_account : text; transaction_window : opt Duration; max_message_size_bytes : opt nat64; icrc1_minting_account : opt Account; archive_options : opt ArchiveOptions; initial_values : vec record { text; Tokens }; token_name : opt text; feature_flags : opt FeatureFlags; };
type LedgerCanisterPayload = variant { Upgrade : opt UpgradeArgs; Init : InitArgs; };
type MetadataValue = variant { Int : int; Nat : nat; Blob : blob; Text : text };
type Name = record { name : text };
type QueryBlocksResponse = record { certificate : opt blob; blocks : vec CandidBlock; chain_length : nat64; first_block_index : nat64; archived_blocks : vec ArchivedBlocksRange; };
type QueryEncodedBlocksResponse = record { certificate : opt blob; blocks : vec blob; chain_length : nat64; first_block_index : nat64; archived_blocks : vec ArchivedEncodedBlocksRange; };
type RemoveApprovalArgs = record { fee : opt nat; from_subaccount : opt blob; spender : blob; };
type Result = variant { Ok : nat; Err : TransferError };
type Result_1 = variant { Ok : ConsentInfo; Err : Icrc21Error };
type Result_2 = variant { Ok : nat; Err : ApproveError };
type Result_3 = variant { Ok : nat; Err : TransferFromError };
type Result_4 = variant { Ok : BlockRange; Err : GetBlocksError };
type Result_5 = variant { Ok : vec blob; Err : GetBlocksError };
type Result_6 = variant { Ok : nat64; Err : TransferError_1 };
type SendArgs = record { to : text; fee : Tokens; memo : nat64; from_subaccount : opt blob; created_at_time : opt TimeStamp; amount : Tokens; };
type StandardRecord = record { url : text; name : text };
type Symbol = record { symbol : text };
type TimeStamp = record { timestamp_nanos : nat64 };
type TipOfChainRes = record { certification : opt blob; tip_index : nat64 };
type Tokens = record { e8s : nat64 };
type TransferArg = record { to : Account; fee : opt nat; memo : opt blob; from_subaccount : opt blob; created_at_time : opt nat64; amount : nat; };
type TransferArgs = record { to : blob; fee : Tokens; memo : nat64; from_subaccount : opt blob; created_at_time : opt TimeStamp; amount : Tokens; };
type TransferError = variant { GenericError : record { message : text; error_code : nat }; TemporarilyUnavailable; BadBurn : record { min_burn_amount : nat }; Duplicate : record { duplicate_of : nat }; BadFee : record { expected_fee : nat }; CreatedInFuture : record { ledger_time : nat64 }; TooOld; InsufficientFunds : record { balance : nat }; };
type TransferError_1 = variant { TxTooOld : record { allowed_window_nanos : nat64 }; BadFee : record { expected_fee : Tokens }; TxDuplicate : record { duplicate_of : nat64 }; TxCreatedInFuture; InsufficientFunds : record { balance : Tokens }; };
type TransferFee = record { transfer_fee : Tokens };
type TransferFromArgs = record { to : Account; fee : opt nat; spender_subaccount : opt blob; from : Account; memo : opt blob; created_at_time : opt nat64; amount : nat; };
type TransferFromError = variant { GenericError : record { message : text; error_code : nat }; TemporarilyUnavailable; InsufficientAllowance : record { allowance : nat }; BadBurn : record { min_burn_amount : nat }; Duplicate : record { duplicate_of : nat }; BadFee : record { expected_fee : nat }; CreatedInFuture : record { ledger_time : nat64 }; TooOld; InsufficientFunds : record { balance : nat }; };
type UpgradeArgs = record { icrc1_minting_account : opt Account; feature_flags : opt FeatureFlags; };
type Value = variant { Text : record { content : text }; TokenAmount : record { decimals : nat8; amount : nat64; symbol : text }; TimestampSeconds : record { amount : nat64 }; DurationSeconds : record { amount : nat64 }; };
service : (LedgerCanisterPayload) -> {
  account_balance : (AccountIdentifierByteBuf) -> (Tokens) query;
  account_balance_dfx : (AccountBalanceArgs) -> (Tokens) query;
  account_identifier : (Account) -> (blob) query;
  archives : () -> (Archives) query;
  decimals : () -> (Decimals) query;
  get_allowances : (GetAllowancesArgs) -> (vec Allowance) query;
  icrc10_supported_standards : () -> (vec StandardRecord) query;
  icrc1_balance_of : (Account) -> (nat) query;
  icrc1_decimals : () -> (nat8) query;
  icrc1_fee : () -> (nat) query;
  icrc1_metadata : () -> (vec record { text; MetadataValue }) query;
  icrc1_minting_account : () -> (opt Account) query;
  icrc1_name : () -> (text) query;
  icrc1_supported_standards : () -> (vec StandardRecord) query;
  icrc1_symbol : () -> (text) query;
  icrc1_total_supply : () -> (nat) query;
  icrc1_transfer : (TransferArg) -> (Result);
  icrc21_canister_call_consent_message : (ConsentMessageRequest) -> (Result_1);
  icrc2_allowance : (AllowanceArgs) -> (Allowance_1) query;
  icrc2_approve : (ApproveArgs) -> (Result_2);
  icrc2_transfer_from : (TransferFromArgs) -> (Result_3);
  is_ledger_ready : () -> (bool) query;
  name : () -> (Name) query;
  query_blocks : (GetBlocksArgs) -> (QueryBlocksResponse) query;
  query_encoded_blocks : (GetBlocksArgs) -> (QueryEncodedBlocksResponse) query;
  remove_approval : (RemoveApprovalArgs) -> (Result_2);
  send_dfx : (SendArgs) -> (nat64);
  symbol : () -> (Symbol) query;
  tip_of_chain : () -> (TipOfChainRes) query;
  transfer : (TransferArgs) -> (Result_6);
  transfer_fee : (record {}) -> (TransferFee) query;
}
"""

class MockAgent:
    def query_raw(self, canister_id, method, args):
        print(f"[Mock] 正在调用: {method}...")
        # 模拟 0.10769909 ICP 的返回数据 (Tokens = record { e8s : nat64 })
        # 0.10769909 ICP = 10769909 e8s
        e8s_value = 10769909
        # 创建正确的 Candid 编码：record { e8s : nat64 }
        tokens_record = Types.Record({'e8s': Types.Nat64})
        mock_data = encode([{'type': tokens_record, 'value': {'e8s': e8s_value}}])
        return mock_data 

def main():
    if USE_REAL_NETWORK:
        try:
            client = Client(url="https://ic0.app")
            identity = Identity(anonymous=True)
            agent = Agent(identity, client)
            print("[+] 网络模式: 连接到 IC 主网")
        except Exception as e:
            print(f"[!] 网络连接失败，切换到 Mock 模式: {e}")
            agent = MockAgent()
            print("[+] Mock模式: 仅验证解析")
    else:
        agent = MockAgent()
        print("[+] Mock模式: 仅验证解析")

    print(f"[-] 正在解析 Ledger DID...")
    
    try:
        # [测试点1] 验证是否支持 service : (args) -> 语法
        ledger = Canister(agent, CANISTER_ID, LEDGER_DID)
        print("[+] ✅ DID 解析成功！")
    except Exception as e:
        print(f"[!] ❌ DID 解析失败: {e}")
        import traceback
        traceback.print_exc()
        return

    # [测试点2] 验证 AccountIdentifierByteBuf (record {account:blob}) 的解析
    # 以及 blob 类型的参数传递
    print(f"[-] 正在查询账户余额: {ACCOUNT_HEX[:10]}...")
    
    try:
        # 将 Hex 转为 bytes (对应 Candid blob)
        account_blob = bytes.fromhex(ACCOUNT_HEX)
        
        # account_balance 需要一个 record 作为参数
        # 根据 Canister 的实现，record 参数应该作为位置参数传递字典
        args = {'account': account_blob}
        
        # [测试点3] 类型链接与编码
        res = ledger.account_balance(args)
        
        # 处理返回结果 Tokens { e8s : nat64 }
        # decode 返回的是列表，格式: [{'type': 'record {e8s:nat64}', 'value': {'e8s': ...}}]
        if isinstance(res, list) and len(res) > 0:
            val = res[0]
            if isinstance(val, dict) and 'value' in val:
                tokens_dict = val['value']
                if isinstance(tokens_dict, dict) and 'e8s' in tokens_dict:
                    e8s = tokens_dict['e8s']
                else:
                    print(f"[!] ⚠️ 无法解析返回结果: {res}")
                    return
            else:
                print(f"[!] ⚠️ 无法解析返回结果: {res}")
                return
        else:
            print(f"[!] ⚠️ 无法解析返回结果: {res}")
            return
            
        icp = e8s / 100_000_000.0
        
        print(f"[+] ✅ 调用成功！")
        print(f"    原始数据: {res}")
        print(f"    ICP余额 : {icp:.8f}")
        
        if abs(icp - 0.10769909) < 1e-8:
            print("[+] ✨ 余额验证通过！数据完全匹配。")
        else:
            print(f"[!] ⚠️ 余额与预期不符 (预期: 0.10769909, 实际: {icp}) - 但调用已成功")

    except Exception as e:
        print(f"[!] ❌ 调用失败: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
