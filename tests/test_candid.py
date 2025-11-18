from icp_candid.candid import encode, decode, Types


class TestCandidBasics:
    def test_nat_encode(self):
        res = encode([{'type': Types.Nat, 'value': 10_000_000_000}])
        assert res.hex() == "4449444c00017d80c8afa025"

    def test_nat_decode(self):
        data = bytes.fromhex("4449444c00017d80c8afa025")
        res = decode(data)
        assert len(res) == 1
        assert res[0]["type"] == 'nat'
        assert res[0]["value"] == 10_000_000_000

    def test_principal_encode(self):
        res = encode([{'type': Types.Principal, 'value': 'aaaaa-aa'}])
        assert res.hex() == "4449444c0001680100"

    def test_principal_decode(self):
        data = bytes.fromhex("4449444c0001680100")
        res = decode(data)
        assert len(res) == 1
        assert res[0]["type"] == 'principal'
        assert res[0]["value"].to_str() == 'aaaaa-aa'

    def test_principal_decode_2(self):
        """Test decoding a real principal with flag byte (non-anonymous principal).

        This test uses a real 29-byte principal value to verify that the decoder
        correctly reads the flag byte before the length.
        """
        data = bytes.fromhex("4449444c000168011d33dc5a7ac97dd25626afa3166ea0bb463e059fea5d3cee12489beb5302")
        res = decode(data)
        assert len(res) == 1
        assert res[0]["type"] == 'principal'
        assert res[0]["value"].to_str() == 'xzgcn-xbt3r-nhvsl-52jlc-nl5dc-zxkbo-2ghyc-z72s5-htxbe-se35n-jqe'

    def test_record_encode(self):
        record = Types.Record({'foo': Types.Text, 'bar': Types.Int})
        res = encode([{'type': record, 'value': {'foo': '💩', 'bar': 42}}])
        assert res.hex() == '4449444c016c02d3e3aa027c868eb7027101002a04f09f92a9'

    def test_record_decode(self):
        data = bytes.fromhex('4449444c016c02d3e3aa027c868eb7027101002a04f09f92a9')
        res = decode(data)
        assert len(res) == 1
        assert res[0]['value'] == {'_4895187': 42, '_5097222': '💩'}