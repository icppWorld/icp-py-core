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

    def test_principal_encode_decode_3(self):
        """Test encoding and decoding a 29-byte principal.

        Principal: ytoqu-ey42w-sb2ul-m7xgn-oc7xo-i4btp-kuxjc-b6pt4-dwdzu-kfqs4-nae
        Hex bytes: 1cd5a41d516cfdccd70bf7723819bd54ba441f3e7c1d879a28b0971a02
        """
        principal_str = 'ytoqu-ey42w-sb2ul-m7xgn-oc7xo-i4btp-kuxjc-b6pt4-dwdzu-kfqs4-nae'
        
        # Test encode
        res_encode = encode([{'type': Types.Principal, 'value': principal_str}])
        expected_encoded = "4449444c000168011d1cd5a41d516cfdccd70bf7723819bd54ba441f3e7c1d879a28b0971a02"
        assert res_encode.hex() == expected_encoded
        
        # Test decode
        data = bytes.fromhex(expected_encoded)
        res_decode = decode(data)
        assert len(res_decode) == 1
        assert res_decode[0]["type"] == 'principal'
        assert res_decode[0]["value"].to_str() == principal_str

    def test_record_encode(self):
        record = Types.Record({'foo': Types.Text, 'bar': Types.Int})
        res = encode([{'type': record, 'value': {'foo': '💩', 'bar': 42}}])
        assert res.hex() == '4449444c016c02d3e3aa027c868eb7027101002a04f09f92a9'

    def test_record_decode(self):
        data = bytes.fromhex('4449444c016c02d3e3aa027c868eb7027101002a04f09f92a9')
        res = decode(data)
        assert len(res) == 1
        assert res[0]['value'] == {'4895187': 42, '5097222': '💩'}