from qdrishti import registry as R


def test_normalize_aliases():
    assert R.normalize("rsaEncryption") == ("RSA", {})
    assert R.normalize("prime256v1") == ("EC", {"curve": "P-256"})
    assert R.normalize("DESede") == ("3DES", {})
    assert R.normalize("ML-KEM-768") == ("ML-KEM", {"size": 768})
    assert R.normalize("X25519MLKEM768") == ("X25519MLKEM768", {})
    assert R.normalize("sha3_256") == ("SHA3-256", {})
    assert R.normalize("not-a-cipher") is None


def test_jca_transformation():
    assert R.parse_transformation("AES/ECB/PKCS5Padding") == [("AES", {"mode": "ecb", "padding": "pkcs5"}, "encrypt")]
    assert R.parse_transformation("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")[0][1]["padding"] == "oaep"
    # bare "AES" defaults to ECB in the JCA
    assert R.parse_transformation("AES")[0][1]["mode"] == "ecb"


def test_jca_signature_splits_hash_and_key():
    parts = R.parse_jca_signature("SHA1withRSA")
    assert ("RSA", {}, "sign") in parts and ("SHA-1", {}, "digest") in parts


def test_cipher_suites_iana_and_openssl():
    iana = R.parse_cipher_suite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
    names = [p[0] for p in iana]
    assert names == ["ECDH", "RSA", "AES"]          # AEAD: no separate HMAC
    ossl = R.parse_cipher_suite("DES-CBC3-SHA")
    assert [p[0] for p in ossl] == ["RSA", "3DES", "HMAC"]
    assert ossl[0][2] == "key-agree"                # static RSA key transport
    tls13 = R.parse_cipher_suite("TLS_AES_256_GCM_SHA384")
    assert tls13 == [("AES", {"size": 256, "mode": "gcm"}, "encrypt")]


def test_ssh_names():
    assert R.parse_ssh("mlkem768x25519-sha256", "kex") == [("X25519MLKEM768", {}, "key-agree")]
    assert R.parse_ssh("hmac-sha2-256", "mac") == [("HMAC", {"hash": "SHA-256"}, "tag")]
    assert R.parse_ssh("aes128-ctr", "cipher")[0][:2] == ("AES", {"size": 128, "mode": "ctr"})


def test_hmac_sha256_not_mangled():
    assert R.parse_hmac("HmacSHA256") == [("HMAC", {"hash": "SHA-256"}, "tag")]


def test_assessment():
    assert R.assess("RSA", {"size": 1024})["status"] == R.BROKEN
    assert R.assess("RSA", {"size": 3072})["status"] == R.QV
    assert R.assess("AES", {"size": 128})["status"] == R.QW
    assert R.assess("AES", {"size": 256, "mode": "gcm"})["status"] == R.SAFE
    assert R.assess("AES", {"size": 256, "mode": "ecb"})["status"] == R.WEAK
    assert R.assess("ML-KEM", {"size": 768})["status"] == R.PQC
    assert R.assess("TLS", {"version": "1.0"})["status"] == R.BROKEN
    assert R.assess("SHA-1", {})["status"] == R.BROKEN
