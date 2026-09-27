import json
import tarfile
from io import BytesIO

from qdrishti.scanners import binary, configs, container, deps
from qdrishti.scanners.source import scan_source


def names(findings):
    return [(f.canonical, f.params.get("size") or f.params.get("curve") or f.params.get("mode")) for f in findings]


def test_java_resolves_constants_and_lookahead():
    src = '''
    class K {
      private static final int BITS = 3072;
      private static final String T = "RSA/ECB/PKCS1Padding";
      void a() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(BITS);
        Cipher c = Cipher.getInstance(T);
        // Cipher.getInstance("DES") in a comment must be ignored
      }
    }'''
    f = scan_source(src, "K.java", ".java")
    assert ("RSA", 3072) in names(f)
    assert any(x.rule_id == "java-getinstance-const" and x.agility == "constant" for x in f)
    assert not any(x.canonical == "DES" for x in f)


def test_python_aes_key_size_from_urandom():
    src = "key = os.urandom(32)\ncipher = AES.new(key, AES.MODE_GCM)\n"
    f = scan_source(src, "a.py", ".py")
    assert f[0].canonical == "AES" and f[0].params == {"size": 256, "mode": "gcm"}


def test_go_c_js_rules():
    go = scan_source("const bits = 1024\nk, _ := rsa.GenerateKey(rand.Reader, bits)\n", "m.go", ".go")
    assert ("RSA", 1024) in names(go)
    c = scan_source("#define BITS 2048\nRSA_generate_key_ex(r, BITS, e, NULL);\n", "x.c", ".c")
    assert ("RSA", 2048) in names(c)
    js = scan_source("crypto.generateKeyPairSync('rsa', { modulusLength: 4096 })", "a.js", ".js")
    assert ("RSA", 4096) in names(js)


def test_config_nginx_and_sshd():
    nginx = "ssl_protocols TLSv1 TLSv1.2;\nssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:!aNULL:HIGH;\nssl_ecdh_curve X25519MLKEM768:X25519;\n"
    f = configs.scan_config(nginx, "nginx.conf", configs.is_config("nginx.conf", nginx))
    kinds = [(x.kind, x.canonical or x.identifier) for x in f]
    assert ("protocol", "TLS") in kinds
    assert ("suite", "ECDHE-RSA-AES128-GCM-SHA256") in kinds
    assert ("algorithm", "X25519MLKEM768") in kinds
    assert len([k for k in kinds if k[0] == "suite"]) == 1          # !aNULL and HIGH are skipped
    ssh = "KexAlgorithms diffie-hellman-group1-sha1,curve25519-sha256\n"
    f = configs.scan_config(ssh, "sshd_config", "ssh")
    assert f[0].params == {"size": 1024}


def test_deps_flags_deprecated_libraries():
    f = deps.scan_deps("pycrypto==2.6.1\nrequests==2.0\n", "requirements.txt", "requirements.txt")
    assert len(f) == 1 and f[0].extra["status"] == "weak"
    f = deps.scan_deps("FROM ubuntu:18.04\n", "Dockerfile", "Dockerfile")
    assert f[0].params["name"] == "OpenSSL" and f[0].params["version"] == "1.1.1"


def test_binary_constants_and_library_mode():
    blob = b"\x7fELF" + b"\x00" * 64 + b"crypto/rsa.GenerateKey" + binary.AES_SBOX
    f = binary.scan_binary(blob, "app")
    assert {x.canonical for x in f} >= {"RSA", "AES"}
    lib = b"\x7fELF" + b"OpenSSL 1.1.1k  25 Mar 2021\x00MD5_Init\x00"
    f = binary.scan_binary(lib, "libcrypto.so.1.1")
    assert any(x.kind == "library" and x.extra["status"] == "weak" for x in f)
    assert all(x.usage == "available" for x in f if x.kind == "algorithm")


def test_container_unpack(tmp_path):
    def tar_bytes(files):
        buf = BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as t:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                t.addfile(info, BytesIO(data))
        return buf.getvalue()
    layer = tar_bytes({"etc/ssl/openssl.cnf": b"MinProtocol = TLSv1\n"})
    image = tar_bytes({"manifest.json": json.dumps([{"Layers": ["l1/layer.tar"]}]).encode(), "l1/layer.tar": layer})
    p = tmp_path / "image.tar"
    p.write_bytes(image)
    rootfs = container.unpack_saved_image(p, tmp_path)
    assert (rootfs / "etc" / "ssl" / "openssl.cnf").read_text() == "MinProtocol = TLSv1\n"
