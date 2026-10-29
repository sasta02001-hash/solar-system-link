"""Offline, independent public-envelope check; never downloads, signs or starts SSS.

Use only with the SSS producer's frozen public catalog and public DER.  This
checks the raw signed message independently of the production .NET verifier.
It does not verify/install a ZIP, bootstrap, process, input grant or native SSS.
"""
import base64
import hashlib
import hmac
import json
from pathlib import Path
import re
import sys
import time

KEY_ID = "24c5cc5e36e928eae4677eba1d6b256ccca90409652c3e43bf69d73581aed1b1"
PURPOSE = "SolarSystemShield.CurrentUserUiUpdate.v1"
PROFILE = "current-user-ui-candidate-v1"
FIELDS = set("schema product purpose profile channel keyId version sequence publishedUtcTicks expiresUtcTicks packageUrl packageBytes packageSha256 files".split())
FILES = set(("SSS.exe", "SSS.exe.config", "SSS.Core.dll", "SSS.Functional.dll", "SSS.Operations.dll", "SSS.Updates.dll", "SSS.OperationsHost.exe", "SSS.OperationsHost.exe.config", "Scripts/ReadStatus.ps1", "Scripts/FirewallOperation.ps1", "README.zh-TW.txt"))
LOWER_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z", re.ASCII)


def require(value, code):
    if not value:
        raise ValueError(code)


def pairs(values):
    result = {}
    for key, value in values:
        require(key not in result, "duplicate-json-field")
        result[key] = value
    return result


def integer(raw):
    require(re.fullmatch(r"0|-?[1-9][0-9]*", raw, flags=re.ASCII) is not None, "noncanonical-number")
    value = int(raw)
    require(-(2**63) <= value <= 2**63 - 1, "int64-overflow")
    return value


def no_float(_):
    raise ValueError("noninteger-json-number")


def decode(raw):
    require(not raw.startswith(b"\xef\xbb\xbf"), "utf8-bom")
    return json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs,
                      parse_int=integer, parse_float=no_float, parse_constant=no_float)


def canonical_base64(value):
    require(type(value) is str, "base64-type")
    raw = base64.b64decode(value.encode("ascii"), validate=True)
    require(base64.b64encode(raw).decode("ascii") == value, "base64-canonical")
    return raw


def positive(value, maximum):
    return type(value) is int and 0 < value <= maximum


def bounded_read(path, maximum):
    with Path(path).open("rb") as handle:
        raw = handle.read(maximum + 1)
    require(0 < len(raw) <= maximum, "input-size")
    return raw


PUBLIC_DER = base64.b64decode("MIIBCgKCAQEAwcCFDTMoYgg4bmHtiJM6YsvnpXXHH/DkqaPftCSWcMGvY+IljvrcCLQoWA5qTAwgOoGqMk9+s3AUyaVWDYOWTGlqYkXokX21LdH1Y/v6KGEc0Xx/0YTIQaUnBK0DD+yLbt91XqV2jgHXBjCgCea3PqUw5tdafMU7H89W5OQf6Z72bZy1YKd6amQrwZ5a7Bu4RRXUXEG78uc86TCqGNH6lrHyzXLsWDAreGEH191We9kmfJM7TZc32MZkgbdXE7XljJO9PWBBJtWmdZktHsQwtEvibnxvSyi6//IWPybYuaXeZ+Pm06sgzOY8jeWbTCWX2onI3sIaqUNsSQejjkA5YQIDAQAB")


def verify_catalog(raw, now_ticks=None, require_current=True):
    require(type(raw) is bytes and 0 < len(raw) <= 8192, "input-size")
    der = PUBLIC_DER
    require(len(der) == 270 and hashlib.sha256(der).hexdigest() == KEY_ID, "fixed-public-key")
    require(der[:9] == bytes.fromhex("3082010a0282010100") and der[265:] == bytes.fromhex("0203010001"), "public-key-der")
    require(der[9] & 128 and der[264] & 1, "rsa2048-modulus")
    envelope = decode(raw)
    require(type(envelope) is dict and set(envelope) == {"payloadBase64", "signatureBase64"}, "envelope-fields")
    payload = canonical_base64(envelope["payloadBase64"])
    signature = canonical_base64(envelope["signatureBase64"])
    require(len(signature) == 256, "rsa-signature-length")
    modulus = int.from_bytes(der[9:265], "big")
    signature_integer = int.from_bytes(signature, "big")
    require(signature_integer < modulus, "rsa-signature-range")
    digest = hashlib.sha256(PURPOSE.encode("ascii") + b"\n" + payload).digest()
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + digest
    expected = b"\x00\x01" + b"\xff" * (256 - len(digest_info) - 3) + b"\x00" + digest_info
    actual = pow(signature_integer, 65537, modulus).to_bytes(256, "big")
    require(hmac.compare_digest(actual, expected), "rsa-sha256-pkcs1-signature")
    value = decode(payload)
    require(type(value) is dict and set(value) == FIELDS, "payload-fields")
    require(type(value["schema"]) is int and value["schema"] == 1, "schema")
    require(value["product"] == "SolarSystemShield" and value["purpose"] == PURPOSE and value["profile"] == PROFILE and value["channel"] == "stable" and value["keyId"] == KEY_ID, "payload-purpose")
    version = value["version"]
    require(type(version) is str and VERSION.fullmatch(version) is not None and all(int(part) <= 2**31 - 1 for part in version.split(".")), "canonical-version")
    require(positive(value["sequence"], 2**63 - 1), "sequence")
    published, expires = value["publishedUtcTicks"], value["expiresUtcTicks"]
    require(positive(published, 3155378975999999999) and positive(expires, 3155378975999999999) and published < expires <= published + 7 * 86400 * 10000000, "catalog-validity")
    now = 621355968000000000 + time.time_ns() // 100 if now_ticks is None else now_ticks
    require(not require_current or published <= now < expires, "catalog-not-current")
    url = f"https://github.com/sasta02001-hash/solar-system-link/releases/download/sss-ui-v{version}/SSS-{version}-UI-x64.zip"
    require(value["packageUrl"] == url and positive(value["packageBytes"], 16777216), "package-binding")
    require(type(value["packageSha256"]) is str and LOWER_HASH.fullmatch(value["packageSha256"]) is not None, "package-sha256")
    files = value["files"]
    require(type(files) is list and len(files) == 11, "file-count")
    seen, total = set(), 0
    for entry in files:
        require(type(entry) is dict and set(entry) == {"path", "bytes", "sha256"}, "file-entry-fields")
        path = entry["path"]
        require(type(path) is str and path in FILES and path not in seen, "file-entry-path")
        require(positive(entry["bytes"], 8388608), "file-entry-size")
        require(type(entry["sha256"]) is str and LOWER_HASH.fullmatch(entry["sha256"]) is not None, "file-entry-sha256")
        seen.add(path)
        total += entry["bytes"]
    require(seen == FILES and total <= 16777216, "file-vector")
    return value
