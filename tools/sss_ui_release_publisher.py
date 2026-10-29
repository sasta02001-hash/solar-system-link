#!/usr/bin/env python3
"""Fixed signed SSS UI assets only; no install, signing, execution or grant.
Stable rotation retains pinned pending/archive bytes, with a possible short404.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import sss_ui_catalog as codec

REPOSITORY = "sasta02001-hash/solar-system-link"
API = "https://api.github.com"
UPLOADS = "https://uploads.github.com"
PUBLIC = "https://github.com/" + REPOSITORY + "/releases/download/"
API_VERSION = "2022-11-28"
VERSION = "0.4.7.0"
VERSION_TAG = "sss-ui-v" + VERSION
RENEWAL_SEQUENCE = 3
RENEWAL_CATALOG_BYTES = 2921
RENEWAL_CATALOG_SHA256 = "369a16eb4efeca86a7c3f0152e62ba15841692bdca031bafe842b75b82ec39db"
STABLE_TAG = "sss-ui-stable"
ENVELOPE_NAME = "sss-ui-update-v1.json"
PACKAGE_NAME = "SSS-" + VERSION + "-UI-x64.zip"
INITIAL_NAME = "SSS-0.4.7.0-Background-Initial-Setup.zip"
REPAIR_NAME = "SSS-0.4.7.0-Background-Repair-From-0.4.6.zip"
VERSION_ASSET_NAMES = (PACKAGE_NAME, INITIAL_NAME, REPAIR_NAME)

# Explicit048 branch. Historical047 constants and activation stay immutable.
VERSION_048 = "0.4.8.0"
VERSION_TAG_048 = "sss-ui-v0.4.8.0"
PACKAGE_NAME_048 = "SSS-0.4.8.0-UI-x64.zip"
INITIAL_NAME_048 = "SSS-0.4.8.0-Background-Initial-Setup.zip"
UI048_BYTES = 760932
UI048_SHA256 = "8bb2dda57da5a8eceb95853939c13cab65d0d9385ec92d42ebb5368962524764"
CATALOG048_BYTES = 2921
CATALOG048_SHA256 = "c58f69ce19aee53cc4dc7309227f80ac9dd5dde075eb7cae0917ee01ba3e5727"
INITIAL048_BYTES = 855417
INITIAL048_SHA256 = "6f7940e5a045fa031ece86a85c79d75b3a356be5e4e8594253c76d9d3475d6b6"
PREDECESSOR048_SHA256 = "369a16eb4efeca86a7c3f0152e62ba15841692bdca031bafe842b75b82ec39db"
WAIT_ACTUAL048 = "WAITING_ACTUAL_REPAIR_ACTIVATION"
# None is an intentional non-authorizing veto. Root must first derive a true,
# redacted maintenance-before-first-start record from actual source-qualified
# ordinary activation evidence, then bind all three exact constants in a new
# reviewed revision. A caller bool, old047 record or source qualification alone
# can never satisfy this gate. No key or remote input authority is conveyed.
ACTIVATION048_RECORD_BYTES = None
ACTIVATION048_RECORD_SHA256 = None
ACTIVATION048_EXPECTED = None
REQUEST048_FIELDS = ("schema","product","purpose","version","sequence",
    "publicationGuard","packageBytes","packageSha256","envelopeSha256",
    "initialSetupBytes","initialSetupSha256","activationRecordSha256",
    "expectedStableEnvelopeSha256")
RELEASE_BODY_048 = ("SSS-UI-PUBLISHER-V1: signed current-user UI assets only.\n\n"
    "SSS 0.4.8.0 更新背景啟動元件整合與維護診斷，UI套件與首次安裝包分開提供。"
    "首次安裝包只供沒有SSS更新根的電腦；已有安裝時會拒絕接管。"
    "本發行不提供本機專用維修工具，也不把UI簽章當成啟動元件維修授權。\n\n"
    "Windows7 POS、登入啟動、遠端連線、鍵鼠與持續操作仍須各自實機驗收；"
    "不是完整防火牆、NativeReady或操作授權，不宣稱99或100分。")

INITIAL048_FILES = {'SSS.UiInitialSetup.exe': (61952, 'c51307558c7ec08c8c179a4c41f833494008e00af53518eaad5499ae08cb4ae9'), 'SSS.UiInitialSetup.exe.config': (138, '008d5c22af1b051c44f2fca2c8f0897cd5763ba687a55372cb480d2d7bc72337'), 'Install-SSS-Background.vbs': (306, 'd1a614d9926ee6ddb86ede0ec575010fec93d70dd3399bee426a957aada86963'), 'initial-input/SSS.UiUpdateCoordinator.exe': (146432, 'b457d95ccf64e711e20704bb85a5ca04b66384ebb26ed989b34c8838c6727b8c'), 'initial-input/SSS.UiUpdateCoordinator.exe.config': (138, '008d5c22af1b051c44f2fca2c8f0897cd5763ba687a55372cb480d2d7bc72337'), 'initial-input/sss-ui-update-v1.json': (2921, 'c58f69ce19aee53cc4dc7309227f80ac9dd5dde075eb7cae0917ee01ba3e5727'), 'initial-input/SSS-0.4.8.0-UI-x64.zip': (760932, '8bb2dda57da5a8eceb95853939c13cab65d0d9385ec92d42ebb5368962524764')}

# New049 data is intentionally unbound. None is not a wildcard or permission.
VERSION_049 = "0.4.9.0"
VERSION_TAG_049 = "sss-ui-v0.4.9.0"
PACKAGE_NAME_049 = "SSS-0.4.9.0-UI-x64.zip"
INITIAL_NAME_049 = "SSS-0.4.9.0-Background-Initial-Setup.zip"
UI049_BYTES = 761651
UI049_SHA256 = 'ad10c1f61bd221498cdc53bda401d703e6df073d6f350e5d68261c10cdf90e93'
CATALOG049_BYTES = 2921
CATALOG049_SHA256 = 'f881f72b5ad759138c58a8201f2292c0df03f298d3ca4afb662e12756635eea1'
INITIAL049_BYTES = 856150
INITIAL049_SHA256 = '993c360cd8405900592b576f3ad22dcad2465c91688935d124e5df2b87e41a9b'
INITIAL049_FILES = {'SSS.UiInitialSetup.exe': (61952, 'cbfe0137ff2c4768039e2449133ae1ffa3ba3c8ebdf8342c03a21e22a231249a'), 'SSS.UiInitialSetup.exe.config': (138, '008d5c22af1b051c44f2fca2c8f0897cd5763ba687a55372cb480d2d7bc72337'), 'Install-SSS-Background.vbs': (306, 'd1a614d9926ee6ddb86ede0ec575010fec93d70dd3399bee426a957aada86963'), 'initial-input/SSS.UiUpdateCoordinator.exe': (146432, 'b457d95ccf64e711e20704bb85a5ca04b66384ebb26ed989b34c8838c6727b8c'), 'initial-input/SSS.UiUpdateCoordinator.exe.config': (138, '008d5c22af1b051c44f2fca2c8f0897cd5763ba687a55372cb480d2d7bc72337'), 'initial-input/sss-ui-update-v1.json': (2921, 'f881f72b5ad759138c58a8201f2292c0df03f298d3ca4afb662e12756635eea1'), 'initial-input/SSS-0.4.9.0-UI-x64.zip': (761651, 'ad10c1f61bd221498cdc53bda401d703e6df073d6f350e5d68261c10cdf90e93')}
BOOTSTRAP049_EXECUTABLE_SHA256 = 'b457d95ccf64e711e20704bb85a5ca04b66384ebb26ed989b34c8838c6727b8c'
BOOTSTRAP049_CONFIG_SHA256 = '008d5c22af1b051c44f2fca2c8f0897cd5763ba687a55372cb480d2d7bc72337'
# The existing stable predecessor is047 sequence3, never superseded048.
PREDECESSOR049_SHA256 = "369a16eb4efeca86a7c3f0152e62ba15841692bdca031bafe842b75b82ec39db"
# Root must bind four real producer/independent qualification receipt hashes in
# a reviewed revision. Source proposals and caller booleans cannot fill this.
ASSET049_PRODUCER_COMMITMENT = {'productionSourceQualificationSha256': 'ffe1bf44e30c54a0ea7490a1976a245c76bf3dac7e07e45c03e6d58f9956100a', 'catalogProducerQualificationSha256': 'e1670e3115540dd6af62fe13ccd5c5bc5ad79c0b0f0f4a955ae0efffa284d097', 'initialProducerQualificationSha256': 'a81bfb97c7f0b4c8fec86ef41df76b687525bbed06b7c60a6a308add06bb0af3', 'independentGenuineVectorQualificationSha256': '385e3a4d78f3461d7571f99f6d3364961943181a77e67c7409cc1626ea0c9a0d'}
WAIT_ASSETS049 = "WAITING_GENUINE049_ASSET_AND_PRODUCER_QUALIFICATION"
WAIT_SOURCE049 = "WAITING_049_PRODUCTION_SOURCE_QUALIFICATION"
ASSET049_GENUINE_DATA_COMMITMENT = {'genuineUIHandoffSha256': '93a7ddb3ca4c9244573591454bf0f95ce46fc4063c7a75bc69305d87feaa7fca', 'rootRawCryptoAndExactElevenDataQualificationSha256': '385e3a4d78f3461d7571f99f6d3364961943181a77e67c7409cc1626ea0c9a0d', 'freshInitialProducerReceiptSha256': 'a81bfb97c7f0b4c8fec86ef41df76b687525bbed06b7c60a6a308add06bb0af3', 'freshInitialRootDataQualificationSha256': '37433bd1c5af748c11495bf11059387819f11a2c90947976d9304f0d78bd9577'}
WAIT_ACTUAL049 = "WAITING_ACTUAL049_REPAIR_ACTIVATION"
WAIT_COMPATIBILITY049 = "WAITING_049_AUDIENCE_MIGRATION_COMPATIBILITY"
WAIT_PUBLICATION049 = "WAITING_GENUINE049_ASSETS_ACTIVATION_AND_COMPATIBILITY"
SUPERSEDED048 = "PERMANENTLY_SUPERSEDED048_DO_NOT_PUBLISH"
ACTIVATION049_RECORD_BYTES = 1394
ACTIVATION049_RECORD_SHA256 = '3d5fdd3a03624163c20084b78cfc3a05b5cd4319c50160cb7f9c101c7406fc11'
ACTIVATION049_EXPECTED = {'schema': 1, 'purpose': 'SSS049.PublicationOrderActivationEvidence.v1', 'status': 'Reviewed049MaintenanceActivated', 'sourceReceiptSha256': 'd909a8cb0a578c72314328db33be4f30edc0f6904c059caf1d394b1cdd43d3e1', 'sourceReceiptBytes': 3684, 'sourceObservedUtc': '2026-10-29T14:43:52.1536524Z', 'previousVersion': '0.4.7.0', 'previousSequence': 2, 'version': '0.4.9.0', 'sequence': 5, 'catalogSha256': 'f881f72b5ad759138c58a8201f2292c0df03f298d3ca4afb662e12756635eea1', 'bootstrapExecutableSha256': 'b457d95ccf64e711e20704bb85a5ca04b66384ebb26ed989b34c8838c6727b8c', 'bootstrapConfigSha256': '008d5c22af1b051c44f2fca2c8f0897cd5763ba687a55372cb480d2d7bc72337', 'sourceQualified': True, 'actualActivation': True, 'durableCancellationPresent': True, 'originalIoSettled': True, 'handlesSettled': True, 'originalRootIdentityPreserved': True, 'ordinaryPackageAbsent': True, 'exclusionsReleased': True, 'ownRunReadback': True, 'forcedTermination': False, 'machineRestarted': False, 'latestVerified': False, 'sssUiLaunchedByMaintenance': False, 'sslOrPosOperationStarted': False, 'nativeReady': False, 'grantsMaintenanceOrRemoteInput': False, 'originalCurrentVersionAtQuiescence': '0.4.7.0', 'originalCurrentSequenceAtQuiescence': 2, 'oldProcessNativeExitCode': 0, 'ownedWorkerNativeExitCode': 16, 'ownedJobTerminal': 'Cancelled', 'originalFailedHistoryArchivedFileCount': 3, 'originalLedgerBackupFileCount': 5, 'installedSignedRuntimeCount': 11, 'maintenanceDoctorMainExitCode': 0}
COMPATIBILITY049_NAME = "audience-compatibility-v1.json"
COMPATIBILITY049_RECORD_BYTES = 1096
COMPATIBILITY049_RECORD_SHA256 = '160ff75dc8eb47625cce2b1778248c154c38815c967f20c936087fb0ec3f9106'
COMPATIBILITY049_EXPECTED = {'schema': 1, 'purpose': 'SSS049.AudienceMigrationCompatibilityEvidence.v1', 'status': 'Reviewed049KnownAudienceCompatible', 'sourceReceiptSha256': 'fbf87ae5612ae909d15d1060514d74ed5c3d03baa1b1ed2c7a24189f4f8b8668', 'sourceReceiptBytes': 4321, 'sourceObservedUtc': '2026-10-29T14:28:28.223732Z', 'version': '0.4.9.0', 'sequence': 5, 'catalogSha256': 'f881f72b5ad759138c58a8201f2292c0df03f298d3ca4afb662e12756635eea1', 'packageSha256': 'ad10c1f61bd221498cdc53bda401d703e6df073d6f350e5d68261c10cdf90e93', 'initialSetupSha256': '993c360cd8405900592b576f3ad22dcad2465c91688935d124e5df2b87e41a9b', 'audienceScope': 'EXACT_KNOWN_R6_R7_TUPLES_ONLY', 'qualifiedKnownBootstrapTupleCount': 2, 'productionSourceQualified': True, 'completeKnownTupleMatchingQualified': True, 'singleBindingPerOperationQualified': True, 'unknownOrMixedTupleRejected': True, 'existing047AudienceQualified': True, 'freshInitialExistingRootRejected': True, 'notDerivedFromSingleLocalRoot': True, 'grantsMaintenanceOrRemoteInput': False, 'nativeReady': False, 'posAccepted': False}
REQUEST049_FIELDS = ("schema","product","purpose","version","sequence",
    "publicationGuard","packageBytes","packageSha256","envelopeSha256",
    "initialSetupBytes","initialSetupSha256","activationRecordSha256",
    "compatibilityRecordSha256","expectedStableEnvelopeSha256")
RELEASE_BODY_049 = ("SSS-UI-PUBLISHER-V1: signed current-user UI assets only.\n\n"
    "SSS 0.4.9.0 加入兩個已知背景元件版本的完整比對與單次操作綁定；UI與首次安裝包分開提供。"
    "首次安裝包限尚無SSS更新根的電腦，不能用於接管既有安裝。"
    "本發行不提供本機專用維修工具，也不把UI簽章當成啟動元件維修授權。\n\n"
    "公開前須另完成實際維修啟用與已知受眾相容性資格。Windows7 POS、登入啟動、遠端連線、"
    "鍵鼠與持續操作仍須各自實機驗收；不是完整防火牆、NativeReady或操作授權，不宣稱99或100分。")

WAIT_FINAL_ASSETS = "WAIT_FINAL_INITIAL_AND_REPAIR_ASSETS_NOT_RUN"
# Exact initial/repair delivery tuples come from producer handoffs and Root.
# These delivery pins and the UI catalog do not prove actual repair activation.
INITIAL_BYTES = 849998
INITIAL_SHA256 = "335bc5b3a2142ba7280ba0aefbcc1b60558499c837029d586f4e41065fd2199b"
INITIAL_FILES = {
    'Install-SSS-Background.vbs': (306,'d1a614d9926ee6ddb86ede0ec575010fec93d70dd3399bee426a957aada86963'),
    'SSS.UiInitialSetup.exe': (61952,'35769fd587227b54a0c83e36c117c511bb718d4cec6646756633f51f6f82ee80'),
    'SSS.UiInitialSetup.exe.config': (138,'008d5c22af1b051c44f2fca2c8f0897cd5763ba687a55372cb480d2d7bc72337'),
    'initial-input/SSS-0.4.7.0-UI-x64.zip': (761226,'adf1130765f0af6c6700c11eaef74c0782a6e84edc8533a754709cd07b11f692'),
    'initial-input/sss-ui-update-v1.json': (2921,'fa00368aefab1da55b859f2e6515676284481c27f6283063dac1307f9db8bdea'),
    'initial-input/SSS.UiUpdateCoordinator.exe': (132608,'4784177d30d249830567b914efd22793d7241dcc0af6c834fbe4c3ad2170752e'),
    'initial-input/SSS.UiUpdateCoordinator.exe.config': (138,'008d5c22af1b051c44f2fca2c8f0897cd5763ba687a55372cb480d2d7bc72337'),
}
REPAIR_BYTES = 914735
REPAIR_SHA256 = "d0b4434e51d4d922b7067bb465dda3a5eb35d4ee98ba9b7df3c5011c40b36a96"
REPAIR_FILES = {
    'SSS.UiRepair.exe': (223744,'a462ad6606262cc047275011377426481845f7f2b020181946577155fbf1435e'),
    'SSS.UiRepair.exe.config': (138,'008d5c22af1b051c44f2fca2c8f0897cd5763ba687a55372cb480d2d7bc72337'),
    'Repair-SSS-Background.vbs': (357,'830da38e5a846244c25565c05e4ee13e96dc6a8a86e10378cc26c3ffd7c7e835'),
    'repair-input/SSS.UiUpdateCoordinator.exe': (132608,'4784177d30d249830567b914efd22793d7241dcc0af6c834fbe4c3ad2170752e'),
    'repair-input/SSS.UiUpdateCoordinator.exe.config': (138,'008d5c22af1b051c44f2fca2c8f0897cd5763ba687a55372cb480d2d7bc72337'),
    'repair-input/sss-ui-update-v1.json': (2921,'fa00368aefab1da55b859f2e6515676284481c27f6283063dac1307f9db8bdea'),
    'repair-input/SSS-0.4.7.0-UI-x64.zip': (761226,'adf1130765f0af6c6700c11eaef74c0782a6e84edc8533a754709cd07b11f692'),
}
ACTIVATION_NAME = "repair-activation-v1.json"
ACTIVATION_RECORD_BYTES = 1247
ACTIVATION_RECORD_SHA256 = "9336e58820af11d9f26f0b3b837f2378cc3611e860e13183ef0c76c917c96bbc"
SOURCE_ACTIVATION_RECEIPT_SHA256 = "b01f2d5eed23e701e13ab410987cc60784a4c5e6817a8623e541e18a8f52ce7f"
ACTIVATION_EXPECTED = {'schema': 1, 'purpose': 'SSS047.PublicationOrderActivationEvidence.v1', 'status': 'Reviewed047MaintenanceActivated', 'sourceReceiptSha256': 'b01f2d5eed23e701e13ab410987cc60784a4c5e6817a8623e541e18a8f52ce7f', 'sourceReceiptBytes': 3592, 'sourceObservedUtc': '2026-10-29T07:59:27.8704907Z', 'previousVersion': '0.4.6.0', 'version': '0.4.7.0', 'sequence': 2, 'catalogSha256': 'fa00368aefab1da55b859f2e6515676284481c27f6283063dac1307f9db8bdea', 'repairZipSha256': 'd0b4434e51d4d922b7067bb465dda3a5eb35d4ee98ba9b7df3c5011c40b36a96', 'bootstrapExecutableSha256': '4784177d30d249830567b914efd22793d7241dcc0af6c834fbe4c3ad2170752e', 'originalRootIdentityPreserved': True, 'ordinaryPackageAbsent': True, 'normalOldProductAndWorkerExited': True, 'retiredOriginalHistoryFileCount': 4, 'ownedJobTerminal': 'Cancelled', 'originalIoSettled': True, 'exclusionsReleased': True, 'installedSignedRuntimeCount': 11, 'ownRunReadback': True, 'ordinaryInstallerExitCode': 0, 'forcedTermination': False, 'machineRestarted': False, 'latestVerified': False, 'productLaunched': False, 'nativeReady': False, 'grantsMaintenanceOrRemoteInput': False, 'newFees': 0, 'paidCredits': 0}
KNOWN_UI_BYTES = 761226
KNOWN_UI_SHA256 = "adf1130765f0af6c6700c11eaef74c0782a6e84edc8533a754709cd07b11f692"
KNOWN_CATALOG_BYTES = 2921
KNOWN_CATALOG_SHA256 = "fa00368aefab1da55b859f2e6515676284481c27f6283063dac1307f9db8bdea"
KNOWN_BOOTSTRAP = {
    "SSS.UiUpdateCoordinator.exe": (132608,"4784177d30d249830567b914efd22793d7241dcc0af6c834fbe4c3ad2170752e"),
    "SSS.UiUpdateCoordinator.exe.config": (138,"008d5c22af1b051c44f2fca2c8f0897cd5763ba687a55372cb480d2d7bc72337"),
}
MAX_FILE = 16777216
MAX_ENVELOPE = 8192
MAX_JSON = 1048576
MAX_ASSETS = 200
RELEASE_BODY = ("SSS-UI-PUBLISHER-V1: signed current-user UI assets only.\n\n"
                "SSS 0.4.6.0 CurrentUser UI 更新通道；不是 NativeReady/C1 或操作授權。"
                "Windows7 POS、無人值守與持續鍵鼠操作仍待實機驗收，非100分交付。\n\n"
                "既有0.4.5須先正常選一次『結束SSS』，再由新背景更新流程接續；不強殺舊程序。"
                "新Run登入啟動登錄已讀回，但下次真登入自啟尚未測試；不是Native全功能驗收。")

RELEASE_BODY_047 = ("SSS-UI-PUBLISHER-V1: signed current-user UI assets only.\n\n"
    "SSS 0.4.7.0 維護修復：補齊 .NET Framework 4.8 中繼資料，並提供正常維護升級流程。\n\n"
    "首次安裝包只供尚無既有SSS更新根的電腦；既有0.4.6只使用專用 Background-Repair-From-0.4.6 修復包。"
    "UI簽章目錄只涵蓋UI套件，不能自行授權替換固定啟動元件。\n\n"
    "既有0.4.5與背景程序須依正常維護退出流程處理，不強制結束。"
    "Windows7 POS、登入啟動、連線、鍵鼠與持續操作仍待實機驗收；不是NativeReady/C1或操作授權，也不宣稱100分。")

def release_body(tag):
    """New047 version copy only; stable retains exact historical ownership."""
    return RELEASE_BODY_049 if tag == VERSION_TAG_049 else (RELEASE_BODY_048 if tag == VERSION_TAG_048 else (RELEASE_BODY_047 if tag == VERSION_TAG else RELEASE_BODY))

class PublishError(Exception):
    pass

def fail(code):
    raise PublishError(code)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def canonical(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")

def parse_json(data, limit):
    if type(data) is not bytes or not 1 <= len(data) <= limit:
        fail("json-size")
    try:
        return codec.decode(data)
    except (ValueError, UnicodeError, RecursionError):
        fail("json-format")

def exact(value, names):
    if type(value) is not dict or set(value) != set(names):
        fail("unexpected-fields")

def verify_envelope(data, current=True):
    try:
        return codec.verify_catalog(data, require_current=current)
    except (ValueError, UnicodeError, RecursionError, TypeError, OverflowError):
        fail("signed-catalog-invalid")

def read_local(path, maximum):
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 1 <= before.st_size <= maximum:
                fail("local-file-type-links-size")
            data = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
            if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or len(data) != before.st_size):
                fail("local-file-changed")
            return data
    except OSError:
        fail("local-file-read")

def verify_zip(data, catalog):
    if type(data) is not bytes or len(data) != catalog["packageBytes"] or sha(data) != catalog["packageSha256"]:
        fail("zip-package-binding")
    rows = {row["path"]: row for row in catalog["files"]}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) != 11 or {entry.filename for entry in entries} != set(rows):
                fail("zip-exact-eleven-files")
            seen, total = set(), 0
            for entry in entries:
                mode = entry.external_attr >> 16
                if (entry.filename in seen or entry.orig_filename != entry.filename or entry.is_dir() or
                        entry.flag_bits & 1 or entry.external_attr & 16 or
                        stat.S_IFMT(mode) not in (0, stat.S_IFREG) or
                        entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
                    fail("zip-file-type-or-duplicate")
                seen.add(entry.filename)
                row = rows[entry.filename]
                if entry.file_size != row["bytes"] or not 1 <= entry.file_size <= 8388608:
                    fail("zip-member-size")
                total += entry.file_size
                if total > MAX_FILE:
                    fail("zip-total-size")
                with archive.open(entry) as member:
                    raw = member.read(row["bytes"] + 1)
                if len(raw) != row["bytes"] or sha(raw) != row["sha256"]:
                    fail("zip-member-hash")
    except (zipfile.BadZipFile, RuntimeError, OSError, ValueError, NotImplementedError):
        fail("zip-invalid")

def verify_known_ui(package, envelope):
    """Real fixed24c UI vector only; never bootstrap repair authority."""
    if (len(package) != KNOWN_UI_BYTES or sha(package) != KNOWN_UI_SHA256 or
            len(envelope) != KNOWN_CATALOG_BYTES or sha(envelope) != KNOWN_CATALOG_SHA256):
        fail("known047-ui-vector-binding")
    catalog = verify_envelope(envelope)
    if catalog["version"] != VERSION or catalog["sequence"] != 2:
        fail("known047-catalog-purpose")
    verify_zip(package,catalog)
    return catalog

def verify_known_bootstrap(contents):
    """Exact public bytes only, no store write, installation or authority."""
    if type(contents) is not dict or set(contents) != set(KNOWN_BOOTSTRAP):
        fail("known047-bootstrap-inventory")
    for name,(size,digest) in KNOWN_BOOTSTRAP.items():
        data=contents[name]
        if type(data) is not bytes or len(data)!=size or sha(data)!=digest:
            fail("known047-bootstrap-tuple")

def verify_exact_delivery_zip(data, size, digest, files, label):
    """Only compiled approved exact7 bytes, never a caller-selected inventory."""
    if type(data) is not bytes or len(data)!=size or sha(data)!=digest:
        fail(label+"-approved-package-binding")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries=archive.infolist()
            if len(entries)!=7 or {entry.filename for entry in entries}!=set(files):
                fail(label+"-exact-seven-files")
            seen=set();total=0
            for entry in entries:
                expected_size,expected_hash=files[entry.filename]
                if (entry.filename in seen or entry.orig_filename!=entry.filename or entry.is_dir() or entry.flag_bits&1 or entry.external_attr&16 or
                        stat.S_IFMT(entry.external_attr>>16) not in (0,stat.S_IFREG) or
                        entry.compress_type not in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED) or entry.file_size!=expected_size or
                        not 1<=expected_size<=8388608):
                    fail(label+"-member-type-or-size")
                seen.add(entry.filename);total+=expected_size
                if total>MAX_FILE:fail(label+"-total-size")
                with archive.open(entry) as stream:raw=stream.read(expected_size+1)
                if len(raw)!=expected_size or sha(raw)!=expected_hash:
                    fail(label+"-member-hash")
    except (zipfile.BadZipFile,RuntimeError,OSError,ValueError,NotImplementedError):
        fail(label+"-zip-invalid")

def verify_final_initial_and_repair(initial, repair):
    # Exact producer-reviewed delivery packages are separate from the signed UI
    # catalog's authority. Nothing here executes a bootstrap or formal repair.
    verify_exact_delivery_zip(initial,INITIAL_BYTES,INITIAL_SHA256,INITIAL_FILES,"initial")
    verify_exact_delivery_zip(repair,REPAIR_BYTES,REPAIR_SHA256,REPAIR_FILES,"repair")

def require_actual_repair_activation(raw, request, catalog, envelope, repair):
    """Fixed redacted publication-order attestation, not a key/input grant.

    Root separately qualified the private actual receipt and retained it locally.
    Only these fixed public bytes/fields can satisfy this release-order check;
    no caller bool, root path, role, environment switch or arbitrary record does.
    """
    if type(raw) is not bytes or len(raw)!=ACTIVATION_RECORD_BYTES:
        fail("activation-record-size")
    if request.get("activationRecordSha256")!=ACTIVATION_RECORD_SHA256:
        fail("activation-record-request-pin")
    if sha(raw)!=ACTIVATION_RECORD_SHA256:
        fail("activation-record-byte-pin")
    value=parse_json(raw,4096)
    exact(value,ACTIVATION_EXPECTED)
    for name,expected in ACTIVATION_EXPECTED.items():
        if type(value[name]) is not type(expected) or value[name]!=expected:
            fail("activation-record-domain")
    if (value["purpose"]!="SSS047.PublicationOrderActivationEvidence.v1" or
            value["sourceReceiptSha256"]!=SOURCE_ACTIVATION_RECEIPT_SHA256 or value["sourceReceiptBytes"]!=3592 or
            value["version"]!=VERSION or value["version"]!=request["version"] or value["version"]!=catalog["version"] or
            value["sequence"]!=request["sequence"] or value["sequence"]!=catalog["sequence"] or
            value["catalogSha256"]!=sha(envelope) or value["catalogSha256"]!=request["envelopeSha256"] or
            value["repairZipSha256"]!=sha(repair) or value["repairZipSha256"]!=request["repairSha256"] or
            value["bootstrapExecutableSha256"]!=KNOWN_BOOTSTRAP["SSS.UiUpdateCoordinator.exe"][1] or
            value["bootstrapExecutableSha256"]!=REPAIR_FILES["repair-input/SSS.UiUpdateCoordinator.exe"][1] or
            catalog["keyId"]!=codec.KEY_ID or catalog["purpose"]!=codec.PURPOSE or catalog["profile"]!=codec.PROFILE or
            catalog["product"]!="SolarSystemShield" or catalog["channel"]!="stable"):
        fail("activation-record-bundle-binding")
    return value

def _require_metadata_only_renewal(request, catalog, package, envelope, initial, repair, activation):
    """Only this actual signed047/3 renewal; historic activation stays seq2."""
    if (request["sequence"]!=RENEWAL_SEQUENCE or catalog["sequence"]!=RENEWAL_SEQUENCE or
            request["version"]!=VERSION or catalog["version"]!=VERSION or
            len(envelope)!=RENEWAL_CATALOG_BYTES or sha(envelope)!=RENEWAL_CATALOG_SHA256 or
            request["expectedStableEnvelopeSha256"]!=KNOWN_CATALOG_SHA256):
        fail("renewal-fixed-target-or-old-pin")
    # Both complete ZIPs and exact7 inventories are immutable. No external flag
    # can disable currentness: current=False exists only for this pinned history.
    verify_final_initial_and_repair(initial,repair)
    baselines=[]
    for data,path in ((initial,"initial-input/sss-ui-update-v1.json"),(repair,"repair-input/sss-ui-update-v1.json")):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            with archive.open(path) as stream:baseline=stream.read(MAX_ENVELOPE+1)
        baselines.append(baseline)
    if (baselines[0]!=baselines[1] or len(baselines[0])!=KNOWN_CATALOG_BYTES or
            sha(baselines[0])!=KNOWN_CATALOG_SHA256):
        fail("renewal-embedded-baseline-conflict")
    baseline_raw=baselines[0]
    baseline=verify_envelope(baseline_raw,current=False)
    if baseline["version"]!=VERSION or baseline["sequence"]!=2:
        fail("renewal-historical-baseline-purpose")
    verify_zip(package,baseline)
    # Derived solely from proved baseline bytes, never a caller's history/root.
    historical_request={"activationRecordSha256":request["activationRecordSha256"],"version":baseline["version"],
                        "sequence":baseline["sequence"],"envelopeSha256":sha(baseline_raw),"repairSha256":sha(repair)}
    require_actual_repair_activation(activation,historical_request,baseline,baseline_raw,repair)
    fixed=codec.FIELDS-{"sequence","publishedUtcTicks","expiresUtcTicks","files"}
    if any(catalog[name]!=baseline[name] for name in fixed):
        fail("renewal-nonmetadata-field-change")
    require_advance(catalog,baseline)  # Existing strict same-URL/package/11 rule.
    # New metadata is always current, including idempotence and slow final checks.
    verify_envelope(envelope)

def _require_published_version_readonly(github, release, members):
    """No version create/upload/ensure/publish helper is reachable from renewal."""
    if release is None:
        fail("renewal-existing-published-version-required")
    current=github.release(release["id"])
    if current["tag_name"]!=VERSION_TAG or current["draft"]:
        fail("renewal-existing-published-version-required")
    assets=github.assets(current)
    if set(assets)!=set(VERSION_ASSET_NAMES):
        fail("renewal-version-inventory")
    for name in VERSION_ASSET_NAMES:
        github.asset_matches(assets[name],members[name])
        github.public_check(VERSION_TAG,name,members[name])

def validate_inputs(request_raw, package, envelope, initial, repair, activation):
    request = parse_json(request_raw, 4096)
    exact(request, ("schema", "version", "sequence", "packageBytes", "packageSha256", "envelopeSha256", "initialSetupBytes", "initialSetupSha256", "repairBytes", "repairSha256", "activationRecordSha256", "expectedStableEnvelopeSha256"))
    if (type(request["schema"]) is not int or request["schema"] != 1 or request["version"] != VERSION or
            type(request["sequence"]) is not int or not 1 <= request["sequence"] <= 2**63 - 1 or
            type(request["packageBytes"]) is not int or not 1 <= request["packageBytes"] <= MAX_FILE):
        fail("request-purpose")
    for field in ("packageSha256", "envelopeSha256"):
        if type(request[field]) is not str or not re.fullmatch(r"[0-9a-f]{64}", request[field]):
            fail("request-digest")
    old = request["expectedStableEnvelopeSha256"]
    if type(old) is not str or old and not re.fullmatch(r"[0-9a-f]{64}", old):
        fail("request-old-pin")
    if request["sequence"]!=RENEWAL_SEQUENCE:
        fail("renewal-sequence-required")
    catalog = verify_envelope(envelope)
    if (catalog["version"] != VERSION or catalog["sequence"] != request["sequence"] or
            len(envelope) > MAX_ENVELOPE or sha(envelope) != request["envelopeSha256"] or
            catalog["packageBytes"] != request["packageBytes"] or catalog["packageSha256"] != request["packageSha256"]):
        fail("request-catalog-binding")
    verify_zip(package,catalog)
    if (type(request["initialSetupBytes"]) is not int or request["initialSetupBytes"]!=INITIAL_BYTES or request["initialSetupSha256"]!=INITIAL_SHA256 or
            type(request["repairBytes"]) is not int or request["repairBytes"]!=REPAIR_BYTES or request["repairSha256"]!=REPAIR_SHA256):
        fail("initial-or-repair-request-pin")
    verify_final_initial_and_repair(initial,repair)
    _require_metadata_only_renewal(request,catalog,package,envelope,initial,repair,activation)
    return request, catalog, {PACKAGE_NAME:package, ENVELOPE_NAME:envelope, INITIAL_NAME:initial, REPAIR_NAME:repair, ACTIVATION_NAME:activation}

def _load_bundle_047(root):
    if INITIAL_FILES is None or REPAIR_FILES is None:
        fail(WAIT_FINAL_ASSETS)
    folder = root / "updates" / "sss-ui"
    for directory in (root, root / "updates", folder, folder / "payload"):
        if directory.is_symlink() or not directory.is_dir():
            fail("checkout-directory-type")
    return validate_inputs(read_local(folder / "publish-request.json", 4096),
                           read_local(folder / "payload" / PACKAGE_NAME, MAX_FILE),
                           read_local(folder / "payload" / ENVELOPE_NAME, MAX_ENVELOPE),
                           read_local(folder / "payload" / INITIAL_NAME, MAX_FILE),
                           read_local(folder / "payload" / REPAIR_NAME, MAX_FILE),
                           read_local(folder / ACTIVATION_NAME,4096))

# The following delivery transport is derived from the reviewed SSL publisher.

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHub:
    def __init__(self, token, receipt):
        if not token or any(c.isspace() for c in token):
            fail("ephemeral-workflow-token-required")
        self.token = token
        self.receipt = receipt
        self.deadline = time.monotonic() + 480
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def event(self, operation, **fields):
        value = dict(operation=operation, **fields)
        self.receipt["events"].append(value)
        # Preserve each known boundary in ordinary job logs even if a later
        # runner/job termination prevents the final aggregate receipt.
        print(json.dumps({"sssUiPublisherEvent": value}, ensure_ascii=True, separators=(",", ":")), flush=True)

    def fetch(self, url, limit, method="GET", body=None, authenticated=False,
              content_type=None, binary=False, public_redirect=False):
        """Token only on fixed API/uploads origins; never forward it on redirect."""
        for hop in range(6):
            parsed = urllib.parse.urlsplit(url)
            if parsed.scheme != "https" or parsed.port not in (None, 443) or parsed.username or parsed.password or parsed.fragment:
                fail("network-origin")
            if authenticated:
                if hop or parsed.netloc not in ("api.github.com", "uploads.github.com"):
                    fail("token-origin")
            elif parsed.hostname not in ("github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"):
                fail("public-origin")
            headers = {"User-Agent": "SSS-CurrentUser-UI-release-publisher-v1",
                       "Accept": "application/octet-stream" if binary else "application/vnd.github+json"}
            if authenticated:
                headers.update({"Authorization": "Bearer " + self.token,
                                "X-GitHub-Api-Version": API_VERSION})
            if content_type:
                headers["Content-Type"] = content_type
            request = urllib.request.Request(url, data=body, headers=headers, method=method)
            started = time.monotonic()
            if started >= self.deadline:
                fail("network-total-deadline")
            try:
                with self.opener.open(request, timeout=min(30, self.deadline-started)) as response:
                    chunks = []
                    count = 0
                    while True:
                        if time.monotonic() - started > 60 or time.monotonic() >= self.deadline:
                            fail("network-read-deadline")
                        chunk = response.read(min(65536, limit - count + 1))
                        if time.monotonic() >= self.deadline:
                            fail("network-total-deadline")
                        if not chunk:
                            break
                        count += len(chunk)
                        if count > limit:
                            fail("network-response-size")
                        chunks.append(chunk)
                    return b"".join(chunks)
            except urllib.error.HTTPError as error:
                status = error.code
                location = error.headers.get("Location")
                error.close()
                if method == "GET" and (public_redirect or binary) and status in (301, 302, 303, 307, 308) and location:
                    if hop == 5:
                        fail("network-redirect-limit")
                    url = urllib.parse.urljoin(url, location)
                    authenticated = False
                    continue
                fail("github-http-" + str(status))
            except (OSError, urllib.error.URLError, TimeoutError):
                fail("network-result-unknown")
        fail("network-redirect-limit")

    def api(self, path, method="GET", value=None):
        if path != "/repos/" + REPOSITORY and not path.startswith("/repos/" + REPOSITORY + "/"):
            fail("api-repository")
        suffix = path[len("/repos/"+REPOSITORY):]
        get_route = suffix == "" or suffix in ("/releases/tags/"+VERSION_TAG,"/releases/tags/"+VERSION_TAG_048,"/releases/tags/"+VERSION_TAG_049,"/releases/tags/"+STABLE_TAG) or re.fullmatch(r"/releases/[1-9][0-9]*(/assets\?per_page=100&page=[1-9][0-9]*)?",suffix)
        create = (method == "POST" and suffix == "/releases" and type(value) is dict and
                  set(value) == {"tag_name","target_commitish","name","body","draft","prerelease","make_latest"} and
                  value["tag_name"] in (VERSION_TAG,VERSION_TAG_048,VERSION_TAG_049,STABLE_TAG) and value["name"] == value["tag_name"] and
                  re.fullmatch(r"[0-9a-f]{40}",value["target_commitish"]) and value["body"] == release_body(value["tag_name"]) and
                  value["draft"] is True and value["prerelease"] is False and value["make_latest"] == "false")
        publish = method == "PATCH" and re.fullmatch(r"/releases/[1-9][0-9]*",suffix) and value == {"draft":False,"make_latest":"false"}
        rename = method == "PATCH" and re.fullmatch(r"/releases/assets/[1-9][0-9]*",suffix) and type(value) is dict and set(value) == {"name"} and allowed_feed_name(value["name"])
        if not ((method == "GET" and get_route and value is None) or create or publish or rename):
            fail("api-method-or-purpose")
        raw = None if value is None else canonical(value)
        data = self.fetch(API + path, MAX_JSON, method, raw, True,
                          "application/json" if raw is not None else None)
        return parse_json(data, MAX_JSON)

    def release(self, release_id):
        value = self.api("/repos/" + REPOSITORY + "/releases/" + str(release_id))
        return self.validate_release(value)

    def validate_release(self, value):
        if (not isinstance(value, dict) or type(value.get("id")) is not int or value["id"] < 1 or
                type(value.get("draft")) is not bool or type(value.get("immutable")) is not bool or
                value.get("prerelease") is not False or value.get("tag_name") not in (VERSION_TAG,VERSION_TAG_048,VERSION_TAG_049,STABLE_TAG) or
                value.get("name") != value["tag_name"] or value.get("body") != release_body(value["tag_name"])):
            fail("release-metadata-unknown")
        if value["immutable"] and value["tag_name"] == STABLE_TAG:
            fail("release-immutable-stop")
        return value

    def find_releases(self, tags):
        found = {}
        if set(tags) not in ({VERSION_TAG,STABLE_TAG},{VERSION_TAG_048,STABLE_TAG},{VERSION_TAG_049,STABLE_TAG}):
            fail("fixed-tags-required")
        for tag in (VERSION_TAG_049 if VERSION_TAG_049 in tags else (VERSION_TAG_048 if VERSION_TAG_048 in tags else VERSION_TAG),STABLE_TAG):
            try:
                value=self.validate_release(self.api("/repos/"+REPOSITORY+"/releases/tags/"+tag))
                if value["tag_name"] != tag:
                    fail("release-tag-changed")
                found[tag]=value
            except PublishError as error:
                if str(error) != "github-http-404":
                    raise
        return found

    def assets(self, release):
        result = {}
        for page in range(1, MAX_ASSETS // 100 + 1):
            values = self.api("/repos/" + REPOSITORY + "/releases/" + str(release["id"]) +
                              "/assets?per_page=100&page=" + str(page))
            if not isinstance(values, list) or len(values) > 100:
                fail("asset-list-shape")
            for value in values:
                if (not isinstance(value, dict) or type(value.get("id")) is not int or value["id"] < 1 or
                        not isinstance(value.get("name"), str) or value["name"] in result or
                        type(value.get("size")) is not int or value["size"] < 1 or value.get("state") != "uploaded"):
                    fail("asset-metadata-unknown")
                result[value["name"]] = value
            if len(values) < 100:
                return result
        fail("asset-list-capacity")

    def asset_bytes(self, asset, limit):
        data = self.fetch(API + "/repos/" + REPOSITORY + "/releases/assets/" + str(asset["id"]),
                          limit, authenticated=True, binary=True)
        if len(data) != asset["size"]:
            fail("asset-metadata-length-mismatch")
        return data

    def asset_matches(self, asset, expected):
        if asset["size"] != len(expected) or self.asset_bytes(asset, len(expected)) != expected:
            fail("existing-asset-bytes-conflict")

    def public_check(self, tag, name, expected):
        url = PUBLIC + urllib.parse.quote(tag, safe="") + "/" + urllib.parse.quote(name, safe="")
        data = self.fetch(url, len(expected), binary=True, public_redirect=True)
        if data != expected:
            fail("public-get-bytes-mismatch")
        self.event("public-get-verified", url=url, bytes=len(data), sha256=sha(data))

    def create_draft(self, tag, commit):
        self.event("draft-create-submitted", tag=tag, commit=commit)
        value = self.api("/repos/" + REPOSITORY + "/releases", "POST",
                         {"tag_name": tag, "target_commitish": commit, "name": tag,
                          "body": release_body(tag), "draft": True, "prerelease": False,
                          "make_latest": "false"})
        release = self.validate_release(value)
        if release["tag_name"] != tag or release["draft"] is not True:
            fail("created-release-shape")
        self.event("draft-created", tag=tag, releaseId=release["id"])
        return release

    def publish_draft(self, release):
        current = self.release(release["id"])
        if current.get("tag_name") != release["tag_name"]:
            fail("release-tag-changed")
        if current["draft"]:
            if current["immutable"]:
                fail("immutable-draft-refused")
            if current.get("body") != release_body(current["tag_name"]):
                fail("draft-not-owned-by-publisher")
            self.event("release-publish-submitted", tag=current["tag_name"], releaseId=current["id"])
            result = self.api("/repos/" + REPOSITORY + "/releases/" + str(current["id"]),
                              "PATCH", {"draft": False, "make_latest": "false"})
            # If repository immutability became enabled, this can publish an
            # immutable release. Never disable it, retry around it, or pretend
            # no external change happened. The receipt records the boundary.
            self.event("release-publish-returned", tag=current["tag_name"],
                       releaseId=current["id"], immutable=result.get("immutable") if isinstance(result, dict) else None)
            current = self.validate_release(result)
        return current

    def ensure_asset(self, release, name, data):
        current = self.release(release["id"])
        if current.get("tag_name") != release["tag_name"]:
            fail("release-tag-changed")
        if ((current["tag_name"] in (VERSION_TAG,VERSION_TAG_048,VERSION_TAG_049) and name not in version_release_asset_names(current["tag_name"])) or
                (current["tag_name"] == STABLE_TAG and not allowed_feed_name(name)) or
                type(data) is not bytes or not 1 <= len(data) <= (MAX_FILE if name in (PACKAGE_NAME,INITIAL_NAME,REPAIR_NAME,PACKAGE_NAME_048,INITIAL_NAME_048,PACKAGE_NAME_049,INITIAL_NAME_049) else MAX_ENVELOPE)):
            fail("upload-name-or-size")
        assets = self.assets(current)
        if name in assets:
            self.asset_matches(assets[name], data)
            self.event("asset-already-matches", name=name, assetId=assets[name]["id"], sha256=sha(data))
            return assets[name]
        if current.get("body") != release_body(current["tag_name"]):
            fail("draft-not-owned-by-publisher")
        if current["immutable"] or current["tag_name"] in (VERSION_TAG,VERSION_TAG_048,VERSION_TAG_049) and not current["draft"]:
            fail("immutable-version-or-published-missing-asset")
        url = UPLOADS + "/repos/" + REPOSITORY + "/releases/" + str(current["id"]) + "/assets?name=" + urllib.parse.quote(name, safe="")
        self.event("asset-upload-submitted", name=name, releaseId=current["id"], bytes=len(data), sha256=sha(data))
        result = parse_json(self.fetch(url, MAX_JSON, "POST", data, True, "application/octet-stream"), MAX_JSON)
        self.event("asset-upload-returned", name=name, releaseId=current["id"])
        after = self.assets(current).get(name)
        if not isinstance(result, dict) or after is None or result.get("id") != after["id"]:
            fail("uploaded-asset-identity-unknown")
        self.asset_matches(after, data)
        return after

    def rename(self, release, asset, before_name, after_name, expected, admission_envelope=None):
        if not allowed_feed_name(before_name) or not allowed_feed_name(after_name):
            fail("rename-name-purpose")
        current = self.release(release["id"])
        if current.get("tag_name") != STABLE_TAG or current["draft"] or current.get("body") != RELEASE_BODY:
            fail("stable-release-state")
        assets = self.assets(current)
        before = assets.get(before_name)
        if before is None or before["id"] != asset["id"] or after_name in assets:
            fail("rename-precondition-conflict")
        self.asset_matches(before, expected)
        # All preceding identity/byte reads can take time.  The candidate must
        # still be current at the final local boundary before archive/promote.
        # Safe restoration passes no admission candidate and retains old bytes.
        if admission_envelope is not None:
            verify_envelope(admission_envelope)
        self.event("asset-rename-submitted", assetId=before["id"], before=before_name, after=after_name, sha256=sha(expected))
        result = self.api("/repos/" + REPOSITORY + "/releases/assets/" + str(before["id"]),
                          "PATCH", {"name": after_name})
        self.event("asset-rename-returned", assetId=before["id"], before=before_name, after=after_name)
        after_assets = self.assets(current)
        after = after_assets.get(after_name)
        if (not isinstance(result, dict) or result.get("id") != before["id"] or
                after is None or after["id"] != before["id"] or before_name in after_assets):
            fail("rename-result-unknown")
        self.asset_matches(after, expected)
        return after


def pending_name(catalog,envelope):
    return "sss-ui-update-pending-v"+catalog["version"]+"-s"+str(catalog["sequence"])+"-"+sha(envelope)+".json"

def archived_name(catalog,envelope):
    return "sss-ui-update-archive-v"+catalog["version"]+"-s"+str(catalog["sequence"])+"-"+sha(envelope)+".json"

def allowed_feed_name(name):
    return type(name) is str and (name == ENVELOPE_NAME or re.fullmatch(r"sss-ui-update-(pending|archive)-v(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){3}-s[1-9][0-9]*-[0-9a-f]{64}\.json",name) is not None)

def require_advance(new,old):
    old_version=tuple(map(int,old["version"].split(".")))
    new_version=tuple(map(int,new["version"].split(".")))
    if new_version < old_version or new["sequence"] <= old["sequence"]:
        fail("stable-rollback-or-no-advance")
    vector=lambda value: sorted((r["path"],r["bytes"],r["sha256"]) for r in value["files"])
    if new_version == old_version and (new["packageUrl"],new["packageBytes"],new["packageSha256"],vector(new)) != (old["packageUrl"],old["packageBytes"],old["packageSha256"],vector(old)):
        fail("same-version-bits-change")

def stable_preflight(github,stable,request,catalog,envelope):
    expected=request["expectedStableEnvelopeSha256"]
    if stable is None:
        if expected:
            fail("expected-stable-missing")
        return None,None
    assets=github.assets(stable)
    if any(not allowed_feed_name(name) for name in assets):
        fail("stable-unknown-asset")
    fixed=assets.get(ENVELOPE_NAME)
    if fixed is not None:
        raw=github.asset_bytes(fixed,MAX_ENVELOPE)
        old=verify_envelope(raw,current=False)
        if raw == envelope:
            return None,fixed
        if sha(raw) != expected:
            fail("stable-old-request-pin")
        require_advance(catalog,old)
        if archived_name(old,raw) in assets:
            fail("stable-archive-conflict")
        return (old,raw,fixed,ENVELOPE_NAME),None
    if expected:
        matches=[]
        for name,asset in assets.items():
            if name.startswith("sss-ui-update-archive-"):
                raw=github.asset_bytes(asset,MAX_ENVELOPE)
                if sha(raw) == expected:
                    old=verify_envelope(raw,current=False)
                    if name != archived_name(old,raw):
                        fail("old-archive-name-binding")
                    matches.append((old,raw,asset,name))
        if len(matches) != 1 or pending_name(catalog,envelope) not in assets:
            fail("rotation-resume-unknown")
        require_advance(catalog,matches[0][0])
        return matches[0],None
    if any(name.startswith("sss-ui-update-archive-") or name != pending_name(catalog,envelope) for name in assets):
        fail("seed-with-existing-history")
    return None,None

def restore_old_if_safe(github,stable,old):
    if old is None:
        return
    catalog,raw,asset,_=old
    try:
        current=github.release(stable["id"])
        assets=github.assets(current)
        if ENVELOPE_NAME in assets:
            github.event("restore-skipped-fixed-present")
            return
        retained=assets.get(archived_name(catalog,raw))
        if retained is None or retained["id"] != asset["id"]:
            github.event("restore-skipped-identity-unknown")
            return
        github.asset_matches(retained,raw)
        github.rename(current,retained,archived_name(catalog,raw),ENVELOPE_NAME,raw)
        github.public_check(STABLE_TAG,ENVELOPE_NAME,raw)
        github.event("old-feed-restored",sha256=sha(raw))
    except PublishError as error:
        github.event("restore-not-confirmed",code=str(error))

def _publish_047(github,request,catalog,members,commit):
    if type(commit) is not str or re.fullmatch(r"[0-9a-f]{40}",commit) is None:
        fail("commit-format")
    if set(members) != {PACKAGE_NAME,ENVELOPE_NAME,INITIAL_NAME,REPAIR_NAME,ACTIVATION_NAME}:
        fail("fixed-five-inputs")
    # Revalidate signed bytes immediately before the first API call.
    request,actual,members=validate_inputs(canonical(request),members[PACKAGE_NAME],members[ENVELOPE_NAME],members[INITIAL_NAME],members[REPAIR_NAME],members[ACTIVATION_NAME])
    if actual != catalog:
        fail("catalog-object-not-verified-bytes")
    _require_metadata_only_renewal(request,actual,members[PACKAGE_NAME],members[ENVELOPE_NAME],members[INITIAL_NAME],members[REPAIR_NAME],members[ACTIVATION_NAME])  # Before first API.
    repo=github.api("/repos/"+REPOSITORY)
    if (type(repo) is not dict or repo.get("full_name") != REPOSITORY or repo.get("private") is not False or
            repo.get("default_branch") != "main" or repo.get("archived") is not False):
        fail("fixed-public-repository-required")
    envelope=members[ENVELOPE_NAME]
    releases=github.find_releases({VERSION_TAG,STABLE_TAG})
    stable=releases.get(STABLE_TAG)
    old,already=stable_preflight(github,stable,request,catalog,envelope)
    release=releases.get(VERSION_TAG)
    _require_published_version_readonly(github,release,members)
    if already is not None:
        github.public_check(STABLE_TAG,ENVELOPE_NAME,envelope)
        verify_envelope(envelope)
        return
    if stable is None:
        stable=github.create_draft(STABLE_TAG,commit)
    candidate=pending_name(catalog,envelope)
    pending=github.ensure_asset(stable,candidate,envelope)
    stable=github.publish_draft(stable)
    github.public_check(STABLE_TAG,candidate,envelope)
    verify_envelope(envelope)  # Never admit an expired candidate after a slow upload.
    old,already=stable_preflight(github,stable,request,catalog,envelope)
    if already is not None:
        github.public_check(STABLE_TAG,ENVELOPE_NAME,envelope)
        verify_envelope(envelope)
        return
    try:
        if old is not None and old[3] == ENVELOPE_NAME:
            verify_envelope(envelope)
            github.rename(stable,old[2],ENVELOPE_NAME,archived_name(old[0],old[1]),old[1],admission_envelope=envelope)
        verify_envelope(envelope)
        github.rename(stable,pending,candidate,ENVELOPE_NAME,envelope,admission_envelope=envelope)
        github.public_check(STABLE_TAG,ENVELOPE_NAME,envelope)
        verify_envelope(envelope)
        github.event("stable-feed-verified",sha256=sha(envelope),possibleTemporary404=True)
    except PublishError:
        restore_old_if_safe(github,stable,old)
        raise


def version_delivery_zip_names(version):
    if version == VERSION:
        return VERSION_ASSET_NAMES
    if version == VERSION_048:
        return (PACKAGE_NAME_048, INITIAL_NAME_048)
    if version == VERSION_049:
        return (PACKAGE_NAME_049, INITIAL_NAME_049)
    fail("fixed-version-required")

def version_release_asset_names(tag):
    if tag == VERSION_TAG:
        return VERSION_ASSET_NAMES
    if tag == VERSION_TAG_048:
        return (PACKAGE_NAME_048, INITIAL_NAME_048, ENVELOPE_NAME)
    if tag == VERSION_TAG_049:
        return (PACKAGE_NAME_049, INITIAL_NAME_049, ENVELOPE_NAME)
    fail("fixed-version-tag-required")

def require_version_inventory(tag, names):
    if set(names) != set(version_release_asset_names(tag)):
        fail("version-specific-inventory")

def require_actual048_activation(raw, request, catalog):
    # This unconditional default veto is before any API and is not overridable
    # by validation_only, caller records, booleans or historic047 authority.
    if (ACTIVATION048_RECORD_BYTES is None or
            ACTIVATION048_RECORD_SHA256 is None or ACTIVATION048_EXPECTED is None):
        fail(WAIT_ACTUAL048)
    if (type(raw) is not bytes or len(raw)!=ACTIVATION048_RECORD_BYTES or
            sha(raw)!=ACTIVATION048_RECORD_SHA256 or
            request["activationRecordSha256"]!=ACTIVATION048_RECORD_SHA256):
        fail("048-activation-record-byte-pin")
    value=parse_json(raw,4096)
    exact(value,ACTIVATION048_EXPECTED)
    if value!=ACTIVATION048_EXPECTED:
        fail("048-activation-record-domain")
    if (value["purpose"]!="SSS048.PublicationOrderActivationEvidence.v1" or
            value["status"]!="Reviewed048MaintenanceActivated" or
            value["previousVersion"]!=VERSION or value["previousSequence"]!=2 or
            value["version"]!=VERSION_048 or value["sequence"]!=4 or
            value["catalogSha256"]!=CATALOG048_SHA256 or
            value["catalogSha256"]!=request["envelopeSha256"]):
        fail("048-activation-target-binding")
    for name in ("sourceQualified","actualActivation","durableCancellationPresent",
            "originalIoSettled","handlesSettled","originalRootIdentityPreserved",
            "ordinaryPackageAbsent","exclusionsReleased","ownRunReadback"):
        if value[name] is not True:fail("048-activation-required-state")
    for name in ("forcedTermination","machineRestarted","latestVerified",
            "sssUiLaunchedByMaintenance","sslOrPosOperationStarted","nativeReady",
            "grantsMaintenanceOrRemoteInput"):
        if value[name] is not False:fail("048-activation-not-other-authority")
    if (value["bootstrapExecutableSha256"]!="b457d95ccf64e711e20704bb85a5ca04b66384ebb26ed989b34c8838c6727b8c" or
            value["bootstrapConfigSha256"]!="008d5c22af1b051c44f2fca2c8f0897cd5763ba687a55372cb480d2d7bc72337" or
            value["originalCurrentVersionAtQuiescence"]!=VERSION or
            value["originalCurrentSequenceAtQuiescence"]!=2 or
            type(value["oldProcessNativeExitCode"]) is not int or value["oldProcessNativeExitCode"]!=0 or
            type(value["ownedWorkerNativeExitCode"]) is not int or value["ownedWorkerNativeExitCode"] not in (16,18) or
            value["ownedJobTerminal"] not in ("Cancelled","Failed","WaitingForNetwork") or
            value["originalFailedHistoryArchivedFileCount"]!=3 or
            value["originalLedgerBackupFileCount"]!=5 or
            value["installedSignedRuntimeCount"]!=11 or
            type(value["maintenanceDoctorMainExitCode"]) is not int or value["maintenanceDoctorMainExitCode"]!=0):
        fail("048-activation-maintenance-state")
    if (type(value["sourceReceiptSha256"]) is not str or not re.fullmatch("[0-9a-f]{64}",value["sourceReceiptSha256"]) or
            type(value["sourceReceiptBytes"]) is not int or not 1<=value["sourceReceiptBytes"]<=1048576 or
            type(value["sourceObservedUtc"]) is not str or not value["sourceObservedUtc"].endswith("Z")):
        fail("048-source-receipt-commitment")

def validate048_inputs(request_raw, package, envelope, initial, activation=None, *, validation_only=False):
    if type(validation_only) is not bool:fail("validation-only-type")
    request=parse_json(request_raw,4096)
    exact(request,REQUEST048_FIELDS)
    if (type(request["schema"]) is not int or request["schema"]!=1 or
            request["product"]!="SolarSystemShield" or
            request["purpose"]!="SSS048.PublicationRequest.v1" or
            request["version"]!=VERSION_048 or type(request["sequence"]) is not int or request["sequence"]!=4):
        fail("048-request-purpose")
    if request["publicationGuard"] not in (WAIT_ACTUAL048,"ACTUAL_REPAIR_ACTIVATION_PINNED"):
        fail("048-publication-guard")
    if (type(request["packageBytes"]) is not int or request["packageBytes"]!=UI048_BYTES or
            request["packageSha256"]!=UI048_SHA256 or request["envelopeSha256"]!=CATALOG048_SHA256 or
            type(request["initialSetupBytes"]) is not int or request["initialSetupBytes"]!=INITIAL048_BYTES or
            request["initialSetupSha256"]!=INITIAL048_SHA256 or
            request["expectedStableEnvelopeSha256"]!=PREDECESSOR048_SHA256):
        fail("048-request-fixed-pins")
    if (type(request["activationRecordSha256"]) is not str or
            request["activationRecordSha256"]!=WAIT_ACTUAL048 and
            not re.fullmatch("[0-9a-f]{64}",request["activationRecordSha256"])):
        fail("048-activation-request-format")
    if len(envelope)!=CATALOG048_BYTES or sha(envelope)!=CATALOG048_SHA256:
        fail("048-catalog-exact-tuple")
    catalog=verify_envelope(envelope)
    if catalog["version"]!=VERSION_048 or catalog["sequence"]!=4:
        fail("048-catalog-purpose")
    verify_zip(package,catalog)
    verify_exact_delivery_zip(initial,INITIAL048_BYTES,INITIAL048_SHA256,INITIAL048_FILES,"initial048")
    members={PACKAGE_NAME_048:package,ENVELOPE_NAME:envelope,INITIAL_NAME_048:initial,ACTIVATION_NAME:activation}
    if not validation_only:
        if request["publicationGuard"]!= "ACTUAL_REPAIR_ACTIVATION_PINNED":
            fail(WAIT_ACTUAL048)
        require_actual048_activation(activation,request,catalog)
    return request,catalog,members

def load_bundle(root, *, validation_only=False):
    folder=root/"updates"/"sss-ui"
    request_raw=read_local(folder/"publish-request.json",4096)
    request=parse_json(request_raw,4096)
    if request.get("version")==VERSION_048:fail(SUPERSEDED048)
    if request.get("version")!=VERSION_049:
        return _load_bundle_047(root)
    # Before reading payload, genuine049 must have been independently qualified.
    # No048 bytes, guessed artifact or caller pin can satisfy these constants.
    _require049_assets_bound()
    for directory in (root,root/"updates",folder,folder/"payload049"):
        if directory.is_symlink() or not directory.is_dir():fail("checkout-directory-type")
    expected={PACKAGE_NAME_049,INITIAL_NAME_049,ENVELOPE_NAME}
    if {p.name for p in (folder/"payload049").iterdir()}!=expected:fail("049-payload-exact-three")
    activation=compatibility=None
    if ACTIVATION049_RECORD_SHA256 is not None:
        activation=read_local(folder/ACTIVATION_NAME,4096)
    if COMPATIBILITY049_RECORD_SHA256 is not None:
        compatibility=read_local(folder/COMPATIBILITY049_NAME,4096)
    return validate049_inputs(request_raw,
        read_local(folder/"payload049"/PACKAGE_NAME_049,MAX_FILE),
        read_local(folder/"payload049"/ENVELOPE_NAME,MAX_ENVELOPE),
        read_local(folder/"payload049"/INITIAL_NAME_049,MAX_FILE),
        activation,compatibility,validation_only=validation_only)

def _publish048(github,request,catalog,members,commit):
    fail(SUPERSEDED048)
    if type(commit) is not str or re.fullmatch("[0-9a-f]{40}",commit) is None:fail("commit-format")
    if set(members)!={PACKAGE_NAME_048,INITIAL_NAME_048,ENVELOPE_NAME,ACTIVATION_NAME}:fail("048-fixed-four-inputs")
    request,actual,members=validate048_inputs(canonical(request),members[PACKAGE_NAME_048],
        members[ENVELOPE_NAME],members[INITIAL_NAME_048],members[ACTIVATION_NAME])
    if actual!=catalog:fail("catalog-object-not-verified-bytes")
    # validate048_inputs above always requires the actual activation record.
    # There is no validation_only argument on any public path.
    repo=github.api("/repos/"+REPOSITORY)
    if (type(repo) is not dict or repo.get("full_name")!=REPOSITORY or repo.get("private") is not False or
            repo.get("default_branch")!="main" or repo.get("archived") is not False):fail("fixed-public-repository-required")
    envelope=members[ENVELOPE_NAME]
    releases=github.find_releases({VERSION_TAG_048,STABLE_TAG})
    stable=releases.get(STABLE_TAG)
    old,already=stable_preflight(github,stable,request,catalog,envelope)
    release=releases.get(VERSION_TAG_048)
    if release is None:release=github.create_draft(VERSION_TAG_048,commit)
    existing=github.assets(release)
    wanted=set(version_release_asset_names(VERSION_TAG_048))
    if not set(existing).issubset(wanted) or not release["draft"] and set(existing)!=wanted:
        fail("048-version-inventory")
    for name in version_release_asset_names(VERSION_TAG_048):
        github.ensure_asset(release,name,members[name])
    release=github.publish_draft(release)
    require_version_inventory(VERSION_TAG_048,github.assets(release))
    for name in version_release_asset_names(VERSION_TAG_048):
        github.public_check(VERSION_TAG_048,name,members[name])
    verify_envelope(envelope)
    if already is not None:
        github.public_check(STABLE_TAG,ENVELOPE_NAME,envelope);verify_envelope(envelope);return
    if stable is None:stable=github.create_draft(STABLE_TAG,commit)
    candidate=pending_name(catalog,envelope)
    pending=github.ensure_asset(stable,candidate,envelope)
    stable=github.publish_draft(stable)
    github.public_check(STABLE_TAG,candidate,envelope)
    verify_envelope(envelope)
    old,already=stable_preflight(github,stable,request,catalog,envelope)
    if already is not None:
        github.public_check(STABLE_TAG,ENVELOPE_NAME,envelope);verify_envelope(envelope);return
    try:
        if old is not None and old[3]==ENVELOPE_NAME:
            verify_envelope(envelope)
            github.rename(stable,old[2],ENVELOPE_NAME,archived_name(old[0],old[1]),old[1],admission_envelope=envelope)
        verify_envelope(envelope)
        github.rename(stable,pending,candidate,ENVELOPE_NAME,envelope,admission_envelope=envelope)
        github.public_check(STABLE_TAG,ENVELOPE_NAME,envelope);verify_envelope(envelope)
        github.event("stable-feed-verified",sha256=sha(envelope),possibleTemporary404=True)
    except PublishError:
        restore_old_if_safe(github,stable,old);raise

def publish(github,request,catalog,members,commit):
    if request.get("version")==VERSION_048:fail(SUPERSEDED048)
    if request.get("version")==VERSION_049:
        return _publish049(github,request,catalog,members,commit)
    return _publish_047(github,request,catalog,members,commit)


def _require049_assets_bound():
    values=(UI049_BYTES,UI049_SHA256,CATALOG049_BYTES,CATALOG049_SHA256,
        INITIAL049_BYTES,INITIAL049_SHA256,INITIAL049_FILES,
        BOOTSTRAP049_EXECUTABLE_SHA256,BOOTSTRAP049_CONFIG_SHA256,
        ASSET049_PRODUCER_COMMITMENT)
    if any(value is None for value in values):fail(WAIT_ASSETS049)
    for value in (UI049_BYTES,CATALOG049_BYTES,INITIAL049_BYTES):
        if type(value) is not int or not 1<=value<=MAX_FILE:fail("049-bound-size")
    for value in (UI049_SHA256,CATALOG049_SHA256,INITIAL049_SHA256,
            BOOTSTRAP049_EXECUTABLE_SHA256,BOOTSTRAP049_CONFIG_SHA256):
        if type(value) is not str or re.fullmatch("[0-9a-f]{64}",value) is None:fail("049-bound-digest")
    if type(INITIAL049_FILES) is not dict or len(INITIAL049_FILES)!=7:fail("049-initial-exact-seven-unbound")
    exact(ASSET049_PRODUCER_COMMITMENT,("productionSourceQualificationSha256",
        "catalogProducerQualificationSha256","initialProducerQualificationSha256",
        "independentGenuineVectorQualificationSha256"))
    if any(value is None for value in ASSET049_PRODUCER_COMMITMENT.values()):
        fail(WAIT_SOURCE049)
    for value in ASSET049_PRODUCER_COMMITMENT.values():
        if type(value) is not str or re.fullmatch("[0-9a-f]{64}",value) is None:fail("049-producer-commitment")

def require_actual049_compatibility(raw,request,catalog):
    if (COMPATIBILITY049_RECORD_BYTES is None or COMPATIBILITY049_RECORD_SHA256 is None or
            COMPATIBILITY049_EXPECTED is None):fail(WAIT_COMPATIBILITY049)
    if (type(raw) is not bytes or len(raw)!=COMPATIBILITY049_RECORD_BYTES or
            sha(raw)!=COMPATIBILITY049_RECORD_SHA256 or
            request["compatibilityRecordSha256"]!=COMPATIBILITY049_RECORD_SHA256):
        fail("049-compatibility-byte-pin")
    value=parse_json(raw,4096)
    exact(value,COMPATIBILITY049_EXPECTED)
    if value!=COMPATIBILITY049_EXPECTED:fail("049-compatibility-domain")
    if (value["purpose"]!="SSS049.AudienceMigrationCompatibilityEvidence.v1" or
            value["status"]!="Reviewed049KnownAudienceCompatible" or
            value["version"]!=VERSION_049 or type(value["sequence"]) is not int or value["sequence"]!=5 or
            value["catalogSha256"]!=CATALOG049_SHA256 or value["catalogSha256"]!=request["envelopeSha256"] or
            value["packageSha256"]!=UI049_SHA256 or value["initialSetupSha256"]!=INITIAL049_SHA256 or
            value["audienceScope"]!="EXACT_KNOWN_R6_R7_TUPLES_ONLY" or
            type(value["qualifiedKnownBootstrapTupleCount"]) is not int or value["qualifiedKnownBootstrapTupleCount"]!=2):
        fail("049-compatibility-target")
    for name in ("productionSourceQualified","completeKnownTupleMatchingQualified",
            "singleBindingPerOperationQualified","unknownOrMixedTupleRejected",
            "existing047AudienceQualified","freshInitialExistingRootRejected",
            "notDerivedFromSingleLocalRoot"):
        if value[name] is not True:fail("049-compatibility-required")
    for name in ("grantsMaintenanceOrRemoteInput","nativeReady","posAccepted"):
        if value[name] is not False:fail("049-compatibility-not-operation-grant")
    if (type(value["sourceReceiptSha256"]) is not str or re.fullmatch("[0-9a-f]{64}",value["sourceReceiptSha256"]) is None or
            type(value["sourceReceiptBytes"]) is not int or not 1<=value["sourceReceiptBytes"]<=MAX_JSON or
            type(value["sourceObservedUtc"]) is not str or not value["sourceObservedUtc"].endswith("Z")):
        fail("049-compatibility-source-commitment")

def require_actual049_activation(raw, request, catalog):
    # This unconditional default veto is before any API and is not overridable
    # by validation_only, caller records, booleans or historic047 authority.
    if (ACTIVATION049_RECORD_BYTES is None or
            ACTIVATION049_RECORD_SHA256 is None or ACTIVATION049_EXPECTED is None):
        fail(WAIT_ACTUAL049)
    if (type(raw) is not bytes or len(raw)!=ACTIVATION049_RECORD_BYTES or
            sha(raw)!=ACTIVATION049_RECORD_SHA256 or
            request["activationRecordSha256"]!=ACTIVATION049_RECORD_SHA256):
        fail("049-activation-record-byte-pin")
    value=parse_json(raw,4096)
    exact(value,ACTIVATION049_EXPECTED)
    if value!=ACTIVATION049_EXPECTED:
        fail("049-activation-record-domain")
    if (value["purpose"]!="SSS049.PublicationOrderActivationEvidence.v1" or
            value["status"]!="Reviewed049MaintenanceActivated" or
            value["previousVersion"]!=VERSION or value["previousSequence"]!=2 or
            value["version"]!=VERSION_049 or value["sequence"]!=5 or
            value["catalogSha256"]!=CATALOG049_SHA256 or
            value["catalogSha256"]!=request["envelopeSha256"]):
        fail("049-activation-target-binding")
    for name in ("sourceQualified","actualActivation","durableCancellationPresent",
            "originalIoSettled","handlesSettled","originalRootIdentityPreserved",
            "ordinaryPackageAbsent","exclusionsReleased","ownRunReadback"):
        if value[name] is not True:fail("049-activation-required-state")
    for name in ("forcedTermination","machineRestarted","latestVerified",
            "sssUiLaunchedByMaintenance","sslOrPosOperationStarted","nativeReady",
            "grantsMaintenanceOrRemoteInput"):
        if value[name] is not False:fail("049-activation-not-other-authority")
    if (value["bootstrapExecutableSha256"]!=BOOTSTRAP049_EXECUTABLE_SHA256 or
            value["bootstrapConfigSha256"]!=BOOTSTRAP049_CONFIG_SHA256 or
            value["originalCurrentVersionAtQuiescence"]!=VERSION or
            value["originalCurrentSequenceAtQuiescence"]!=2 or
            type(value["oldProcessNativeExitCode"]) is not int or value["oldProcessNativeExitCode"]!=0 or
            type(value["ownedWorkerNativeExitCode"]) is not int or value["ownedWorkerNativeExitCode"] not in (16,18) or
            value["ownedJobTerminal"] not in ("Cancelled","Failed","WaitingForNetwork") or
            value["originalFailedHistoryArchivedFileCount"]!=3 or
            value["originalLedgerBackupFileCount"]!=5 or
            value["installedSignedRuntimeCount"]!=11 or
            type(value["maintenanceDoctorMainExitCode"]) is not int or value["maintenanceDoctorMainExitCode"]!=0):
        fail("049-activation-maintenance-state")
    if (type(value["sourceReceiptSha256"]) is not str or not re.fullmatch("[0-9a-f]{64}",value["sourceReceiptSha256"]) or
            type(value["sourceReceiptBytes"]) is not int or not 1<=value["sourceReceiptBytes"]<=1048576 or
            type(value["sourceObservedUtc"]) is not str or not value["sourceObservedUtc"].endswith("Z")):
        fail("049-source-receipt-commitment")

def validate049_inputs(request_raw, package, envelope, initial, activation=None, compatibility=None, *, validation_only=False):
    if type(validation_only) is not bool:fail("validation-only-type")
    request=parse_json(request_raw,4096)
    exact(request,REQUEST049_FIELDS)
    if (type(request["schema"]) is not int or request["schema"]!=1 or
            request["product"]!="SolarSystemShield" or
            request["purpose"]!="SSS049.PublicationRequest.v1" or
            request["version"]!=VERSION_049 or type(request["sequence"]) is not int or request["sequence"]!=5):
        fail("049-request-purpose")
    _require049_assets_bound()
    if request["publicationGuard"] not in (WAIT_PUBLICATION049,"ACTUAL_REPAIR_ACTIVATION_AND_AUDIENCE_PINNED"):
        fail("049-publication-guard")
    if (type(request["packageBytes"]) is not int or request["packageBytes"]!=UI049_BYTES or
            request["packageSha256"]!=UI049_SHA256 or request["envelopeSha256"]!=CATALOG049_SHA256 or
            type(request["initialSetupBytes"]) is not int or request["initialSetupBytes"]!=INITIAL049_BYTES or
            request["initialSetupSha256"]!=INITIAL049_SHA256 or
            request["expectedStableEnvelopeSha256"]!=PREDECESSOR049_SHA256):
        fail("049-request-fixed-pins")
    if (type(request["activationRecordSha256"]) is not str or
            request["activationRecordSha256"]!=WAIT_ACTUAL049 and
            not re.fullmatch("[0-9a-f]{64}",request["activationRecordSha256"])):
        fail("049-activation-request-format")
    if (request["compatibilityRecordSha256"]!=WAIT_COMPATIBILITY049 and
            (type(request["compatibilityRecordSha256"]) is not str or re.fullmatch("[0-9a-f]{64}",request["compatibilityRecordSha256"]) is None)):
        fail("049-compatibility-request-format")
    if len(envelope)!=CATALOG049_BYTES or sha(envelope)!=CATALOG049_SHA256:
        fail("049-catalog-exact-tuple")
    catalog=verify_envelope(envelope)
    if catalog["version"]!=VERSION_049 or catalog["sequence"]!=5:
        fail("049-catalog-purpose")
    verify_zip(package,catalog)
    verify_exact_delivery_zip(initial,INITIAL049_BYTES,INITIAL049_SHA256,INITIAL049_FILES,"initial049")
    members={PACKAGE_NAME_049:package,ENVELOPE_NAME:envelope,INITIAL_NAME_049:initial,ACTIVATION_NAME:activation,COMPATIBILITY049_NAME:compatibility}
    if not validation_only:
        if request["publicationGuard"]!= "ACTUAL_REPAIR_ACTIVATION_AND_AUDIENCE_PINNED":
            fail(WAIT_ACTUAL049)
        require_actual049_activation(activation,request,catalog)
        require_actual049_compatibility(compatibility,request,catalog)
    return request,catalog,members

def _publish049(github,request,catalog,members,commit):
    if type(commit) is not str or re.fullmatch("[0-9a-f]{40}",commit) is None:fail("commit-format")
    if set(members)!={PACKAGE_NAME_049,INITIAL_NAME_049,ENVELOPE_NAME,ACTIVATION_NAME,COMPATIBILITY049_NAME}:fail("049-fixed-five-inputs")
    request,actual,members=validate049_inputs(canonical(request),members[PACKAGE_NAME_049],
        members[ENVELOPE_NAME],members[INITIAL_NAME_049],members[ACTIVATION_NAME],members[COMPATIBILITY049_NAME])
    if actual!=catalog:fail("catalog-object-not-verified-bytes")
    # validate049_inputs above always requires the actual activation record.
    # There is no validation_only argument on any public path.
    repo=github.api("/repos/"+REPOSITORY)
    if (type(repo) is not dict or repo.get("full_name")!=REPOSITORY or repo.get("private") is not False or
            repo.get("default_branch")!="main" or repo.get("archived") is not False):fail("fixed-public-repository-required")
    envelope=members[ENVELOPE_NAME]
    releases=github.find_releases({VERSION_TAG_049,STABLE_TAG})
    stable=releases.get(STABLE_TAG)
    old,already=stable_preflight(github,stable,request,catalog,envelope)
    release=releases.get(VERSION_TAG_049)
    if release is None:release=github.create_draft(VERSION_TAG_049,commit)
    existing=github.assets(release)
    wanted=set(version_release_asset_names(VERSION_TAG_049))
    if not set(existing).issubset(wanted) or not release["draft"] and set(existing)!=wanted:
        fail("049-version-inventory")
    for name in version_release_asset_names(VERSION_TAG_049):
        github.ensure_asset(release,name,members[name])
    release=github.publish_draft(release)
    require_version_inventory(VERSION_TAG_049,github.assets(release))
    for name in version_release_asset_names(VERSION_TAG_049):
        github.public_check(VERSION_TAG_049,name,members[name])
    verify_envelope(envelope)
    if already is not None:
        github.public_check(STABLE_TAG,ENVELOPE_NAME,envelope);verify_envelope(envelope);return
    if stable is None:stable=github.create_draft(STABLE_TAG,commit)
    candidate=pending_name(catalog,envelope)
    pending=github.ensure_asset(stable,candidate,envelope)
    stable=github.publish_draft(stable)
    github.public_check(STABLE_TAG,candidate,envelope)
    verify_envelope(envelope)
    old,already=stable_preflight(github,stable,request,catalog,envelope)
    if already is not None:
        github.public_check(STABLE_TAG,ENVELOPE_NAME,envelope);verify_envelope(envelope);return
    try:
        if old is not None and old[3]==ENVELOPE_NAME:
            verify_envelope(envelope)
            github.rename(stable,old[2],ENVELOPE_NAME,archived_name(old[0],old[1]),old[1],admission_envelope=envelope)
        verify_envelope(envelope)
        github.rename(stable,pending,candidate,ENVELOPE_NAME,envelope,admission_envelope=envelope)
        github.public_check(STABLE_TAG,ENVELOPE_NAME,envelope);verify_envelope(envelope)
        github.event("stable-feed-verified",sha256=sha(envelope),possibleTemporary404=True)
    except PublishError:
        restore_old_if_safe(github,stable,old);raise

def publication_version_tag(version):
    if version==VERSION_049:return VERSION_TAG_049
    if version==VERSION:return VERSION_TAG
    fail("publication-version-not-current-or-historical047")

def publication_package_name(version):
    if version==VERSION_049:return PACKAGE_NAME_049
    if version==VERSION:return PACKAGE_NAME
    fail("publication-version-not-current-or-historical047")

def main():
    receipt={"schema":1,"repository":REPOSITORY,"tags":[VERSION_TAG,STABLE_TAG],"status":"not-started","events":[],"productExecuted":False,"nativeReady":False,"remoteInputGranted":False}
    try:
        if (len(sys.argv)!=1 or os.environ.get("GITHUB_ACTIONS")!="true" or os.environ.get("GITHUB_EVENT_NAME")!="push" or
                os.environ.get("GITHUB_REPOSITORY")!=REPOSITORY or os.environ.get("GITHUB_REF")!="refs/heads/main"):
            fail("fixed-public-main-push-required")
        root=Path(os.environ.get("GITHUB_WORKSPACE","")).resolve(strict=True)
        if Path(__file__).resolve(strict=True) != root/"tools"/"sss_ui_release_publisher.py":
            fail("fixed-checkout-layout")
        request,catalog,members=load_bundle(root)
        receipt["tags"]=[publication_version_tag(catalog["version"]),STABLE_TAG]
        receipt.update({"version":catalog["version"],"sequence":catalog["sequence"],"envelopeSha256":sha(members[ENVELOPE_NAME]),"packageSha256":sha(members[publication_package_name(catalog["version"])])})
        publish(GitHub(os.environ.get("GITHUB_TOKEN",""),receipt),request,catalog,members,os.environ.get("GITHUB_SHA",""))
        verify_envelope(members[ENVELOPE_NAME])
        receipt["status"]="public-readback-verified"
    except PublishError as error:
        receipt.update({"status":"failed-or-external-state-unknown","code":str(error)})
    except Exception as error:
        receipt.update({"status":"failed-or-external-state-unknown","code":"unexpected-"+type(error).__name__})
    print(json.dumps(receipt,ensure_ascii=True,separators=(",",":")))
    return 0 if receipt["status"] == "public-readback-verified" else 1

if __name__ == "__main__":
    sys.exit(main())


