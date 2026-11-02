"""One reviewed SSL076 existing-six recovery. No sign/build/install or version writes."""
import hashlib
import json
import os
from pathlib import Path
import types
import urllib.parse

REPO = "sasta02001-hash/solar-system-link"
TAG = "ssl-v0.7.6.0"
RELEASE = 431598285
VERSION_COMMIT = "fa4b7210a334fe38f37d30b9d5d64994ecda93bb"
STABLE = 426495684
OLD_ASSET = 689014662
OLD_SHA = "6da56f8c8f06ca1311df847d053efb4e0b493186e30add387de60aea95e7ac16"
NEW_SHA = "827d9329e04a6e9d1d0e5ecd5bbe443f85af059ddddf7ac554247bcd29236d06"
PUB_SHA = "3d5a1c52cf8dac662028c0d1e7d5e2a49d37c590d84aea1d9ddf83135f53b262"
PENDING = "ssl-update-pending-v0.7.6.0-s11-" + NEW_SHA + ".json"
ARCHIVE = "ssl-update-archive-v0.7.4.0-s9-" + OLD_SHA + ".json"
ASSETS = (
    ("SSS.RemoteAuthorization.dll", 702122939, 47616, "3bedc1d4a786a01cea89fe98363a4220a843d963b2c16023b09d46cc81e58968"),
    ("SSS.RemoteManagement.exe", 702123034, 173056, "b0edbc5f4a5df3282275e58640e1de7cc1850e256a15e358953cbbe4f012fc1a"),
    ("SSS.RemoteManagement.exe.config", 702123190, 317, "600bb2b8a2eafa824a422c2431f289913297e9ed02aee321663919eb02ee85da"),
    ("SolarSystemLink.Controller.exe", 702123282, 2500608, "99c8fed2128fa5912ebdddc9b01a3716ff101f2ca89a58c2d9841178fe9dbb11"),
    ("SolarSystemLink.Controller.exe.config", 702123385, 349, "b8402739500962d939890d74df8065caed11331c4ded36bbd3934d003df500f7"),
    ("SolarSystemLink.Remote.dll", 702123483, 2195968, "4131d453ab60423bfbdee31dd8e889f7f2670906eafc4e887a370ac053088a2a"),
)
REQUEST = {"schema": 1, "purpose": "SSL076.ExistingSixOnly.StableRecovery.v1", "version": "0.7.6.0", "sequence": "11",
           "existingReleaseId": RELEASE, "existingVersionCommit": VERSION_COMMIT,
           "expectedStableReleaseId": STABLE, "expectedOldStableAssetId": OLD_ASSET,
           "expectedOldStableEnvelopeSha256": OLD_SHA, "signedEnvelopeSha256": NEW_SHA,
           "originalPublisherSha256": PUB_SHA,
           "originalArchiveSha256": "ff5fa9f8733200a473d9a8b77885538a1d7a23ee4903e50cb5dbf25e39452166",
           "assets": [{"name": n, "id": i, "bytes": b, "sha256": h} for n, i, b, h in ASSETS]}


class RecoveryError(Exception):
    pass


def demand(ok, code):
    if not ok:
        raise RecoveryError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def validate_request(raw):
    demand(raw == canonical(REQUEST), "recovery-fixed-request-only")


def validate_version_snapshot(pub, release, assets):
    demand(release.get("id") == RELEASE and release.get("tag_name") == TAG and release.get("draft") is False and
           release.get("prerelease") is False and release.get("immutable") is False and
           release.get("target_commitish") == VERSION_COMMIT and release.get("body") == pub.version_body(TAG), "recovery-version-release-changed")
    demand(set(assets) == {x[0] for x in ASSETS}, "recovery-exact-existing-six")
    for name, asset_id, size, value in ASSETS:
        item = assets[name]
        demand(type(item.get("id")) is int and item["id"] == asset_id and item.get("name") == name and
               type(item.get("size")) is int and item["size"] == size and item.get("state") == "uploaded" and
               item.get("digest") == "sha256:" + value, "recovery-existing-asset-identity-changed")


def permit_mutation(admitted, pending_id, method, url, body, envelope):
    demand(admitted is True, "recovery-not-admitted")
    parsed = urllib.parse.urlsplit(url)
    demand(parsed.scheme == "https" and not parsed.username and not parsed.password and not parsed.fragment, "recovery-mutation-url")
    if method == "POST":
        demand(parsed.netloc == "uploads.github.com" and parsed.path == "/repos/" + REPO + "/releases/" + str(STABLE) + "/assets" and
               urllib.parse.parse_qsl(parsed.query) == [("name", PENDING)] and
               type(body) is bytes and len(body) == 1712 and digest(body) == NEW_SHA and body == envelope, "recovery-only-fixed-stable-pending-upload")
        return
    demand(method == "PATCH" and parsed.netloc == "api.github.com" and not parsed.query, "recovery-no-release-or-version-mutation")
    root = "/repos/" + REPO + "/releases/assets/"
    demand(parsed.path not in {root + str(item[1]) for item in ASSETS}, "recovery-version-asset-never-renamed")
    if parsed.path == root + str(OLD_ASSET):
        demand(body in (canonical({"name": ARCHIVE}), canonical({"name": "ssl-update-v1.json"})), "recovery-old-asset-only-archive-or-restore")
        return
    demand(type(pending_id) is int and pending_id > 0 and pending_id != OLD_ASSET and
           parsed.path == root + str(pending_id) and body == canonical({"name": "ssl-update-v1.json"}), "recovery-confirmed-pending-only-promote")


def client_class(pub):
    class ExistingSixOnly(pub.GitHub):
        def __init__(self, token, receipt, envelope):
            super().__init__(token, receipt)
            self._envelope = envelope
            self._admitted = False
            self._pending_id = None
            self._pending_started = False
            self._pending_post_attempted = False

        def fetch(self, url, limit, method="GET", body=None, authenticated=False, content_type=None, binary=False, public_redirect=False):
            if method != "GET":
                permit_mutation(self._admitted, self._pending_id, method, url, body, self._envelope)
                if method == "POST":
                    demand(not self._pending_post_attempted, "recovery-no-second-pending-post")
                    self._pending_post_attempted = True
            return super().fetch(url, limit, method, body, authenticated, content_type, binary, public_redirect)

        def create_draft(self, tag, commit):
            raise RecoveryError("recovery-never-create-release-or-tag")

        def publish_draft(self, release):
            current = self.release(release["id"])
            demand(current.get("id") in (RELEASE, STABLE) and current.get("draft") is False, "recovery-never-publish-draft")
            if current["id"] == RELEASE:
                validate_version_snapshot(pub, current, self.assets(current))
            else:
                demand(current.get("tag_name") == "ssl-stable" and current.get("body") == pub.RELEASE_BODY, "recovery-stable-owner-changed")
            return current

        def ensure_asset(self, release, name, data):
            if release.get("id") == RELEASE:
                current = self.release(RELEASE)
                assets = self.assets(current)
                validate_version_snapshot(pub, current, assets)
                demand(name in assets, "recovery-no-missing-version-asset-upload")
                self.asset_matches(assets[name], data)
                self.event("recovery-existing-version-read-only", name=name, assetId=assets[name]["id"])
                return assets[name]
            demand(self._admitted is True and release.get("id") == STABLE and name == PENDING and data == self._envelope and
                   not self._pending_started, "recovery-only-one-stable-pending")
            self._pending_started = True
            demand(PENDING not in self.assets(self.release(STABLE)), "recovery-pending-raced-stop")
            item = super().ensure_asset(release, name, data)
            demand(self._pending_post_attempted and type(item.get("id")) is int and item["id"] != OLD_ASSET and
                   item["id"] not in {row[1] for row in ASSETS},
                   "recovery-pending-not-confirmed-from-this-attempt")
            self._pending_id = item["id"]
            return item

        def admit_existing(self, request, manifest, members):
            release = self.release(RELEASE)
            assets = self.assets(release)
            validate_version_snapshot(pub, release, assets)
            for name, _, size, value in ASSETS:
                raw = members[name]
                demand(len(raw) == size and digest(raw) == value, "recovery-genuine-six-local-pin")
                self.asset_matches(assets[name], raw)
                self.public_check(TAG, name, raw)
            stable = self.release(STABLE)
            demand(stable.get("tag_name") == "ssl-stable" and stable.get("draft") is False and stable.get("body") == pub.RELEASE_BODY,
                   "recovery-stable-release-owner")
            current = self.assets(stable)
            old = current.get("ssl-update-v1.json")
            demand(old is not None and old.get("id") == OLD_ASSET and PENDING not in current and ARCHIVE not in current,
                   "recovery-initial-stable-state-changed")
            old_raw = self.asset_bytes(old, pub.MAX_ENVELOPE)
            demand(len(old_raw) == 1712 and digest(old_raw) == OLD_SHA, "recovery-old-stable-bytes")
            self.public_check("ssl-stable", "ssl-update-v1.json", old_raw)
            pub.stable_preflight(self, stable, request, manifest, self._envelope)
            self._admitted = True
            self.event("recovery-existing-six-and-old-stable-qualified", releaseId=RELEASE, stableId=STABLE)
    return ExistingSixOnly


def load_fixed_publisher(root):
    path = root / "tools/ssl_release_publisher.py"
    raw = path.read_bytes()
    demand(len(raw) == 38567 and digest(raw) == PUB_SHA, "recovery-original-publisher-pin")
    module = types.ModuleType("ssl076_original_reviewed_publisher")
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def main():
    receipt = {"schema": 1, "repository": REPO, "status": "not-started", "events": [],
               "recoveryPurpose": REQUEST["purpose"], "versionMutationAuthorized": False,
               "remoteControlAcceptance": "not-established", "paidServicesInvoked": False}
    pub = None
    try:
        demand(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("GITHUB_EVENT_NAME") == "push" and
               os.environ.get("GITHUB_REPOSITORY") == REPO and os.environ.get("GITHUB_REF") == "refs/heads/main" and
               os.environ.get("GITHUB_WORKFLOW") == "Recover existing SSL076 six assets and stable feed", "recovery-fixed-new-workflow-only")
        root = Path(__file__).resolve().parents[1]
        demand(root == Path(os.environ.get("GITHUB_WORKSPACE", "")).resolve(strict=True), "recovery-fixed-checkout")
        pub = load_fixed_publisher(root)
        validate_request(pub.read_local(root / "updates/ssl076-recovery/publish-request.json", 4096))
        request, manifest, members = pub.load_bundle(root)
        demand(request["archiveSha256"] == REQUEST["originalArchiveSha256"] and request["expectedStableEnvelopeSha256"] == OLD_SHA and
               request["envelopeSha256"] == NEW_SHA and manifest["version"] == "0.7.6.0" and manifest["sequence"] == "11" and
               digest(members[pub.ENVELOPE_NAME]) == NEW_SHA, "recovery-original-signed-request-bundle")
        token = os.environ.get("GITHUB_TOKEN", "")
        demand(bool(token) and not any(c.isspace() for c in token), "recovery-ephemeral-workflow-token")
        client = client_class(pub)(token, receipt, members[pub.ENVELOPE_NAME])
        client.admit_existing(request, manifest, members)
        pub.publish(client, request, manifest, members, VERSION_COMMIT)
        receipt["status"] = "existing-six-and-stable-public-get-verified"
        pub.emit_receipt(receipt)
        return 0
    except Exception as error:
        receipt["status"] = "failed-or-external-state-unknown-stop-no-retry"
        receipt["code"] = str(error) if isinstance(error, RecoveryError) or (pub and isinstance(error, pub.PublishError)) else "unexpected-" + type(error).__name__
        if pub:
            pub.emit_receipt(receipt)
        else:
            print(json.dumps(receipt, separators=(",", ":")), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
