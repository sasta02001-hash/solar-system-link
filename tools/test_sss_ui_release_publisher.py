"""Three grouped metadata-renewal delta cases; no true HTTP/product/root."""
import ast
import copy
import hashlib
import io
import json
from pathlib import Path
import socket
from unittest.mock import patch
import urllib.parse
import urllib.request
import zipfile
import sss_ui_release_publisher as p
def forbidden(*args,**kwargs):raise AssertionError("Real network forbidden")
socket.socket=forbidden;socket.create_connection=forbidden
urllib.request.urlopen=forbidden;urllib.request.OpenerDirector.open=forbidden
ROOT=Path(__file__).resolve().parent
STAGE=ROOT.parent if ROOT.name=="tools" else ROOT/"repository-staging"
COMMIT="a"*40
def funcs(tree):
    result={}
    for node in tree.body:
        if isinstance(node,ast.FunctionDef):result[node.name]=ast.dump(node)
        elif isinstance(node,ast.ClassDef):
            for child in node.body:
                if isinstance(child,ast.FunctionDef):result[node.name+"."+child.name]=ast.dump(child)
    return result
def denied(action,code):
    try:action()
    except p.PublishError as error:assert str(error)==code,(str(error),code)
    else:raise AssertionError("Expected refusal: "+code)
PROTECTED_AST = {'release_body': '77a145733342a6bbfa4482b1eecbf642c90f0d03ea065541549d186fd452bf83', 'fail': '405c438d0b16008e47c9c1b0838043c0f8ea4f51b88cdac89953ea4f4c04ff7f', 'sha': '87191a4a1d6f9f9404d87bb99ad2beeb2e96ca92d77fbcf51ac3740484fdfda6', 'canonical': '66031fdc6e9a26d38d835d2478409427d5a0c60e92525b7b83af097bfaa5ab5f', 'parse_json': 'c006c926ab340a828d99a64c103510ee37c2f2b8e38145d55419b364c86b7675', 'exact': 'f7c599a29a9ba70149cccbb07db0f917f5a9be6dafdae2b4c5554e945d5f0ba3', 'verify_envelope': '3b81447b3bf0e57e331305be3a7d5ac0e60863672fdf9ff83b2c70100d2d6bdd', 'read_local': 'fd2133f0bff14a5d0dcec682dd6d8d9264dd7888d017aa83f089e930e9dd732b', 'verify_zip': '4545d68910aacc6d486027845208202ff4013b7e2bfa9660c3fa1400170e6975', 'verify_known_ui': '4596efe528836852b0ce660d21806444ce33a6b42cce5e634daaec4aea0115f9', 'verify_known_bootstrap': 'a52199220178565a160dec18d663356ce0377afae4f01d74be728493abd5cd7a', 'verify_exact_delivery_zip': '5171d67c65c89ae95111b1e417f9e0db0c2fe92a8e6f376986aed665c897184f', 'verify_final_initial_and_repair': 'cd8dc65ec080d8b0f7cc890017f2e8f75610c534da42b59b2b4a64cf7f8269e5', 'require_actual_repair_activation': '996727f110021464b4839aaec5526023d8c68fac442d4a992cd545016240914f', 'load_bundle': '4062d826af84d07bfacdc157cb359a1bcc45770351802931d45dc34a6478501e', 'NoRedirect.redirect_request': '31941de59306b0430a7f327b1df97ea8f0d56975bbfb0249ea521b4740e90a48', 'GitHub.__init__': 'b95e5dacfd5a80b8f9b0cdf0b367d3d1ce797c05d5a1fab2751a1a49ce925e9a', 'GitHub.event': '6708d4fc1b6fc51b27957395e316b3a1a582adcbf3b5533d2de8f1215963d1e9', 'GitHub.fetch': 'a8998d75d99d22777e9a8987d8121193c0eb2867dd6241561870a453b1cbb6af', 'GitHub.api': '39c7b2273233581ac32b955056f2e8a05086d31df4b203f4f82ac16086e17905', 'GitHub.release': '3b951f28a58f5c8e9f9e135a803bd2a7769f8410d7995a4b09effb4f3178abfa', 'GitHub.validate_release': 'dde0da7886ecca6d3f5d345aa821657f9371b1c5d336a32a7248de74e9390d40', 'GitHub.find_releases': '637d29d4bd18e564badf421540ef140d44efbb756d4a76ab9c7c5970d32bf02f', 'GitHub.assets': '18c537262f744f138a4c4a8c92dec9da67323838f2cd3e4470e41cec4e8f0783', 'GitHub.asset_bytes': '4cb6a93ede2a5f1858639637ac369f710d86bab951bf7dba130a43d0c5074b7d', 'GitHub.asset_matches': '2909967fe52d212b0d5fa02d8a970d32d44779cc0b4f68d71aecf30d7e487a71', 'GitHub.public_check': '209c3201a02bf3a343d23e970ecd70dab81ef310539b65709316a2ae93be1ad6', 'GitHub.create_draft': '8cfac675bdc7f7212a88c1b9e11bb37b685643862d405f7479168d93e731bb50', 'GitHub.publish_draft': '874ace40a8e386f5cd37e1501a0b58c646d4c5d5263809a0fe9290258926c721', 'GitHub.ensure_asset': 'e6a1b7aa335dc7e31170dd369e1250e8032a48ca98be8fa0000e7bdec5653504', 'GitHub.rename': 'f60f0bd422ca1532ca7ef89e7bdd0d82e690b1852d41803c704d219fbc2921f8', 'pending_name': '278dfa81a833108892ba5651333b41e4cc1035106082677ff84260cb902c754a', 'archived_name': 'f85ede3e41815ac7548b127a3cb0cf2898e9d2404267c94f642775c80db3f3f3', 'allowed_feed_name': '7f75e6dfafad81d7439a160ac5179a92087dbb4ae69c699a445cb9ccf9168fb6', 'require_advance': 'c37b8adf6e693e58203ddc51b1f55e5702bda9a8b8b1726b0f45de88d502c278', 'stable_preflight': 'e1a759d2632ba0c02e79310673b0662abffbcdc1f8c1b69e17bb107c808f499d', 'restore_old_if_safe': '222c9d48f97d9ea24169d6dde1867bdb0f4f3cd097e4006b0ec3f84ee971c21d', 'main': 'e9dc22904e2f350b0f8d382b41354298f33bf5e478e48a8a4900ca7c7965f5b4'}

class MemoryGitHub(p.GitHub):
    """Actual GitHub adapter/state machine, replacing only its HTTP boundary."""
    def __init__(self):
        super().__init__("owned-dummy-not-a-credential",{"events":[]})
        self.releases={};self.data={};self.assets_by_release={};self.next=100
        self.calls=[];self.mutations=[];self.unknown_upload=False;self.unknown_rename=False;self.bad_public=False
    def event(self,operation,**fields):
        self.receipt["events"].append(dict(operation=operation,**fields))
    def fetch(self,url,limit,method="GET",body=None,authenticated=False,content_type=None,binary=False,public_redirect=False):
        self.calls.append((url,method))
        parsed=urllib.parse.urlsplit(url);path=parsed.path;value=None if body is None or content_type=="application/octet-stream" else json.loads(body)
        prefix="/repos/"+p.REPOSITORY
        def encoded(item):
            raw=p.canonical(item)
            if len(raw)>limit:raise p.PublishError("owned-response-bound")
            return raw
        def release_id():return int(path.split("/")[-1])
        def get_asset(asset_id):
            for rid,assets in self.assets_by_release.items():
                for name,item in assets.items():
                    if item["id"]==asset_id:return rid,name,item
            raise p.PublishError("github-http-404")
        if parsed.hostname=="github.com":
            tag,name=path.split("/releases/download/",1)[1].split("/",1);tag=urllib.parse.unquote(tag);name=urllib.parse.unquote(name)
            release=next(r for r in self.releases.values() if r["tag_name"]==tag)
            if release["draft"]:raise AssertionError("draft public read")
            item=self.assets_by_release[release["id"]][name]
            return b"bad" if self.bad_public else self.data[item["id"]]
        if method=="GET" and path==prefix:return encoded({"full_name":p.REPOSITORY,"private":False,"archived":False,"default_branch":"main"})
        if method=="GET" and "/releases/tags/" in path:
            tag=path.rsplit("/",1)[1]
            found=[r for r in self.releases.values() if r["tag_name"]==tag]
            if not found:raise p.PublishError("github-http-404")
            return encoded(found[0])
        if method=="POST" and path==prefix+"/releases":
            self.next+=1;rid=self.next
            item=dict(value,id=rid,immutable=False);self.releases[rid]=item;self.assets_by_release[rid]={}
            self.mutations.append(("create",value["tag_name"]))
            return encoded(item)
        if method=="GET" and "/releases/assets/" in path:
            return self.data[release_id()]
        if method=="GET" and path.endswith("/assets"):
            return encoded(list(self.assets_by_release[int(path.split("/")[-2])].values()))
        if method=="GET":return encoded(self.releases[release_id()])
        if parsed.hostname=="uploads.github.com":
            rid=int(path.split("/")[-2]);name=urllib.parse.parse_qs(parsed.query)["name"][0]
            if name in self.assets_by_release[rid]:raise AssertionError("asset overwrite")
            self.next+=1;item={"id":self.next,"name":name,"size":len(body),"state":"uploaded"}
            self.assets_by_release[rid][name]=item;self.data[item["id"]]=body;self.mutations.append(("upload",name))
            if self.unknown_upload:raise p.PublishError("owned-unknown-after-upload")
            return encoded(item)
        if method=="PATCH" and "/releases/assets/" in path:
            rid,name,item=get_asset(release_id());after=value["name"]
            if after in self.assets_by_release[rid]:raise AssertionError("rename overwrite")
            del self.assets_by_release[rid][name];item["name"]=after;self.assets_by_release[rid][after]=item
            self.mutations.append(("rename",name,after))
            if self.unknown_rename:raise p.PublishError("owned-unknown-after-rename")
            return encoded(item)
        if method=="PATCH":
            item=self.releases[release_id()];item.update(value);self.mutations.append(("publish",item["tag_name"]))
            return encoded(item)
        raise AssertionError("unexpected HTTP operation")
    def fixed(self,tag):return next(r for r in self.releases.values() if r["tag_name"]==tag)

def fixture(members,base_raw):
    client=MemoryGitHub()
    version=client.create_draft(p.VERSION_TAG,COMMIT)
    for name in p.VERSION_ASSET_NAMES:client.ensure_asset(version,name,members[name])
    version=client.publish_draft(version);client.releases[version["id"]]["immutable"]=True
    stable=client.create_draft(p.STABLE_TAG,COMMIT);client.ensure_asset(stable,p.ENVELOPE_NAME,base_raw);client.publish_draft(stable)
    create=client.create_draft;ensure=client.ensure_asset;draft=client.publish_draft
    def no_create(tag,commit):raise AssertionError("Renewal must not create any release")
    def no_version_ensure(release,name,data):
        assert release["tag_name"]!=p.VERSION_TAG,"Version ensure helper entered"
        return ensure(release,name,data)
    def no_version_draft(release):
        assert release["tag_name"]!=p.VERSION_TAG,"Version publish-draft helper entered"
        return draft(release)
    client.create_draft=no_create;client.ensure_asset=no_version_ensure;client.publish_draft=no_version_draft
    client.calls.clear();client.mutations.clear();return client

def test_real_renewal_old_expired_new_fresh_idempotence_and_expired_new(request,catalog,members,base_raw,base):
    current=funcs(ast.parse(Path(p.__file__).read_text(encoding="utf-8-sig")))
    for name,digest in PROTECTED_AST.items():assert hashlib.sha256(current[name].encode()).hexdigest()==digest,name
    assert set(current)-set(PROTECTED_AST)=={"validate_inputs","publish","_require_metadata_only_renewal","_require_published_version_readonly"}
    assert request["sequence"]==3 and request["expectedStableEnvelopeSha256"]==p.KNOWN_CATALOG_SHA256
    assert p.sha(base_raw)==p.KNOWN_CATALOG_SHA256 and base["sequence"]==2
    assert p.sha(members[p.ENVELOPE_NAME])=="369a16eb4efeca86a7c3f0152e62ba15841692bdca031bafe842b75b82ec39db"
    assert p.sha(members[p.ACTIVATION_NAME])=="9336e58820af11d9f26f0b3b837f2378cc3611e860e13183ef0c76c917c96bbc"
    tick=base["expiresUtcTicks"]+1
    assert catalog["publishedUtcTicks"]<=tick<catalog["expiresUtcTicks"]
    with patch.object(p.codec.time,"time_ns",return_value=(tick-621355968000000000)*100):
        denied(lambda:p.verify_envelope(base_raw),"signed-catalog-invalid")
        client=fixture(members,base_raw)
        version=client.fixed(p.VERSION_TAG)
        before=tuple((name,client.asset_bytes(item,p.MAX_FILE)) for name,item in sorted(client.assets(version).items()))
        body=client.release(version["id"])["body"]
        p.publish(client,request,catalog,members,COMMIT)
        assert all(row[0] in ("upload","rename") for row in client.mutations)
        assert [row for row in client.mutations if row[0]=="upload"][0][1].startswith("sss-ui-update-pending-")
        assert before==tuple((name,client.asset_bytes(item,p.MAX_FILE)) for name,item in sorted(client.assets(version).items()))
        assert client.release(version["id"])["body"]==body
        stable=client.fixed(p.STABLE_TAG)
        assert client.asset_bytes(client.assets(stable)[p.ENVELOPE_NAME],8192)==members[p.ENVELOPE_NAME]
        client.calls.clear();client.mutations.clear();p.publish(client,request,catalog,members,COMMIT)
        assert client.mutations==[]
        # Idempotence must still demand all pre-existing version bytes.
        del client.assets_by_release[version["id"]][p.PACKAGE_NAME]
        denied(lambda:p.publish(client,request,catalog,members,COMMIT),"renewal-version-inventory")
        assert client.mutations==[]
    client=fixture(members,base_raw)
    with patch.object(p.codec.time,"time_ns",return_value=(catalog["expiresUtcTicks"]-621355968000000000)*100):
        denied(lambda:p.publish(client,request,catalog,members,COMMIT),"signed-catalog-invalid")
    assert client.calls==[] and client.mutations==[]

def test_version_missing_draft_inventory_body_or_bytes_never_mutated(request,catalog,members,base_raw):
    for variant in ("missing-release","draft","missing-zip","extra-asset","wrong-body","wrong-bytes"):
        client=fixture(members,base_raw);version=client.fixed(p.VERSION_TAG);assets=client.assets_by_release[version["id"]]
        code="renewal-version-inventory"
        if variant=="missing-release":
            del client.releases[version["id"]];code="renewal-existing-published-version-required"
        elif variant=="draft":
            client.releases[version["id"]]["draft"]=True;code="renewal-existing-published-version-required"
        elif variant=="missing-zip":del assets[p.INITIAL_NAME]
        elif variant=="extra-asset":assets["owned-extra"]={"id":9999,"name":"owned-extra","size":1,"state":"uploaded"};client.data[9999]=b"x"
        elif variant=="wrong-body":client.releases[version["id"]]["body"]="not publisher owned";code="release-metadata-unknown"
        else:
            item=assets[p.PACKAGE_NAME];data=client.data[item["id"]];client.data[item["id"]]=bytes([data[0]^1])+data[1:];code="existing-asset-bytes-conflict"
        denied(lambda:p.publish(client,request,catalog,members,COMMIT),code)
        assert client.mutations==[],variant

def test_fixed_cas_activation_and_nonmetadata_identity_fail_before_api(request,catalog,members,base_raw):
    client=fixture(members,base_raw)
    for pin in ("","0"*64):
        changed=dict(request);changed["expectedStableEnvelopeSha256"]=pin
        denied(lambda:p.publish(client,changed,catalog,members,COMMIT),"renewal-fixed-target-or-old-pin")
    changed=dict(request);changed["sequence"]=2
    denied(lambda:p.publish(client,changed,catalog,members,COMMIT),"renewal-sequence-required")
    changed=dict(members);changed[p.ACTIVATION_NAME]=b"true"
    denied(lambda:p.publish(client,request,catalog,changed,COMMIT),"activation-record-size")
    # These are explicit negative data-only seams, not invented valid signatures.
    synthetic=copy.deepcopy(catalog);synthetic["packageUrl"]+="/owned-change"
    denied(lambda:p._require_metadata_only_renewal(request,synthetic,members[p.PACKAGE_NAME],members[p.ENVELOPE_NAME],members[p.INITIAL_NAME],members[p.REPAIR_NAME],members[p.ACTIVATION_NAME]),"renewal-nonmetadata-field-change")
    synthetic=copy.deepcopy(catalog);synthetic["files"][0]["sha256"]="0"*64
    denied(lambda:p._require_metadata_only_renewal(request,synthetic,members[p.PACKAGE_NAME],members[p.ENVELOPE_NAME],members[p.INITIAL_NAME],members[p.REPAIR_NAME],members[p.ACTIVATION_NAME]),"same-version-bits-change")
    assert client.calls==[] and client.mutations==[]

if __name__=="__main__":
    request,catalog,members=p.load_bundle(STAGE)
    with zipfile.ZipFile(io.BytesIO(members[p.INITIAL_NAME])) as z:base_raw=z.read("initial-input/sss-ui-update-v1.json")
    with zipfile.ZipFile(io.BytesIO(members[p.REPAIR_NAME])) as z:assert z.read("repair-input/sss-ui-update-v1.json")==base_raw
    base=p.verify_envelope(base_raw,current=False)
    test_real_renewal_old_expired_new_fresh_idempotence_and_expired_new(request,catalog,members,base_raw,base)
    test_version_missing_draft_inventory_body_or_bytes_never_mutated(request,catalog,members,base_raw)
    test_fixed_cas_activation_and_nonmetadata_identity_fail_before_api(request,catalog,members,base_raw)
    print(json.dumps({"ownedRenewalResult":{"passed":3,"failed":0,"realSeq3SignatureAndHistoricalSeq2Baseline":True,"bothPinnedEmbeddedBaselinesIdentical":True,"oldExpiredOnlyHistoricalNewAlwaysFresh":True,"newSame3IdempotentStillReadsAllThreeZips":True,"versionMissingDraftInventoryBodyOrBytesRejected":True,"versionCreateEnsurePublishHelpersNeverEntered":True,"versionZipsAndBodyNeverMutated":True,"old19OrExpiry7OrRepairSuitesRerun":False,"negativeDataOnlySeamsNotValidSignatures":True,"realHTTP":False,"productOrRootOrMainExecuted":False,"actualPublication":False,"newFees":0,"paidCredits":0,"exactTaskTokens":None}},separators=(",",":")))
