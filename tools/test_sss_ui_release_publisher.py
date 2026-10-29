"""Local data-only s1 crypto/ZIP checks plus explicitly synthetic memory HTTP.
No signing/new key, real HTTP, extraction, installation or product execution.
"""
import copy
import io
import json
from pathlib import Path
import socket
import stat
import sys
import unittest
from unittest.mock import patch
import urllib.error
import urllib.parse
import zipfile
import sss_ui_release_publisher as p

DATA=Path(__file__).resolve().parent/"public-data"
if not DATA.is_dir():
    DATA=Path(__file__).resolve().parent.parent/"updates"/"sss-ui"/"payload"
ZIP=(DATA/p.PACKAGE_NAME).read_bytes()
ENV=(DATA/p.ENVELOPE_NAME).read_bytes()
INITIAL=(DATA/p.INITIAL_NAME).read_bytes()
CAT=p.verify_envelope(ENV)
COMMIT="a"*40

def request(catalog=CAT,envelope=ENV,old=""):
    return {"schema":1,"version":p.VERSION,"sequence":catalog["sequence"],"packageBytes":catalog["packageBytes"],
            "packageSha256":catalog["packageSha256"],"envelopeSha256":p.sha(envelope),
            "initialSetupBytes":p.INITIAL_BYTES,"initialSetupSha256":p.INITIAL_SHA256,"expectedStableEnvelopeSha256":old}

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

def publish(client,catalog=CAT,envelope=ENV,old=""):
    return p.publish(client,request(catalog,envelope,old),catalog,{p.PACKAGE_NAME:ZIP,p.ENVELOPE_NAME:envelope,p.INITIAL_NAME:INITIAL},COMMIT)

class ActualPublicData(unittest.TestCase):
    def test_actual_repository_stage_fixed_request_and_two_payloads(self):
        if DATA.name != "payload":
            self.skipTest("stage-only filesystem layout case")
        req,catalog,members=p.load_bundle(DATA.parents[2])
        self.assertEqual(req["expectedStableEnvelopeSha256"],"")
        self.assertEqual(catalog,CAT)
        self.assertEqual(members,{p.PACKAGE_NAME:ZIP,p.ENVELOPE_NAME:ENV,p.INITIAL_NAME:INITIAL})
    def test_actual_s1_fixed24c_signature_and_exact_eleven_zip(self):
        self.assertEqual((len(ZIP),p.sha(ZIP)),(760763,"9e4879305f790bdbeb67deb29319146550a95983f0e4b22df566d618b8afa2aa"))
        self.assertEqual((len(ENV),p.sha(ENV)),(2921,"ff58613e4b1dbd1aa1b181cbf340646506fb1d239d75bc54e264f09f6a440f01"))
        self.assertEqual(CAT["sequence"],1)
        p.validate_inputs(p.canonical(request()),ZIP,ENV,INITIAL)
    def test_actual_pinned_initial_setup_seven_data_files_and_mutation_refusal(self):
        self.assertEqual((len(INITIAL),p.sha(INITIAL)),(850627,"248bb18c9b37f7bdc46fde729a345aa2b62b499f9c5b11990c3dea9fc347f05f"))
        p.verify_initial(INITIAL)
        with self.assertRaises(p.PublishError):p.verify_initial(INITIAL[:-1]+b"x")
        changed=request();changed["initialSetupSha256"]="0"*64
        with self.assertRaises(p.PublishError):p.validate_inputs(p.canonical(changed),ZIP,ENV,INITIAL)
        changed=request();changed["initialSetupBytes"]=True
        with self.assertRaises(p.PublishError):p.validate_inputs(p.canonical(changed),ZIP,ENV,INITIAL)
    def test_signature_mutation_wrong_domain_and_expired_are_rejected(self):
        outer=p.codec.decode(ENV);signature=bytearray(p.codec.canonical_base64(outer["signatureBase64"]));signature[40]^=1
        import base64
        outer["signatureBase64"]=base64.b64encode(signature).decode("ascii")
        with self.assertRaises(p.PublishError):p.verify_envelope(p.canonical(outer))
        with self.assertRaises(ValueError):p.codec.verify_catalog(ENV,now_ticks=CAT["expiresUtcTicks"])
        with patch.object(p.codec,"PURPOSE","SolarSystemLink"):
            with self.assertRaises(p.PublishError):p.verify_envelope(ENV)
    def test_duplicate_escaped_duplicate_noninteger_bom_and_unknown_fields(self):
        for raw in (b'{"a":1,"a":2}',b'{"a":1,"\\u0061":2}',b'{"a":-0}',b'{"a":1.0}',b'{"a":NaN}',b'\xef\xbb\xbf{}'):
            with self.assertRaises((p.PublishError,ValueError)):p.parse_json(raw,8192)
        changed=request();changed["unknown"]=1
        with self.assertRaises(p.PublishError):p.validate_inputs(p.canonical(changed),ZIP,ENV,INITIAL)
    def test_request_wrong_version_sequence_size_hash_and_oldpin(self):
        for key,value in (("version","0.4.5.0"),("sequence",True),("sequence",2),("packageBytes",1),("packageSha256","0"*64),("envelopeSha256","A"*64),("expectedStableEnvelopeSha256","bad")):
            changed=request();changed[key]=value
            with self.assertRaises(p.PublishError):p.validate_inputs(p.canonical(changed),ZIP,ENV,INITIAL)
    def test_zip_no_extra_duplicate_traversal_symlink_or_bad_bytes(self):
        with zipfile.ZipFile(io.BytesIO(ZIP)) as z:contents={i.filename:z.read(i) for i in z.infolist()}
        for variant in range(5):
            data=io.BytesIO()
            with zipfile.ZipFile(data,"w",zipfile.ZIP_DEFLATED) as z:
                for name,raw in contents.items():z.writestr(name,raw)
                if variant==0:z.writestr("publisher.exe",b"owned")
                elif variant==1:z.writestr("../outside",b"owned")
                elif variant==2:
                    info=zipfile.ZipInfo("SSS.exe");info.create_system=3;info.external_attr=(stat.S_IFLNK|0o777)<<16;z.writestr(info,b"owned")
                elif variant==3:z.writestr("SSS.exe",b"owned duplicate")
            raw=data.getvalue();fake=copy.deepcopy(CAT);fake["packageBytes"]=len(raw);fake["packageSha256"]=p.sha(raw)
            if variant==4:fake["files"][0]["sha256"]="0"*64
            with self.assertRaises(p.PublishError):p.verify_zip(raw,fake)

class DeliveryStateMachine(unittest.TestCase):
    def test_initial_two_tags_exact_three_final_assets_and_public_readback(self):
        client=MemoryGitHub();publish(client)
        self.assertEqual(set(r["tag_name"] for r in client.releases.values()),{p.VERSION_TAG,p.STABLE_TAG})
        self.assertEqual(set(client.assets(client.fixed(p.VERSION_TAG))),{p.PACKAGE_NAME,p.INITIAL_NAME})
        self.assertEqual(set(client.assets(client.fixed(p.STABLE_TAG))),{p.ENVELOPE_NAME})
    def test_identical_published_idempotent_even_immutable_version(self):
        client=MemoryGitHub();publish(client);client.fixed(p.VERSION_TAG)["immutable"]=True;client.mutations.clear();publish(client)
        self.assertEqual(client.mutations,[])
    def test_version_byte_conflict_and_foreign_release_body_no_mutation(self):
        for variant in range(2):
            client=MemoryGitHub();publish(client);client.mutations.clear()
            release=client.fixed(p.VERSION_TAG)
            if variant==0:
                item=client.assets_by_release[release["id"]][p.PACKAGE_NAME];client.data[item["id"]]=b"X"+ZIP[1:]
            else:release["body"]="not owned"
            with self.assertRaises(p.PublishError):publish(client)
            self.assertEqual(client.mutations,[])
    def test_synthetic_s1_to_s2_same_bits_archive_without_delete(self):
        client=MemoryGitHub();publish(client);fake=copy.deepcopy(CAT);fake["sequence"]=2;raw=b"owned-synthetic-s2-not-a-24c-signature"
        actual=p.verify_envelope
        with patch.object(p,"verify_envelope",side_effect=lambda data,current=True:fake if data==raw else actual(data,current)):
            publish(client,fake,raw,p.sha(ENV))
        self.assertEqual(client.asset_bytes(client.assets(client.fixed(p.STABLE_TAG))[p.ENVELOPE_NAME],8192),raw)
        self.assertIn(p.archived_name(CAT,ENV),client.assets(client.fixed(p.STABLE_TAG)))
    def test_synthetic_rollback_same_sequence_and_same_version_bits_reject(self):
        for key,value in (("sequence",1),("sequence",0),("version","0.4.5.0"),("packageSha256","0"*64),("packageBytes",1)):
            fake=copy.deepcopy(CAT);fake["sequence"]=2;fake[key]=value
            with self.assertRaises(p.PublishError):p.require_advance(fake,CAT)
        fake=copy.deepcopy(CAT);fake["sequence"]=2;fake["files"][0]["sha256"]="0"*64
        with self.assertRaises(p.PublishError):p.require_advance(fake,CAT)
    def test_old_pin_mismatch_and_unknown_stable_asset_before_mutation(self):
        client=MemoryGitHub();publish(client);client.mutations.clear()
        fake=copy.deepcopy(CAT);fake["sequence"]=2
        with self.assertRaises(p.PublishError):p.stable_preflight(client,client.fixed(p.STABLE_TAG),request(fake,b"fake","0"*64),fake,b"fake")
        assets=client.assets_by_release[client.fixed(p.STABLE_TAG)["id"]];assets["publisher.exe"]={"id":999,"name":"publisher.exe","state":"uploaded","size":1}
        with self.assertRaises(p.PublishError):publish(client)
        self.assertEqual(client.mutations,[])
    def test_unknown_upload_never_retries_or_claims_success(self):
        client=MemoryGitHub();client.unknown_upload=True
        with self.assertRaises(p.PublishError):publish(client)
        self.assertEqual(sum(row[0]=="upload" for row in client.mutations),1)
    def test_unknown_rename_preserves_state_and_never_deletes(self):
        client=MemoryGitHub();client.unknown_rename=True
        with self.assertRaises(p.PublishError):publish(client)
        self.assertEqual(sum(row[0]=="rename" for row in client.mutations),1)
        self.assertTrue(any(row[0]=="rename" for row in client.mutations))
    def test_wrong_public_bytes_is_failure(self):
        client=MemoryGitHub();client.bad_public=True
        with self.assertRaises(p.PublishError):publish(client)
    def test_api_blocks_ssl_native_unknown_tags_delete_and_overwrite(self):
        client=MemoryGitHub()
        for path,method,value in (("/releases/tags/ssl-stable","GET",None),("/releases/tags/sss-stable","GET",None),("/releases/1","DELETE",None),("/releases/assets/1","PATCH",{"name":"NativeReady"})):
            with self.assertRaises(p.PublishError):client.api("/repos/"+p.REPOSITORY+path,method,value)
        self.assertEqual(client.calls,[])
    def test_adapter_forbids_publisher_source_profiles_or_extra_upload(self):
        client=MemoryGitHub();release=client.create_draft(p.VERSION_TAG,COMMIT);client.mutations.clear()
        for name in ("publisher.exe","source.py","authorizations.dpapi",p.ENVELOPE_NAME):
            with self.assertRaises(p.PublishError):client.ensure_asset(release,name,b"owned")
        self.assertEqual(client.mutations,[])
        with self.assertRaises(p.PublishError):client.rename(release,{"id":1},"publisher.exe",p.ENVELOPE_NAME,b"owned")

class ExpiryCurrentness(unittest.TestCase):
    """Incremental real s1 signature checks with a controlled clock/HTTP memory boundary."""
    def setUp(self):
        self.now=[(CAT["expiresUtcTicks"]-621355968000000000-1)*100]
        self.clock=patch.object(p.codec.time,"time_ns",side_effect=lambda:self.now[0]);self.clock.start()
        self.network=patch.object(socket,"create_connection",side_effect=AssertionError("real network forbidden"));self.network.start()
    def tearDown(self):
        self.network.stop();self.clock.stop()
    def expire(self):self.now[0]=(CAT["expiresUtcTicks"]-621355968000000000)*100
    def seeded(self):
        client=MemoryGitHub();publish(client);client.mutations.clear();client.receipt["events"].clear()
        return client
    def assert_no_success(self,client):
        self.assertFalse(any(row["operation"]=="stable-feed-verified" for row in client.receipt["events"]))
    def test_true_s1_last_valid_tick_succeeds(self):
        client=MemoryGitHub();publish(client)
        self.assertTrue(any(row["operation"]=="stable-feed-verified" for row in client.receipt["events"]))
    def test_archive_final_byte_read_crosses_expiry_before_patch(self):
        client=self.seeded();stable=client.fixed(p.STABLE_TAG);asset=client.assets(stable)[p.ENVELOPE_NAME]
        actual=client.asset_matches
        def cross(item,data):
            actual(item,data);self.expire()
        with patch.object(client,"asset_matches",side_effect=cross):
            with self.assertRaisesRegex(p.PublishError,"signed-catalog-invalid"):
                client.rename(stable,asset,p.ENVELOPE_NAME,p.archived_name(CAT,ENV),ENV,admission_envelope=ENV)
        self.assertEqual(client.mutations,[]);self.assertIn(p.ENVELOPE_NAME,client.assets(stable));self.assert_no_success(client)
    def test_promote_final_byte_read_crosses_expiry_before_patch(self):
        client=MemoryGitHub();actual_check=client.public_check;actual_match=client.asset_matches;armed=[False]
        def check(tag,name,data):
            actual_check(tag,name,data)
            if tag==p.STABLE_TAG and name==p.pending_name(CAT,ENV):armed[0]=True
        def match(asset,data):
            actual_match(asset,data)
            if armed[0] and asset["name"]==p.pending_name(CAT,ENV):self.expire()
        with patch.object(client,"public_check",side_effect=check),patch.object(client,"asset_matches",side_effect=match):
            with self.assertRaisesRegex(p.PublishError,"signed-catalog-invalid"):publish(client)
        self.assertFalse(any(row[0]=="rename" for row in client.mutations))
        self.assertNotIn(p.ENVELOPE_NAME,client.assets(client.fixed(p.STABLE_TAG)));self.assert_no_success(client)
    def test_final_public_read_crosses_expiry_reports_failure_after_mutation(self):
        client=MemoryGitHub();actual=client.public_check
        def cross(tag,name,data):
            actual(tag,name,data)
            if tag==p.STABLE_TAG and name==p.ENVELOPE_NAME:self.expire()
        with patch.object(client,"public_check",side_effect=cross):
            with self.assertRaisesRegex(p.PublishError,"signed-catalog-invalid"):publish(client)
        self.assertIn(p.ENVELOPE_NAME,client.assets(client.fixed(p.STABLE_TAG)))
        self.assertEqual(sum(row[0]=="rename" for row in client.mutations),1);self.assert_no_success(client)
    def test_first_idempotent_public_read_crosses_expiry_no_success_or_mutation(self):
        client=self.seeded();actual=client.public_check
        def cross(tag,name,data):
            actual(tag,name,data)
            if tag==p.STABLE_TAG and name==p.ENVELOPE_NAME:self.expire()
        with patch.object(client,"public_check",side_effect=cross):
            with self.assertRaisesRegex(p.PublishError,"signed-catalog-invalid"):publish(client)
        self.assertEqual(client.mutations,[]);self.assert_no_success(client)
    def test_second_idempotent_after_concurrent_promote_crosses_expiry(self):
        client=self.seeded();stable=client.fixed(p.STABLE_TAG);candidate=p.pending_name(CAT,ENV)
        asset=client.assets(stable)[p.ENVELOPE_NAME]
        client.rename(stable,asset,p.ENVELOPE_NAME,candidate,ENV);client.mutations.clear()
        actual=client.public_check
        def cross(tag,name,data):
            actual(tag,name,data)
            if tag==p.STABLE_TAG and name==candidate:
                # Explicitly synthetic second publisher completes the same bytes
                # between the two real preflights; no crypto/admission seam.
                asset=client.assets(stable)[candidate]
                client.rename(stable,asset,candidate,p.ENVELOPE_NAME,ENV,admission_envelope=ENV)
            elif tag==p.STABLE_TAG and name==p.ENVELOPE_NAME:self.expire()
        with patch.object(client,"public_check",side_effect=cross):
            with self.assertRaisesRegex(p.PublishError,"signed-catalog-invalid"):publish(client)
        self.assertEqual(client.asset_bytes(client.assets(stable)[p.ENVELOPE_NAME],8192),ENV);self.assert_no_success(client)
    def test_main_final_success_boundary_rechecks_true_catalog(self):
        client=MemoryGitHub();output=io.StringIO();workspace=Path(p.__file__).resolve().parents[1]
        environment={"GITHUB_ACTIONS":"true","GITHUB_EVENT_NAME":"push","GITHUB_REPOSITORY":p.REPOSITORY,
                     "GITHUB_REF":"refs/heads/main","GITHUB_WORKSPACE":str(workspace),"GITHUB_SHA":COMMIT,"GITHUB_TOKEN":"owned-dummy"}
        with patch.dict(p.os.environ,environment),patch.object(p.sys,"argv",["owned"]),patch.object(p,"GitHub",return_value=client),\
                patch.object(p,"publish",side_effect=lambda *_:self.expire()),patch.object(p.sys,"stdout",output):
            self.assertEqual(p.main(),1)
        receipt=json.loads(output.getvalue());self.assertEqual(receipt["code"],"signed-catalog-invalid")
        self.assertEqual(receipt["status"],"failed-or-external-state-unknown");self.assertEqual(client.calls,[])

class Transport(unittest.TestCase):
    def test_token_dropped_on_allowed_cdn_redirect_and_bounded_read(self):
        class Response:
            def __init__(self,data):self.data=io.BytesIO(data)
            def __enter__(self):return self
            def __exit__(self,*_):self.data.close()
            def read(self,count):return self.data.read(count)
        class Opener:
            def __init__(self):self.calls=[]
            def open(self,request,timeout):
                self.calls.append(request)
                if len(self.calls)==1:raise urllib.error.HTTPError(request.full_url,302,"owned",{"Location":"https://release-assets.githubusercontent.com/owned"},io.BytesIO())
                return Response(b"abc")
        client=p.GitHub("owned-dummy",{"events":[]});opener=Opener();client.opener=opener
        self.assertEqual(client.fetch(p.API+"/repos/"+p.REPOSITORY+"/releases/assets/1",3,authenticated=True,binary=True),b"abc")
        self.assertIsNotNone(opener.calls[0].get_header("Authorization"));self.assertIsNone(opener.calls[1].get_header("Authorization"))
        with self.assertRaises(p.PublishError):client.fetch("https://evil.invalid/x",3)
        with self.assertRaises(p.PublishError):client.fetch("https://github.com/x",2)

if __name__=="__main__":
    with patch.object(socket,"create_connection",side_effect=AssertionError("real network forbidden")):
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    print(json.dumps({"schema":1,"testsRun":result.testsRun,"failures":len(result.failures),"errors":len(result.errors),"actualS1PublicSignatureAndZip":True,"syntheticS2StateMachineOnly":True,"realS2Signature":False,"realNetwork":False,"productExecuted":False,"privateKeyRead":False,"newFees":0,"paidCredits":0}))
    sys.exit(0 if result.wasSuccessful() else 1)
