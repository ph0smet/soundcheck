import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { unzipSync } from "fflate";
import { beforeAll, describe, expect, it, vi } from "vitest";
import type { RbacExample, RbacRunSuccess } from "../../rbac/api";
import { rbacSequenceReport, rbacVerifyReport } from "../../rbac/contract";
import { sha256 } from "../engine";
import { loadRbacExamples, reviewRbac, runRbac, rbacExit } from "../rbac";
import { accept } from "../accept";
import { validateRbacEvidence } from "../rbac-evidence";

const root=path.resolve(process.env.SOUNDCHECK_REPO ?? "..");
const binary=process.env.SOUNDCHECK_TEST_BIN ?? path.join(root,"_build/default/cli/main.exe");
const read=(p:string)=>readFile(path.join(root,p),"utf8");
const retirement="bench/kubernetes-rbac/workflows/policy-retirement/";
let examples:RbacExample[]=[];
let positive:RbacRunSuccess;
let gap:RbacRunSuccess;
async function execute(input:RbacExample) {
  const {mode,contract,baseline,candidate}=input;
  const result=await reviewRbac({mode,contract,...(baseline===undefined?{}:{baseline})});
  expect(result.ok,JSON.stringify(result)).toBe(true);
  if(!result.ok) throw new Error(result.message);
  return runRbac({mode,contract,candidate,...(baseline===undefined?{}:{baseline}),reviewed:{contractSha256:result.review.contractSha256,baselineSha256:result.review.baselineSha256}});
}
describe.runIf(existsSync(binary))("real CLI RBAC web adapter",()=>{
  beforeAll(async()=>{process.env.SOUNDCHECK_BIN=binary;examples=await loadRbacExamples();expect(examples).toHaveLength(5);});
  it.each(["access","repair","delete","migration"])("accepts %s with bound evidence",async id=>{
    const example=examples.find(e=>e.id===id)!;
    const result=await execute(example);
    expect(result.ok,JSON.stringify(result)).toBe(true);if(!result.ok)return;
    expect(result.exitCode).toBe(0);
    expect(result.report.result).toBe(id==="delete"?"valid_change":id==="migration"?"valid_sequence":"proved");
    expect(result.provenance.inputs.contract).toBe(sha256(example.contract));
    expect(result.provenance.inputs.candidate).toBe(sha256(example.candidate));
    const zip=Buffer.from(result.evidenceArchive.base64,"base64");expect(sha256(zip)).toBe(result.evidenceArchive.sha256);
    const files=unzipSync(zip);expect(Object.keys(files)).toHaveLength(result.evidenceArchive.fileCount);
    expect(JSON.parse(Buffer.from(files["report.json"]).toString())).toEqual(result.report);
    if(id==="migration") positive=result;
  });
  it("retains a temporary invariant failure",async()=>{
    const result=await execute(examples.find(e=>e.id==="migration-gap")!);
    expect(result.ok,JSON.stringify(result)).toBe(true);if(!result.ok)return;
    expect(result.exitCode).toBe(3);expect(result.report.result).toBe("invariant_failed");
    expect(result.report).toMatchObject({phase:"state_invariants",failing_step:1});gap=result;
  });
  it("accepts failed candidate access in verify and repair",async()=>{
    for(const id of ["access","repair"]) {
      const result=await execute({...examples.find(e=>e.id===id)!,candidate:await read(retirement+"before.json")});
      expect(result.ok,JSON.stringify(result)).toBe(true);if(!result.ok)continue;
      expect(result.report.result).toBe("violated");expect(result.exitCode).toBe(3);
    }
  });
  it.each([
    ["contract-failed.json","contract.json","contract_failed"],
    ["authorization-failed.json","contract.json","authorization_failed"],
    ["out-of-scope-regression.json","contract.json","out_of_scope_regression"],
    ["repaired.json","role-first-contract.json","unknown"],
  ])("accepts native sequence outcome for %s",async(candidate,contract,expected)=>{
    const example={...examples.find(e=>e.id==="migration")!,candidate:await read(retirement+candidate),contract:await read(retirement+contract)};
    const result=await execute(example);expect(result.ok,JSON.stringify(result)).toBe(true);if(result.ok)expect(result.report.result).toBe(expected);
  });
  it("accepts deletion authorization failure",async()=>{
    const result=await execute({...examples.find(e=>e.id==="delete")!,contract:await read(retirement+"delete-unauthorized-contract.json")});
    expect(result.ok,JSON.stringify(result)).toBe(true);if(result.ok)expect(result.report.result).toBe("authorization_failed");
  });
  it("retains unsupported snapshot outcomes",async()=>{
    const result=await execute({...examples[0],candidate:'{"apiVersion":"v1","kind":"List","items":[{"kind":"Unsupported"}]}'});
    expect(result.ok,JSON.stringify(result)).toBe(true);if(result.ok)expect(result.report.result).toBe("unknown");
  });
  it.each([
    [1,"contracts/frontend-access.json"],[2,"workflows/read-access/contract.json"],[3,"workflows/write-access/contract.json"],[4,"workflows/authoring/contract.json"],
    [5,"resources/contract.json"],[6,"collection-writes/contract.json"],[7,"subresources/contract.json"],[8,"apply/contract.json"],[9,"coverage/contract.json"],[10,"controller-apis/contract.json"],
  ])("reviews the exact access profile for schema %s",async(version,file)=>{
    const result=await reviewRbac({mode:"verify",contract:await read("bench/kubernetes-rbac/"+file)});
    expect(result.ok,JSON.stringify(result)).toBe(true);if(result.ok)expect(result.review.accessProfile.contract_schema_version??1).toBe(version);
  });
  it.each([["change","policy-changes","valid_change"],["sequence","policy-sequences","valid_sequence"]] as const)("accepts schema-1 %s",async(mode,folder,expected)=>{
    const prefix=`bench/kubernetes-rbac/workflows/${folder}/`;
    const result=await execute({id:"legacy",label:"legacy",description:"legacy",mode,contract:await read(prefix+"contract.json"),baseline:await read(prefix+"before.json"),candidate:await read(prefix+"repaired.json")});
    expect(result.ok,JSON.stringify(result)).toBe(true);if(result.ok){expect(result.report.result).toBe(expected);expect(result.report.schema_version).toBe(1);}
  });
  it("shows an invariant failure at the original state and permits explicit empty selection",async()=>{
    const e=examples.find(e=>e.id==="migration")!;
    const baseline=await execute({...e,baseline:await read(retirement+"initial-before.json")});
    expect(baseline.ok,JSON.stringify(baseline)).toBe(true);if(baseline.ok)expect(baseline.report).toMatchObject({result:"invariant_failed",failing_step:0});
    const empty=await execute({...e,contract:await read(retirement+"unguarded-gap-contract.json")});
    expect(empty.ok,JSON.stringify(empty)).toBe(true);if(empty.ok)expect(empty.report).toMatchObject({result:"valid_sequence",state_invariants:[]});
  });
  it("retains URL and compound-operation witnesses",async()=>{
    const access=JSON.parse(examples[0].contract);
    access.clauses=[{name:"required-ready-grant",kind:"must_allow",subject:"app",operation:"get",request_kind:"non_resource",paths:{exact:"/readyz"}},{name:"no-health-grant",kind:"must_not_grant",subject:"app",operation:"get",request_kind:"non_resource",paths:{exact:"/healthz"}}];access.change_scope=[];
    const snapshot={apiVersion:"v1",kind:"List",items:[
      {apiVersion:"rbac.authorization.k8s.io/v1",kind:"ClusterRole",metadata:{name:"health"},rules:[{verbs:["get"],nonResourceURLs:["/healthz","/readyz"]}]},
      {apiVersion:"rbac.authorization.k8s.io/v1",kind:"ClusterRoleBinding",metadata:{name:"health"},roleRef:{apiGroup:"rbac.authorization.k8s.io",kind:"ClusterRole",name:"health"},subjects:[{kind:"User",apiGroup:"rbac.authorization.k8s.io",name:"app"}]}]};
    const url=await execute({...examples[0],contract:JSON.stringify(access),candidate:JSON.stringify(snapshot)});
    expect(url.ok,JSON.stringify(url)).toBe(true);if(url.ok)expect(url.report).toMatchObject({result:"violated",counterexample:{path:"/healthz",object_request:null,identity_groups:[]}});
    const compound=await execute({...examples[0],contract:await read("bench/kubernetes-rbac/apply/contract.json"),candidate:'{"apiVersion":"v1","kind":"List","items":[]}'});
    expect(compound.ok,JSON.stringify(compound)).toBe(true);if(compound.ok)expect(compound.report).toMatchObject({result:"violated",counterexample:{action:"apply-existing"}});
  });
  it("rejects changed reviewed contract and baseline before running",async()=>{
    const e=examples.find(e=>e.id==="migration")!;
    for(const change of [{contractSha256:"0".repeat(64),baselineSha256:sha256(e.baseline!)},{contractSha256:sha256(e.contract),baselineSha256:"0".repeat(64)}]) {
      const result=await runRbac({mode:e.mode,contract:e.contract,baseline:e.baseline,candidate:e.candidate,reviewed:change});
      expect(result).toMatchObject({ok:false,stage:"input"});
    }
  });
  it("rejects unknown schemas and foreign contract kinds",async()=>{
    for(const contract of ['{"kind":"kubernetes-rbac-access","schema_version":11}','{"kind":"foreign","schema_version":1}']) expect(await reviewRbac({mode:"verify",contract})).toMatchObject({ok:false,stage:"input"});
  });
  it("rejects missing required invariant stages and dishonest nested identities",()=>{
    expect(positive).toBeDefined();
    for(const mutate of [
      (r:Record<string,unknown>)=>{r.state_invariants=[];},
      (r:Record<string,unknown>)=>{(r.state_invariants as unknown[]).pop();},
      (r:Record<string,unknown>)=>{r.schema_version=3;},
      (r:Record<string,unknown>)=>{const stages=r.state_invariants as {report:{frozen_spec:{canonical:string}}}[];stages[0].report.frozen_spec.canonical='{}';},
      (r:Record<string,unknown>)=>{const states=r.states as unknown[];states.pop();},
      (r:Record<string,unknown>)=>{const steps=r.steps as {authorization:{special:unknown;coverage:unknown}}[];steps[0].authorization.special=null;steps[0].authorization.coverage=null;},
      (r:Record<string,unknown>)=>{const steps=r.steps as {authorization:{initial:{attributes:{name:string}}}}[];steps[0].authorization.initial.attributes.name="different";},
    ]) {const report=JSON.parse(JSON.stringify(positive.report));mutate(report);expect(()=>rbacSequenceReport(report,"report")).toThrow();}
  });
  it("rejects corrupt/missing/extra evidence and profile/engine/input disagreement",()=>{
    const original=new Map(Object.entries(unzipSync(Buffer.from(positive.evidenceArchive.base64,"base64"))).map(([key,v])=>[key,Buffer.from(v)]));
    const e=examples.find(e=>e.id==="migration")!;
    const run={mode:e.mode,candidate:e.candidate,baseline:e.baseline,stdout:original.get("report.json")!.toString(),report:positive.report,profile:positive.profile,accessProfile:positive.accessProfile,engine:positive.provenance.engine};
    expect(()=>validateRbacEvidence(original,run)).not.toThrow();
    const query=[...original.keys()].find(p=>p.endsWith(".smt2"))!;
    for(const mutate of [(m:Map<string,Buffer>)=>m.delete(query),(m:Map<string,Buffer>)=>m.set(query,Buffer.from("corrupted")),(m:Map<string,Buffer>)=>m.set("unexpected.txt",Buffer.from("extra"))]) {
      const files=new Map(original);mutate(files);expect(()=>validateRbacEvidence(files,run)).toThrow();
    }
    const omitted=new Map(original);
    const preservationQuery=[...omitted.keys()].find(p=>p.startsWith("preservation/")&&p.endsWith(".smt2"))!;
    const manifest=JSON.parse(omitted.get("manifest.json")!.toString());manifest.artifacts=manifest.artifacts.filter((a:{path:string})=>a.path!==preservationQuery);
    omitted.set("manifest.json",Buffer.from(JSON.stringify(manifest)));omitted.set(preservationQuery,Buffer.from("tampered unlisted query"));
    expect(()=>validateRbacEvidence(omitted,run)).toThrow("artifact inventory is incomplete");
    expect(()=>validateRbacEvidence(original,{...run,candidate:e.candidate+" "})).toThrow();
    expect(()=>validateRbacEvidence(original,{...run,engine:{...run.engine,executableSha256:"0".repeat(64)}})).toThrow();
    expect(()=>validateRbacEvidence(original,{...run,accessProfile:{...run.accessProfile,id:"wrong"}})).toThrow();
  });
  it("requires skipped invariant plans and every frozen query",()=>{
    const e=examples.find(e=>e.id==="migration-gap")!;
    expect(gap).toBeDefined();
    const files=new Map(Object.entries(unzipSync(Buffer.from(gap.evidenceArchive.base64,"base64"))).map(([key,v])=>[key,Buffer.from(v)]));
    const run={mode:e.mode,candidate:e.candidate,baseline:e.baseline,stdout:files.get("report.json")!.toString(),report:gap.report,profile:gap.profile,accessProfile:gap.accessProfile,engine:gap.provenance.engine};
    const prefix="invariants/state-002/";
    expect(files.has(prefix+"plan.json")).toBe(true);
    for(const name of [...files.keys()]) if(name.startsWith(prefix))files.delete(name);
    const manifest=JSON.parse(files.get("manifest.json")!.toString());manifest.artifacts=manifest.artifacts.filter((a:{path:string})=>!a.path.startsWith(prefix));files.set("manifest.json",Buffer.from(JSON.stringify(manifest)));
    expect(()=>validateRbacEvidence(files,run)).toThrow("missing evidence artifact invariants/state-002/plan.json");
  });
  it("never presents conservative or unsupported assurance as an RBAC proof",()=>{
    if(!("verification" in positive.report)||!positive.report.verification)throw new Error("missing candidate");
    const original=positive.report.verification.candidate_report!;
    for(const status of ["unsupported","conservative"])expect(()=>rbacVerifyReport({...original,assurance:{...original.assurance,status}},"report")).toThrow();
  });
  it("rejects mismatched exits and complete-looking output after timeout or cancellation",()=>{
    const run={exitCode:0,signal:null,stdout:JSON.stringify(positive.report),stderr:"",durationMs:1,timedOut:false,outputExceeded:false,aborted:false};
    for(const overrides of [{exitCode:3},{timedOut:true},{outputExceeded:true},{aborted:true},{exitCode:null},{stdout:run.stdout+run.stdout}]) {
      expect(accept({...run,...overrides},"soundcheck",{validate:rbacSequenceReport,verdictExits:[0,3,4,5,6],exitFor:rbacExit}).ok).toBe(false);
    }
  });
  it("refuses a canonical evidence contract that does not match the original engine review",async()=>{
    const engine=await import("../engine");const actual=engine.execEngine;
    const spy=vi.spyOn(engine,"execEngine").mockImplementation(async(args,signal)=>{
      const result=await actual(args,signal);
      if(args[1]==="check-contract" && args[2].endsWith("/evidence/contract.json")) return {...result,stdout:result.stdout.replace(/^Canonical frozen-contract SHA-256: [a-f0-9]{64}$/m,"Canonical frozen-contract SHA-256: "+"0".repeat(64))};
      return result;
    });
    try {expect(await execute(examples[0])).toMatchObject({ok:false,stage:"protocol",message:expect.stringContaining("canonical contract differs")});} finally {spy.mockRestore();}
  });
  it("rejects cross-target reports",()=>{
    expect(()=>rbacVerifyReport({schema_version:10,result:"proved",property:"authenticated-access",assurance:{profile:"kong-v11",status:"within_profile",findings:[]},frozen_spec:null,clause:null,counterexample:null},"report")).toThrow();
  });
  it("cancels before starting",async()=>{
    const c=new AbortController();c.abort();expect(await reviewRbac({mode:examples[0].mode,contract:examples[0].contract},c.signal)).toMatchObject({ok:false,stage:"cancelled"});
  });
});
