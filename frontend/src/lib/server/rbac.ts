import "server-only";
import { readFile } from "node:fs/promises";
import path from "node:path";
import type { EngineFailure, EngineIdentity } from "../api";
import { MAX_RBAC_DOCUMENT_BYTES, RBAC_MODES, type RbacExample, type RbacMode, type RbacReview, type RbacReviewResponse, type RbacRunResponse } from "../rbac/api";
import { ACCESS_PROFILES, authorizationProblem, target, jsonEqual, rbacChangeReport, rbacProfile, rbacSequenceReport, rbacVerifyReport, sha256 as digestValidator, type RbacProfile, type RbacReport } from "../rbac/contract";
import { nullable, object, oneOf, string, SchemaError, type Validator } from "../schema";
import { shellCommand } from "../shell";
import { accept, VERIFY_EXIT } from "./accept";
import { EngineAbortedError, EngineBusyError, EngineUnavailableError, REPO_ROOT, engineIdentity, execEngine, sha256, withWorkspace, type RunResult } from "./engine";
import { readRbacEvidence } from "./rbac-evidence";

export const MAX_RBAC_BODY_BYTES = 18 * MAX_RBAC_DOCUMENT_BYTES + 4096;
const reviewRequest = object({ mode: oneOf(RBAC_MODES), contract: string }, { baseline: string });
const runRequest = object({ mode: oneOf(RBAC_MODES), contract: string, candidate: string, reviewed: object({ contractSha256: digestValidator, baselineSha256: nullable(digestValidator) }) }, { baseline: string });
class RbacFailure extends Error { constructor(readonly failure: EngineFailure) { super(failure.message); } }
function fail(stage: EngineFailure["stage"], message: string, exitCode: number|null = null, command?:string): never { throw new RbacFailure({ok:false,stage,message,exitCode,...(command?{command}:{})}); }
function inputDocument(value:string,label:string) { if (!value.trim()) fail("input",`${label} is empty.`); if(Buffer.byteLength(value)>MAX_RBAC_DOCUMENT_BYTES) fail("input",`${label} is larger than 512 KB.`);return value; }
function baselineInput(mode:RbacMode,baseline?:string) { if (mode==="verify") { if(baseline!==undefined) fail("input","Access verification does not accept a baseline; choose repair comparison."); return undefined; } if(baseline===undefined) fail("input","This operation requires an original baseline snapshot.");return inputDocument(baseline,"Baseline"); }
interface ContractInfo { schema:number; accessSchema:number; profileId:string; profileArgs:string[]; accessArgs:string[] }
function contractInfo(source:string,mode:RbacMode):ContractInfo {
  let data:unknown;try { data=JSON.parse(source); } catch { fail("input","The frozen contract must be JSON."); }
  if (!data || typeof data!=="object" || Array.isArray(data)) fail("input","The frozen contract must be a JSON object.");
  const c=data as Record<string,unknown>;
  const kind=mode==="verify"||mode==="repair"?"kubernetes-rbac-access":`kubernetes-rbac-policy-${mode}`;
  if(c.kind!==kind) fail("input",`The selected operation requires ${kind}.`);
  const schema=c.schema_version;
  if (!Number.isInteger(schema) || typeof schema!=="number") fail("input","Contract schema_version must be an integer.");
  let accessSchema=schema;
  if(mode==="change"||mode==="sequence") {
    if(schema!==1&&schema!==2) fail("input","Unsupported policy contract schema; this workspace accepts versions 1 and 2.");
    if(!c.requirements||typeof c.requirements!=="object"||Array.isArray(c.requirements)) fail("input","Policy contract lacks nested access requirements.");
    accessSchema=(c.requirements as Record<string,unknown>).schema_version as number;
  }
  if(!Number.isInteger(accessSchema)||accessSchema<1||accessSchema>10) fail("input","Unsupported access contract schema; this workspace accepts versions 1–10.");
  const accessArgs=["profile","kubernetes-rbac","--contract-version",String(accessSchema),"--format","json"];
  const outer=mode==="change"||mode==="sequence";
  return {schema,accessSchema,profileId:outer?`kubernetes-rbac-v1.34-policy-${mode}-v${schema}`:ACCESS_PROFILES[accessSchema-1],accessArgs,
    profileArgs:outer?["profile",`kubernetes-rbac-policy-${mode}${schema===2?"-v2":""}`,"--format","json"]:accessArgs};
}
function display(args:string[]) { return shellCommand(["soundcheck",...args]); }
function completedText(result:RunResult,command:string):string {
  if(result.aborted) fail("cancelled","The run was cancelled. No review or verdict was produced.",null,command);
  if(result.timedOut) fail("engine","The engine did not finish within the time limit.",null,command);
  if(result.outputExceeded) fail("protocol","The engine exceeded the output limit.",null,command);
  if(result.exitCode===null) fail("engine","The engine terminated before completion.",null,command);
  if(result.exitCode!==0) fail(result.exitCode===1?"parse":result.exitCode===2?"usage":"protocol",result.stderr.trim()||"The engine rejected the contract.",result.exitCode,command);
  return result.stdout;
}
export function reviewSignature(text:string):string {
  const hashes=text.match(/^Canonical frozen-contract SHA-256: [0-9a-f]{64}$/gm);
  if(hashes?.length!==1 || !text.includes("RBAC contract parsed (structure only; not a verification result).")) throw new Error("unrecognized engine contract review");
  return text.split("\n").filter(line=>!line.startsWith("Raw artifact SHA-256: ")&&!line.startsWith("Artifact size: ")).join("\n");
}
async function textReview(file:string,signal?:AbortSignal) { const args=["rbac","check-contract",file];const text=completedText(await execEngine(args,signal),display(["rbac","check-contract","contract.json"]));reviewSignature(text);return text; }
async function loadProfile(args:string[],expectedId:string,signal?:AbortSignal):Promise<RbacProfile> {
  const accepted=accept(await execEngine(args,signal),display(args),{validate:rbacProfile,verdictExits:[0],exitFor:()=>0,answers:p=>p.id===expectedId?null:"wrong assurance profile"});
  if(!accepted.ok) throw new RbacFailure(accepted);return accepted.report;
}
function sameEngine(before:EngineIdentity|null,after:EngineIdentity|null):asserts after is EngineIdentity {
  if(!before||!after) fail("engine","The engine identity could not be established.");
  if(!jsonEqual(before,after)) fail("protocol","The engine or solver changed during the request. Run again.");
}
async function reviewWithin(mode:RbacMode,contract:string,baseline:string|undefined,file:string,signal?:AbortSignal):Promise<RbacReview> {
  const info=contractInfo(contract,mode);
  const reviewText=await textReview(file,signal);
  const accessProfile=await loadProfile(info.accessArgs,ACCESS_PROFILES[info.accessSchema-1],signal);
  const profile=mode==="verify"||mode==="repair"?accessProfile:await loadProfile(info.profileArgs,info.profileId,signal);
  return {mode,contractSha256:sha256(contract),baselineSha256:baseline===undefined?null:sha256(baseline),reviewText,profile,accessProfile};
}
async function guarded<T>(fn:()=>Promise<T>):Promise<T|EngineFailure> {
  try{return await fn();} catch(error) {
    if(error instanceof RbacFailure) return error.failure;
    if(error instanceof SchemaError) return {ok:false,stage:"input",message:error.message,exitCode:null};
    if(error instanceof EngineBusyError) return {ok:false,stage:"busy",message:error.message,exitCode:null};
    if(error instanceof EngineAbortedError) return {ok:false,stage:"cancelled",message:error.message,exitCode:null};
    if(error instanceof EngineUnavailableError) return {ok:false,stage:"engine",message:error.message,exitCode:null};
    return {ok:false,stage:"protocol",message:`RBAC response was not accepted: ${(error as Error).message}`,exitCode:null};
  }
}
export async function reviewRbac(raw:unknown,signal?:AbortSignal):Promise<RbacReviewResponse> {
  return guarded(async()=>{
    const request=reviewRequest(raw,"request");
    const contract=inputDocument(request.contract,"Contract"),baseline=baselineInput(request.mode,request.baseline);
    const identity=await engineIdentity();
    return withWorkspace({"contract.json":contract},async paths=>{
      const review=await reviewWithin(request.mode,contract,baseline,paths["contract.json"],signal);
      sameEngine(identity,await engineIdentity());
      if(signal?.aborted) throw new EngineAbortedError("The review was cancelled.");
      return {ok:true as const,review};
    });
  });
}
export function rbacExit(report:RbacReport):number {
  if(!("kind" in report)) return VERIFY_EXIT[report.result];
  if(report.result==="valid_change"||report.result==="valid_sequence") return 0;
  if(report.result==="unknown") return 4;
  if(report.result==="contract_failed") return report.verification?VERIFY_EXIT[report.verification.comparison_report.result]:3;
  if(report.result==="invariant_failed" && "state_invariants" in report) {
    const result=report.state_invariants.find(s=>s.state===report.failing_step)?.report?.result;
    return result?VERIFY_EXIT[result]:3;
  }
  return 3;
}
function validator(mode:RbacMode):Validator<RbacReport> { return mode==="change"?rbacChangeReport:mode==="sequence"?rbacSequenceReport:rbacVerifyReport; }
export async function runRbac(raw:unknown,signal?:AbortSignal):Promise<RbacRunResponse> {
  return guarded(async()=>{
    const request=runRequest(raw,"request");
    const contract=inputDocument(request.contract,"Contract"),candidate=inputDocument(request.candidate,"Candidate"),baseline=baselineInput(request.mode,request.baseline);
    if(request.reviewed.contractSha256!==sha256(contract)||request.reviewed.baselineSha256!==(baseline===undefined?null:sha256(baseline))) fail("input","The contract or baseline differs from the reviewed context. Review and lock the inputs again.");
    const identity=await engineIdentity();
    if(!identity) fail("engine","The engine identity could not be established.");
    const started=performance.now();
    const files={"contract.json":contract,"candidate.json":candidate,...(baseline===undefined?{}:{"baseline.json":baseline})};
    return withWorkspace(files,async(paths,dir)=>{
      const review=await reviewWithin(request.mode,contract,baseline,paths["contract.json"],signal);
      const verb=request.mode==="repair"?"compare":request.mode;
      const names=baseline===undefined?["candidate.json"]:["baseline.json","candidate.json"];
      const args=["rbac",verb,...names.map(name=>paths[name]),"--contract",paths["contract.json"],"--format","json","--evidence-dir",path.join(dir,"evidence")];
      const command=display(["rbac",verb,...names,"--contract","contract.json","--format","json","--evidence-dir","evidence"]);
      const result=await execEngine(args,signal);
      const accepted=accept<RbacReport>(result,command,{validate:validator(request.mode),verdictExits:[0,3,4,5,6],exitFor:rbacExit,answers:report=>{
        if(report.assurance?.profile!==review.profile.id) return "report uses the wrong profile";
        if(!("kind" in report)) {
          if(report.frozen_spec?.kind!=="kubernetes-rbac-access") return "report lacks access contract identity";
          if(request.mode==="verify" && report.property!=="kubernetes-rbac-access") return "wrong access verification property";
          if(request.mode==="repair" && !["kubernetes-rbac-access","rbac-repair-preservation"].includes(report.property)) return "wrong repair property";
          if(request.mode==="repair" && report.result==="proved" && report.property!=="rbac-repair-preservation") return "proved repair lacks preservation";
        } else {
          if(report.inputs.before.sha256!==sha256(baseline!)||report.inputs.before.bytes!==Buffer.byteLength(baseline!)||report.inputs.after.sha256!==sha256(candidate)||report.inputs.after.bytes!==Buffer.byteLength(candidate)) return "report describes different input bytes";
          const declared=JSON.parse(report.frozen_spec!.canonical) as {operation:string;target:unknown};
          const stages=report.kind==="kubernetes-rbac-policy-sequence"?report.steps:[{operation:declared.operation,target:target(declared.target,"target"),authorization:report.authorization}];
          for(const stage of stages) {
            if(!stage.authorization || !stage.target.kind.endsWith("Binding") || stage.operation==="delete-existing") continue;
            const snapshot=JSON.parse(candidate) as {items?:{kind:string;metadata:{namespace?:string;name:string};roleRef?:{kind:string;name:string}}[]};
            const body=snapshot.items?.find(o=>o.kind===stage.target.kind&&o.metadata.name===stage.target.name&&(o.metadata.namespace||null)===stage.target.namespace);
            if(!body?.roleRef) return "authorized binding lacks its candidate roleRef";
            const problem=authorizationProblem(stage.authorization,stage.operation,stage.target,body.roleRef);if(problem)return problem;
          }
        }
        return null;
      }});
      if(!accepted.ok) return accepted;
      let evidence;
      try {
        evidence=await readRbacEvidence(path.join(dir,"evidence"),{mode:request.mode,candidate,baseline,stdout:result.stdout,report:accepted.report,profile:review.profile,accessProfile:review.accessProfile,engine:identity});
        // Re-run only the structural parser over the canonical artifact. The engine's
        // nested canonical digest and full outer actor/order/target/invariant review
        // must match the original input; no TypeScript policy normalization is used.
        const canonicalReview=await textReview(path.join(dir,"evidence","contract.json"),signal);
        if(reviewSignature(canonicalReview)!==reviewSignature(review.reviewText)) throw new Error("returned canonical contract differs from the reviewed input");
      } catch(error) {
        if(error instanceof RbacFailure || error instanceof EngineAbortedError) throw error;
        fail("protocol",`The RBAC evidence was not accepted: ${(error as Error).message}`,result.exitCode,command);
      }
      const engine=await engineIdentity();sameEngine(identity,engine);
      if(signal?.aborted) throw new EngineAbortedError("The run was cancelled.");
      return {ok:true as const,mode:request.mode,report:accepted.report,profile:review.profile,accessProfile:review.accessProfile,exitCode:accepted.exitCode,durationMs:Math.round(performance.now()-started),command,
        provenance:{inputs:{contract:sha256(contract),candidate:sha256(candidate),...(baseline===undefined?{}:{baseline:sha256(baseline)})},engine,evidence:evidence.manifest},evidenceArchive:evidence.archive};
    });
  });
}

/** Fixed repository examples only; there is no user-controlled server path. */
export async function loadRbacExamples():Promise<RbacExample[]> {
  const base=path.join(REPO_ROOT,"bench/kubernetes-rbac/workflows/policy-retirement");
  const load=(name:string)=>readFile(path.join(base,name),"utf8");
  try {
    const [contract,before,after,deleteContract,deleteBefore,deleteAfter,gapContract]=await Promise.all(["contract.json","before.json","repaired.json","delete-contract.json","delete-before.json","delete-after.json","gap-contract.json"].map(load));
    const access=JSON.stringify((JSON.parse(contract) as {requirements:unknown}).requirements,null,2)+"\n";
    return [
      {id:"access",label:"Access requirements",description:"Synthetic: required ConfigMap access and forbidden Secret access.",mode:"verify",contract:access,candidate:after},
      {id:"repair",label:"Repair and preservation",description:"Synthetic: remove Secret access while preserving other modeled decisions.",mode:"repair",contract:access,baseline:before,candidate:after},
      {id:"delete",label:"Retire a binding",description:"Synthetic: ordinary named deletion with predecessor authorization.",mode:"change",contract:deleteContract,baseline:deleteBefore,candidate:deleteAfter},
      {id:"migration",label:"Preserve access during migration",description:"Synthetic: install replacement grants before retiring the old policy.",mode:"sequence",contract,baseline:before,candidate:after},
      {id:"migration-gap",label:"Find a temporary access gap",description:"Synthetic: the final policy passes, but the frozen order loses required access in an intermediate state.",mode:"sequence",contract:gapContract,baseline:before,candidate:after},
    ];
  } catch { return []; }
}
