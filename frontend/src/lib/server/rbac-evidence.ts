import "server-only";
import { lstat, readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { zipSync } from "fflate";
import type { EngineIdentity } from "../api";
import type { JsonValue, RbacEvidenceArchive, RbacMode } from "../rbac/api";
import { inputDigest, nonnegative, rbacProfile, rbacVerifyReport, sha256 as digestValidator, type RbacProfile, type RbacReport, type RbacVerifyReport } from "../rbac/contract";
import { array, integer, literal, nullable, object, oneOf, refine, string, type Validator } from "../schema";
import { sha256 } from "./engine";

export const RBAC_EVIDENCE_LIMITS = { files: 4096, bytes: 64 * 1024 * 1024, fileBytes: 16 * 1024 * 1024, archiveBytes: 16 * 1024 * 1024 };
const safePath = refine(string, (s) => s.length <= 512 && /^[A-Za-z0-9._/-]+$/.test(s) && !s.startsWith("/") && s.split("/").every(p => p && p !== "." && p !== "..") ? null : "unsafe evidence path");
const artifact = object({ path: safePath, sha256: digestValidator });
const sizedArtifact = object({ path: safePath, sha256: digestValidator, bytes: nonnegative });
const sourceDigest = object({ sha256: digestValidator, size_bytes: nonnegative });
const model = object({ principal: oneOf(["anonymous", "authenticated"]), method: string, path: string, source_ip: string, host: string, scheme: string, sni: string,
  headers: array(object({ name: string, value: string })), principal_name: nullable(string), object_request: nullable(object({ namespace: string, resource_kind: string, name: string })) });
const obligation = refine(object({ id: string, phase: oneOf(["inhabitance", "consistency", "clause", "preservation"]), clauses: array(string), query: artifact,
  execution: oneOf(["executed", "not_executed"]), solver_result: nullable(oneOf(["sat", "unsat", "unknown"])), model: nullable(model), reason: nullable(string) }), (q) => {
  if (q.execution === "not_executed") return q.solver_result !== null || q.model !== null || q.reason !== null ? "skipped query has a solver result" : null;
  if (q.solver_result === null || (q.solver_result === "sat") !== (q.model !== null) || (q.solver_result === "unknown") !== (q.reason !== null)) return "incoherent solver execution";
  return null;
});
const coreBase = { contract: artifact, assurance_profile: object({ id: string, artifact }), soundcheck: object({ executable_sha256: digestValidator, ocaml_version: string, report_schema_version: literal(10) }),
  solver: object({ name: literal("z3"), version: nullable(string), version_error: nullable(string) }), obligation_plan: object({ status: oneOf(["complete", "unavailable"]), reason: nullable(string) }),
  obligations: array(obligation), report: artifact, result: oneOf(["proved", "violated", "vacuous", "inconsistent", "unknown"]) };
const verificationManifest = object({ ...coreBase, schema_version: literal(2), config: sourceDigest });
const comparisonManifest = object({ ...coreBase, schema_version: literal(3), operation: literal("repair_comparison"), inputs: object({ before: sourceDigest, after: sourceDigest }), candidate_report: nullable(artifact) });
const version = refine(integer, n => n === 1 || n === 2 ? null : "unsupported evidence version");
const z3Version: Validator<{value: string} | {error: string}> = (v,p) => typeof v === "object" && v !== null && "value" in v ? object({value:string})(v,p) : object({error:string})(v,p);
const outerBase = { schema_version: version, inputs: object({ before: inputDigest, after: inputDigest }), authorization_method: literal("deterministic-native-rbac-policy-coverage"),
  verification: oneOf(["not_executed", "see verification/manifest.json"]), provenance: object({ executable_sha256: digestValidator, ocaml_version: string, z3_version: z3Version }), artifacts: array(sizedArtifact) };
const changeManifest = object({ ...outerBase, kind: literal("kubernetes-rbac-policy-change-evidence") });
const sequenceBase = { ...outerBase, kind: literal("kubernetes-rbac-policy-sequence-evidence"), phase: oneOf(["preparation","authorization","final_verification","state_invariants","intermediate_preservation","complete"]), failing_step: nullable(nonnegative),
  intermediate_preservation: array(object({ step: nonnegative, status: oneOf(["proved","violated","unknown","not_executed"]), query: safePath, report: nullable(safePath) })) };
const sequenceManifestV1 = object({ ...sequenceBase, schema_version: literal(1) });
const sequenceManifestV2 = object({ ...sequenceBase, schema_version: literal(2), state_invariants: array(object({ state: nonnegative, input: inputDigest, status: oneOf(["proved","violated","vacuous","inconsistent","unknown","not_executed"]), verification: nullable(safePath) })) });

function ensure(condition: unknown, message: string): asserts condition { if (!condition) throw new Error(message); }
function same(a: unknown,b:unknown) { return JSON.stringify(a) === JSON.stringify(b); }
function compareDigest(value: {sha256:string;bytes?:number;size_bytes?:number}, source: string) { return value.sha256 === sha256(source) && (value.bytes ?? value.size_bytes) === Buffer.byteLength(source); }

function expectedPlan(canonical:string,selected:boolean,comparison:boolean) {
  const frozen=JSON.parse(canonical) as {clauses?:{name:string;kind:string}[];requirements?:{clauses:{name:string;kind:string}[]};invariants?:string[]};
  const clauses=selected?frozen.requirements!.clauses.filter(c=>frozen.invariants!.includes(c.name)):frozen.clauses!;
  ensure(Array.isArray(clauses)&&clauses.length>0,"frozen evidence has no selected clauses");
  const slug=(name:string)=>name.toLowerCase().replace(/[^a-z0-9]+/g,"-").replace(/^-|-$/g,"")||"unnamed";
  const phase=(phase:string,names:string[][])=>names.map((clauses,i)=>({id:`${phase}-${String(i+1).padStart(2,"0")}-${clauses.map(slug).join("-")}`,phase,clauses}));
  return [
    ...phase("inhabitance",clauses.map(c=>[c.name])),
    ...phase("consistency",clauses.filter(c=>c.kind==="must_not_grant").flatMap(deny=>clauses.filter(c=>c.kind==="must_allow").map(allow=>[deny.name,allow.name]))),
    ...phase("clause",clauses.map(c=>[c.name])),
    ...(comparison?[{id:"preservation-outside-change-scope",phase:"preservation",clauses:[]}]:[]),
  ];
}

/** Reads only regular files from the invocation's private tree; every byte is bounded. */
export async function readEvidenceFiles(directory: string): Promise<Map<string, Buffer>> {
  const files = new Map<string, Buffer>(); let bytes = 0, entries = 0;
  async function walk(relative: string, depth: number) {
    ensure(depth <= 8 && ++entries <= 2 * RBAC_EVIDENCE_LIMITS.files, "evidence directory limits exceeded");
    if(relative) safePath(relative,"evidence path");
    const full = path.join(directory,relative);
    const stat = await lstat(full);
    ensure(!stat.isSymbolicLink(), "evidence contains a symbolic link");
    if (stat.isDirectory()) {
      for (const name of (await readdir(full)).sort()) await walk(relative ? `${relative}/${name}` : name,depth+1);
    } else {
      safePath(relative,"evidence path");
      ensure(stat.isFile(), "evidence contains a nonregular file");
      ensure(files.size < RBAC_EVIDENCE_LIMITS.files && stat.size <= RBAC_EVIDENCE_LIMITS.fileBytes && bytes + stat.size <= RBAC_EVIDENCE_LIMITS.bytes, "evidence exceeds web size limits; use the CLI for this bundle");
      const data = await readFile(full);
      ensure(data.length === stat.size, "evidence file changed while reading");
      bytes += data.length; files.set(relative,data);
    }
  }
  await walk("",0); return files;
}

interface EvidenceRun { mode: RbacMode; candidate: string; baseline?: string; stdout: string; report: RbacReport; profile: RbacProfile; accessProfile: RbacProfile; engine: EngineIdentity }
/** Validate hashes, nested manifests, trace protocol, profiles and the exact accepted report. */
export function validateRbacEvidence(files: Map<string,Buffer>, run: EvidenceRun): JsonValue {
  const seen = new Set<string>();
  function get(name: string): Buffer { safePath(name,"evidence path");const data=files.get(name);ensure(data,`missing evidence artifact ${name}`);seen.add(name);return data; }
  function text(name:string) { return new TextDecoder("utf-8",{fatal:true}).decode(get(name)); }
  function json(name:string): unknown { return JSON.parse(text(name)); }
  function checked(a:{path:string;sha256:string;bytes?:number}, base="") { const name=base+a.path; const data=get(name);ensure(sha256(data)===a.sha256 && (a.bytes===undefined || a.bytes===data.length),`corrupt evidence artifact ${name}`);return name; }
  function identity(executable:string,solver:string|null) {
    ensure(!run.engine.executableSha256 || executable===run.engine.executableSha256,"evidence identifies a different engine");
    ensure(!run.engine.solverVersion || solver===run.engine.solverVersion,"evidence identifies a different solver");
  }
  function traceOutcome(obligations: ReturnType<typeof verificationManifest>["obligations"]): string {
    let result="proved",stopped=false;
    for (const q of obligations) {
      if (stopped) { ensure(q.execution==="not_executed","evidence executed an obligation after a terminal result");continue; }
      ensure(q.execution==="executed","evidence skips a required obligation");
      if (q.solver_result==="unknown") result="unknown";
      else if (q.phase==="inhabitance" && q.solver_result==="unsat") result="vacuous";
      else if (q.phase==="consistency" && q.solver_result==="sat") result="inconsistent";
      else if (["clause","preservation"].includes(q.phase) && q.solver_result==="sat") result="violated";
      stopped=result!=="proved";
    }
    return result;
  }
  function core(base:string, expected:RbacVerifyReport, config:string, baseline?:string) {
    const raw=json(base+"manifest.json");
    const m=baseline===undefined?verificationManifest(raw,"manifest"):comparisonManifest(raw,"manifest");
    ensure(m.result===expected.result,"evidence verdict mismatch");
    if ("config" in m) ensure(compareDigest(m.config,config),"evidence config mismatch");
    else ensure(compareDigest(m.inputs.before,baseline!)&&compareDigest(m.inputs.after,config),"evidence comparison inputs mismatch");
    identity(m.soundcheck.executable_sha256,m.solver.version);
    ensure((m.solver.version===null)!==(m.solver.version_error===null),"incoherent solver identity");
    const reportPath=checked(m.report,base);
    ensure(same(rbacVerifyReport(json(reportPath),"report"),expected),"nested report disagrees with accepted result");
    ensure(text(checked(m.contract,base))===expected.frozen_spec!.canonical+"\n","evidence frozen identity mismatch");
    const profile=rbacProfile(json(checked(m.assurance_profile.artifact,base)),"profile");
    ensure(profile.id===expected.assurance!.profile && profile.id===m.assurance_profile.id && same(profile,run.accessProfile),"evidence access profile mismatch");
    ensure(new Set(m.obligations.map(q=>q.id)).size===m.obligations.length,"duplicate evidence obligations");
    for (const q of m.obligations) checked(q.query,base);
    if (m.obligation_plan.status==="unavailable") {
      ensure(expected.result==="unknown" && expected.assurance!.status==="unsupported" && m.obligations.length===0 && m.obligation_plan.reason!==null,"missing obligation plan cannot carry a proof");
      if ("candidate_report" in m) ensure(m.candidate_report===null,"unavailable comparison has candidate report");
    } else {
      ensure(m.obligation_plan.reason===null && m.obligations.length>0,"complete evidence lacks obligations");
      // A complete trace must retain the frozen clause plan even after an early
      // failure. This checks protocol names/order, not SMT formulas or policy logic.
      const plan=expectedPlan(expected.frozen_spec!.canonical,expected.property==="rbac-sequence-invariants","candidate_report" in m);
      ensure(same(m.obligations.map(q=>({id:q.id,phase:q.phase,clauses:q.clauses})),plan),"evidence omitted or reordered a required obligation");
      ensure(traceOutcome(m.obligations)===expected.result,"evidence execution disagrees with result");
      if ("candidate_report" in m) {
        ensure(m.candidate_report!==null,"comparison evidence lacks candidate report");
        const candidate=rbacVerifyReport(json(checked(m.candidate_report,base)),"candidate report");
        ensure(candidate.property==="kubernetes-rbac-access" && same(candidate.frozen_spec,expected.frozen_spec) && candidate.assurance?.profile===profile.id,"candidate report identity mismatch");
        ensure(traceOutcome(m.obligations.filter(q=>q.phase!=="preservation"))===candidate.result,"candidate execution disagrees with result");
        ensure(m.obligations.at(-1)?.phase==="preservation" && m.obligations.filter(q=>q.phase==="preservation").length===1,"comparison evidence lacks one final preservation obligation");
      } else ensure(m.obligations.every(q=>q.phase!=="preservation"),"verification evidence contains comparison obligation");
    }
    return m;
  }
  ensure(text("report.json")===run.stdout,"evidence report bytes disagree with stdout");
  let manifest:unknown;
  if (!("kind" in run.report)) manifest=core("",run.report,run.candidate,run.mode==="repair"?run.baseline:undefined);
  else {
    const report=run.report;
    const raw=json("manifest.json");
    const m=report.kind==="kubernetes-rbac-policy-change"?changeManifest(raw,"manifest"):report.schema_version===1?sequenceManifestV1(raw,"manifest"):sequenceManifestV2(raw,"manifest");
    manifest=m;
    ensure(m.schema_version===report.schema_version && same(m.inputs,report.inputs),"outer evidence inputs/version mismatch");
    ensure(compareDigest(m.inputs.before,run.baseline!) && compareDigest(m.inputs.after,run.candidate),"outer evidence describes different input bytes");
    identity(m.provenance.executable_sha256,"value" in m.provenance.z3_version?m.provenance.z3_version.value:null);
    const listed=new Set(m.artifacts.map(a=>a.path));
    ensure(listed.size===m.artifacts.length,"duplicate outer evidence artifacts");
    ensure(!listed.has("manifest.json") && listed.size===files.size-1 && [...files.keys()].every(name=>name==="manifest.json"||listed.has(name)),"outer evidence artifact inventory is incomplete");
    for (const a of m.artifacts) checked(a);
    ensure(text("contract.json")===report.frozen_spec!.canonical+"\n","outer evidence frozen identity mismatch");
    ensure(same(rbacProfile(json("profile.json"),"profile"),run.profile),"outer evidence profile mismatch");
    ensure(m.verification===(report.verification?"see verification/manifest.json":"not_executed"),"outer verification execution mismatch");
    if (report.verification) {
      const nested=core("verification/",report.verification.comparison_report,run.candidate,run.baseline);
      const candidate="candidate_report" in nested && nested.candidate_report ? rbacVerifyReport(json("verification/"+nested.candidate_report.path),"candidate") : null;
      ensure(same(candidate,report.verification.candidate_report),"outer candidate report disagrees with evidence");
    }
    if (report.kind==="kubernetes-rbac-policy-sequence") {
      ensure("phase" in m && m.phase===report.phase && m.failing_step===report.failing_step,"sequence phase differs from evidence");
      for (const state of report.states) ensure(compareDigest(state.digest,text(`states/state-${String(state.index).padStart(3,"0")}.json`)),"state snapshot digest mismatch");
      ensure(m.intermediate_preservation.length===report.intermediate_preservation.length,"preservation evidence length mismatch");
      for (const [i,p] of report.intermediate_preservation.entries()) {
        const entry=m.intermediate_preservation[i];
        ensure(entry.step===p.step && entry.status===p.status && (entry.report!==null)===(p.report!==null),"preservation evidence status mismatch");get(entry.query);
        if (entry.report) ensure(same(rbacVerifyReport(json(entry.report),"preservation"),p.report),"preservation report mismatch");
      }
      if ("state_invariants" in report) {
        ensure("state_invariants" in m && m.state_invariants.length===report.state_invariants.length,"invariant evidence length mismatch");
        for (const [i,p] of report.state_invariants.entries()) {
          const entry=m.state_invariants[i];
          ensure(entry.state===p.state && entry.status===p.status && same(entry.input,p.input) && (entry.verification!==null)===(p.report!==null),"invariant evidence status mismatch");
          const base=`invariants/state-${String(p.state).padStart(3,"0")}/`;
          if (p.report) {ensure(entry.verification===base+"manifest.json","invariant evidence path mismatch");core(base,p.report,text(`states/state-${String(p.state).padStart(3,"0")}.json`));}
          else {
            const plan=object({state:nonnegative,input:inputDigest,status:literal("not_executed"),queries:array(object({id:string,path:safePath}))})(json(base+"plan.json"),"skipped invariant plan");
            ensure(plan.state===p.state && same(plan.input,p.input),"skipped invariant plan state/input mismatch");
            const required=expectedPlan(report.frozen_spec!.canonical,true,false).map(q=>({id:q.id,path:`queries/${q.id}.smt2`}));
            ensure(same(plan.queries,required),"skipped invariant plan omits required queries");
            for(const q of plan.queries) get(base+q.path);
          }
        }
      }
    }
  }
  // Outer manifests enumerate planned/skipped query files too. Plain manifests only list executed/planned references.
  ensure(seen.size===files.size,"evidence contains unreferenced files");
  return manifest as JsonValue;
}

export async function readRbacEvidence(directory:string,run:EvidenceRun):Promise<{manifest:JsonValue;archive:RbacEvidenceArchive;canonical:string}> {
  const files=await readEvidenceFiles(directory);
  const manifest=validateRbacEvidence(files,run);
  const zip=zipSync(Object.fromEntries(files),{level:6});
  ensure(zip.length<=RBAC_EVIDENCE_LIMITS.archiveBytes,"compressed evidence exceeds web size limit; use the CLI for this bundle");
  return {manifest,canonical:files.get("contract.json")!.toString("utf8").trimEnd(),archive:{filename:`soundcheck-rbac-${run.mode}-evidence.zip`,mediaType:"application/zip",base64:Buffer.from(zip).toString("base64"),sha256:sha256(zip),bytes:zip.length,fileCount:files.size}};
}
