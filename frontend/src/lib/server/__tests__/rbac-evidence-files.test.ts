import { mkdtemp, mkdir, rm, symlink, truncate, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { RBAC_EVIDENCE_LIMITS, readEvidenceFiles } from "../rbac-evidence";

async function temporary(fn: (directory:string)=>Promise<void>) {
  const directory=await mkdtemp(path.join(os.tmpdir(),"soundcheck-rbac-reader-test-"));
  try {await fn(directory);} finally {await rm(directory,{recursive:true,force:true});}
}
describe("RBAC evidence file boundary",()=>{
  it("reads regular files and rejects links or unsafe path names",async()=>{
    await temporary(async directory=>{
      await writeFile(path.join(directory,"report.json"),"{}\n");
      expect([...(await readEvidenceFiles(directory)).keys()]).toEqual(["report.json"]);
      await symlink(path.join(directory,"report.json"),path.join(directory,"link.json"));
      await expect(readEvidenceFiles(directory)).rejects.toThrow("symbolic link");
    });
    await temporary(async directory=>{
      await writeFile(path.join(directory,"bad\\name.json"),"{}");
      await expect(readEvidenceFiles(directory)).rejects.toThrow("unsafe evidence path");
    });
  });
  it("rejects oversized files before reading and excessive directory depth",async()=>{
    await temporary(async directory=>{
      const file=path.join(directory,"large.smt2");await writeFile(file,"");await truncate(file,RBAC_EVIDENCE_LIMITS.fileBytes+1);
      await expect(readEvidenceFiles(directory)).rejects.toThrow("size limits");
    });
    await temporary(async directory=>{
      await mkdir(path.join(directory,...Array.from({length:9},()=>"nested")),{recursive:true});
      await expect(readEvidenceFiles(directory)).rejects.toThrow("directory limits");
    });
  });
});
