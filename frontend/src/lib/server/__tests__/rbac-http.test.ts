import { describe, expect, it } from "vitest";
import { POST as review } from "../../../app/api/rbac/review/route";
import { POST as run } from "../../../app/api/rbac/run/route";
import { MAX_RBAC_BODY_BYTES } from "../rbac";

function request(path:string,headers:Record<string,string>,body="{}") {
  return new Request(`http://localhost${path}`,{method:"POST",headers:{host:"localhost","content-type":"application/json",...headers},body});
}
describe("RBAC HTTP boundary",()=>{
  it.each([review,run])("rejects foreign hosts/origins before engine work",async route=>{
    for(const headers of [{host:"attacker.invalid"},{origin:"https://attacker.invalid"},{"sec-fetch-site":"cross-site"}] as Record<string,string>[]) {
      expect((await route(request("/api/rbac/run",headers))).status).toBe(403);
    }
  });
  it.each([review,run])("rejects oversized declared and streamed bodies",async route=>{
    expect((await route(request("/api/rbac/run",{"content-length":String(MAX_RBAC_BODY_BYTES+1)}))).status).toBe(413);
    expect((await route(request("/api/rbac/run",{}," ".repeat(MAX_RBAC_BODY_BYTES+1)))).status).toBe(413);
  });
  it.each([review,run])("rejects malformed content and unexpected request fields",async route=>{
    expect((await route(request("/api/rbac/run",{"content-type":"text/plain"}))).status).toBe(415);
    expect((await route(request("/api/rbac/run",{},"{"))).status).toBe(400);
    const response=await route(request("/api/rbac/run",{},JSON.stringify({mode:"verify",contract:"{}",serverPath:"/private/input.json"})));
    expect(await response.json()).toMatchObject({ok:false,stage:"input"});
    expect(response.headers.get("cache-control")).toBe("no-store");
  });
});
