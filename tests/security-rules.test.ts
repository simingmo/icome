import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { scan } from "../src/scanner.js";

const directories: string[] = [];
afterEach(async () => Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))));

async function fixture(name: string, source: string): Promise<string> {
  const cwd = await mkdtemp(path.join(tmpdir(), "lego-rules-"));
  directories.push(cwd);
  const target = path.join(cwd, name);
  await mkdir(path.dirname(target), { recursive: true });
  await writeFile(target, source, "utf8");
  return cwd;
}

describe("独立凭据模块", () => {
  it.each([
    ["const apiKey = 'abcdefghijklmnop';", "security/no-hardcoded-secret"],
    ["const token = 'abcdefghijklmnop';", "security/no-hardcoded-secret"],
    ["AKIA1234567890ABCDEF", "security/no-cloud-access-key"],
    ["-----BEGIN RSA PRIVATE KEY-----", "security/no-private-key"],
    ["-----BEGIN OPENSSH PRIVATE KEY-----", "security/no-private-key"],
  ])("识别并脱敏凭据：%s", async (source, ruleId) => {
    const cwd = await fixture("src/app.ts", source);
    const result = await scan({ cwd, moduleIds: ["@lego-scan/credentials"] });
    const finding = result.findings.find((item) => item.ruleId === ruleId);
    expect(finding).toBeDefined();
    expect(finding?.evidence).toContain("[REDACTED");
    expect(finding?.evidence).not.toContain("abcdefghijklmnop");
    expect(finding?.evidence).not.toContain("AKIA1234567890ABCDEF");
  });

  it.each(["const token = 'short';", "AKIA123", "-----BEGIN PUBLIC KEY-----"])("忽略非凭据内容：%s", async (source) => {
    const cwd = await fixture("src/app.ts", source);
    const result = await scan({ cwd, moduleIds: ["@lego-scan/credentials"] });
    expect(result.findings).toEqual([]);
  });
});

describe("独立配置模块", () => {
  it.each([
    [".env", "APP_DEBUG=true", "configuration/no-debug-mode"],
    ["config.yml", "Access-Control-Allow-Origin: '*'", "configuration/no-wildcard-cors"],
    ["config.js", "const agent = { rejectUnauthorized: false };", "security/no-disabled-tls-verification"],
    ["config.ini", "cookie_secure=false", "configuration/no-insecure-cookie"],
  ])("识别高风险配置 %s", async (name, source, ruleId) => {
    const cwd = await fixture(name, source);
    const result = await scan({ cwd, include: ["**/*", "**/.env*"], moduleIds: ["@lego-scan/configuration"] });
    expect(result.findings.map((item) => item.ruleId)).toContain(ruleId);
    expect(result.executedRules.every((id) => id.includes("configuration") || id === "security/no-disabled-tls-verification")).toBe(true);
  });

  it.each(["APP_DEBUG=false", "Access-Control-Allow-Origin: 'https://example.com'", "rejectUnauthorized: true", "cookie_secure=true"])("忽略安全配置：%s", async (source) => {
    const cwd = await fixture("config.txt", source);
    const result = await scan({ cwd, include: ["**/*.txt"], moduleIds: ["@lego-scan/configuration"] });
    expect(result.findings).toEqual([]);
  });
});

describe("高频注入类规则", () => {
  it.each([
    ["const q = \"SELECT * FROM u WHERE id = \" + req.params.id;", "security/no-sql-injection"],
    ["el.innerHTML = userInput;", "security/no-xss"],
    ["res.send(`<div>${userInput}</div>`);", "security/no-xss"],
    ["fetch(req.query.url);", "security/no-ssrf"],
    ["fs.readFile(req.query.file);", "security/no-path-traversal"],
  ])("识别注入风险：%s", async (source, ruleId) => {
    const cwd = await fixture("src/app.ts", source);
    const result = await scan({ cwd, moduleIds: ["@lego-scan/security"] });
    expect(result.findings.map((item) => item.ruleId)).toContain(ruleId);
  });

  it.each([
    ["const q = \"SELECT * FROM users\";", "security/no-sql-injection"],
    ["el.textContent = userInput;", "security/no-xss"],
    ["fetch(\"https://api.example.com\");", "security/no-ssrf"],
    ["fs.readFile(\"/var/log/app.log\");", "security/no-path-traversal"],
  ])("忽略安全写法：%s", async (source, ruleId) => {
    const cwd = await fixture("src/app.ts", source);
    const result = await scan({ cwd, moduleIds: ["@lego-scan/security"] });
    expect(result.findings.some((item) => item.ruleId === ruleId)).toBe(false);
  });
});

describe("更多安全规则", () => {
  it.each([
    ["const h = crypto.createHash(\"md5\");", "security/no-weak-hash"],
    ["const o = unserialize(data);", "security/no-insecure-deserialization"],
    ["res.redirect(req.query.next);", "security/no-open-redirect"],
    ["const token = Math.random().toString(36);", "security/no-insecure-randomness"],
  ])("识别风险：%s", async (source, ruleId) => {
    const cwd = await fixture("src/app.ts", source);
    const result = await scan({ cwd, moduleIds: ["@lego-scan/security"] });
    expect(result.findings.map((item) => item.ruleId)).toContain(ruleId);
  });

  it.each([
    ["const h = crypto.createHash(\"sha256\");", "security/no-weak-hash"],
    ["const o = JSON.parse(data);", "security/no-insecure-deserialization"],
    ["res.redirect(\"/login\");", "security/no-open-redirect"],
    ["const r = Math.random();", "security/no-insecure-randomness"],
  ])("忽略安全写法：%s", async (source, ruleId) => {
    const cwd = await fixture("src/app.ts", source);
    const result = await scan({ cwd, moduleIds: ["@lego-scan/security"] });
    expect(result.findings.some((item) => item.ruleId === ruleId)).toBe(false);
  });
});
