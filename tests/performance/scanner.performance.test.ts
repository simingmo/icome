import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { scan } from "../../src/scanner.js";

const directories: string[] = [];
afterAll(async () => Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))));

async function largeProject(fileCount: number): Promise<string> {
  const cwd = await mkdtemp(path.join(tmpdir(), "lego-performance-"));
  directories.push(cwd);
  await mkdir(path.join(cwd, "src"), { recursive: true });
  await Promise.all(Array.from({ length: fileCount }, (_, index) => writeFile(
    path.join(cwd, "src", `module-${index}.ts`),
    index % 100 === 0 ? "eval(userInput);" : `export const value${index} = ${index};`,
    "utf8",
  )));
  return cwd;
}

describe("大型项目性能基线", () => {
  it("扫描 1000 个源码文件并保持结果完整", async () => {
    const cwd = await largeProject(1_000);
    const startedAt = performance.now();
    const result = await scan({ cwd, include: ["src/**/*.ts"] });
    const elapsedMs = performance.now() - startedAt;
    expect(result.scannedFiles).toBe(1_000);
    expect(result.findings.filter((finding) => finding.ruleId === "security/no-eval")).toHaveLength(10);
    expect(result.status).toBe("succeeded");
    expect(elapsedMs).toBeLessThan(60_000);
  });
});
