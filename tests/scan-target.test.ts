import { access, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { gzipSync } from "node:zlib";
import AdmZip from "adm-zip";
import { afterEach, describe, expect, it } from "vitest";
import { cleanupScanTarget, prepareScanTarget } from "../src/scan-target.js";

const cleanup: string[] = [];
afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((target) => rm(target, { recursive: true, force: true })));
});

function buildTar(entries: Array<{ name: string; content: Buffer }>): Buffer {
  const chunks: Buffer[] = [];
  for (const entry of entries) {
    const header = Buffer.alloc(512);
    header.write(entry.name.slice(0, 99), 0, "utf8");
    header.write("0000644\0", 100, "ascii");
    header.write("0000000\0", 108, "ascii");
    header.write("0000000\0", 116, "ascii");
    header.write(entry.content.length.toString(8).padStart(11, "0") + "\0", 124, "ascii");
    header.write("        ", 148, "ascii");
    header.write("0", 156, "ascii");
    header.write("ustar\0" + "00", 257, "ascii");
    let checksum = 0;
    for (const byte of header) checksum += byte;
    header.write(checksum.toString(8).padStart(6, "0") + "\0 ", 148, "ascii");
    chunks.push(header, entry.content);
    const padding = (512 - (entry.content.length % 512)) % 512;
    if (padding) chunks.push(Buffer.alloc(padding));
  }
  chunks.push(Buffer.alloc(1024));
  return Buffer.concat(chunks);
}

describe("扫描目标准备", () => {
  it("支持单个源码文件", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "lego-target-file-"));
    cleanup.push(root);
    const file = path.join(root, "app.ts");
    await writeFile(file, "eval(input);", "utf8");

    const target = await prepareScanTarget(file);
    expect(target).toMatchObject({ originalPath: file, scanCwd: root, kind: "file", include: ["app.ts"], totalFiles: 1 });
  });

  it.each(["zip", "apk", "jar"])("安全展开并准备 .%s ZIP 类压缩包", async (extension) => {
    const root = await mkdtemp(path.join(tmpdir(), "lego-target-archive-"));
    cleanup.push(root);
    const archivePath = path.join(root, `sample.${extension}`);
    const archive = new AdmZip();
    archive.addFile("src/app.ts", Buffer.from("eval(input);", "utf8"));
    archive.addFile("package.json", Buffer.from("{}", "utf8"));
    archive.writeZip(archivePath);

    const target = await prepareScanTarget(archivePath);
    expect(target).toMatchObject({ originalPath: archivePath, kind: "archive", totalFiles: 2 });
    expect(target.scanCwd).not.toBe(root);
    await expect(access(path.join(target.scanCwd, "src", "app.ts"))).resolves.toBeUndefined();

    await cleanupScanTarget(target);
    await expect(access(target.scanCwd)).rejects.toThrow();
  });

  it.each([["sample.tar", false], ["sample.tgz", true], ["sample.tar.gz", true]] as const)("安全展开并准备 %s 压缩包", async (name, gzipped) => {
    const root = await mkdtemp(path.join(tmpdir(), "lego-target-tar-"));
    cleanup.push(root);
    const archivePath = path.join(root, name);
    const tar = buildTar([
      { name: "src/app.ts", content: Buffer.from("eval(input);", "utf8") },
      { name: "package.json", content: Buffer.from("{}", "utf8") },
      { name: "docs/readme.txt", content: Buffer.from("说明", "utf8") },
    ]);
    await writeFile(archivePath, gzipped ? gzipSync(tar) : tar);

    const target = await prepareScanTarget(archivePath);
    expect(target).toMatchObject({ originalPath: archivePath, kind: "archive", totalFiles: 3 });
    expect(target.scanCwd).not.toBe(root);
    await expect(access(path.join(target.scanCwd, "src", "app.ts"))).resolves.toBeUndefined();
    await expect(access(path.join(target.scanCwd, "docs", "readme.txt"))).resolves.toBeUndefined();

    await cleanupScanTarget(target);
    await expect(access(target.scanCwd)).rejects.toThrow();
  });

  it("拒绝不支持的压缩格式和普通二进制文件", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "lego-target-unsupported-"));
    cleanup.push(root);
    const rar = path.join(root, "source.rar");
    const image = path.join(root, "image.png");
    await writeFile(rar, "not-rar", "utf8");
    await writeFile(image, "not-image", "utf8");

    await expect(prepareScanTarget(rar)).rejects.toThrow("暂不支持 .rar 压缩格式");
    await expect(prepareScanTarget(image)).rejects.toThrow("不属于源码或配置文件");
  });
});
