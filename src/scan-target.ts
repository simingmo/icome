import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { gunzipSync } from "node:zlib";
import AdmZip from "adm-zip";

const ZIP_EXTENSIONS = new Set([".zip", ".apk", ".jar", ".war", ".ear", ".whl", ".vsix", ".nupkg"]);
const UNSUPPORTED_ARCHIVES = new Set([".rar", ".7z", ".bz2", ".xz", ".gz"]);
const SCANNABLE_FILES = /(?:\.(?:js|jsx|mjs|cjs|ts|tsx|mts|cts|php|java|jsp|cs|cshtml|c|h|cc|cpp|cxx|hpp|py|json|json5|yaml|yml|toml|ini|conf|config|properties|xml|lock)|(?:^|[\\/])(?:Dockerfile|Containerfile|\.env[^\\/]*|composer\.lock|package-lock\.json))$/i;
const MAX_ENTRIES = 10_000;
const MAX_ENTRY_SIZE = 128 * 1024 * 1024;
const MAX_TOTAL_SIZE = 512 * 1024 * 1024;
const MAX_ARCHIVE_SOURCE_SIZE = 512 * 1024 * 1024;

export type ScanTargetKind = "directory" | "file" | "archive";

export interface PreparedScanTarget {
  originalPath: string;
  scanCwd: string;
  kind: ScanTargetKind;
  include?: string[];
  cleanupPath?: string;
  totalFiles: number;
}

function safeEntryName(name: string): string {
  const normalized = name.replaceAll("\\", "/").replace(/^\.\//, "");
  if (!normalized || normalized.startsWith("/") || /^[A-Za-z]:\//.test(normalized)) {
    throw new Error(`压缩包包含不安全的绝对路径：${name}`);
  }
  const segments = normalized.split("/").filter(Boolean);
  if (segments.includes("..")) throw new Error(`压缩包包含路径穿越条目：${name}`);
  return segments.join("/");
}

async function assertArchiveSourceSize(originalPath: string): Promise<void> {
  const metadata = await stat(originalPath);
  if (metadata.size > MAX_ARCHIVE_SOURCE_SIZE) throw new Error("压缩包源文件超过 512 MB 安全限制");
}

async function prepareArchive(originalPath: string): Promise<PreparedScanTarget> {
  await assertArchiveSourceSize(originalPath);
  const archive = new AdmZip(originalPath);
  const entries = archive.getEntries();
  if (entries.length > MAX_ENTRIES) throw new Error(`压缩包文件数量超过限制（最多 ${MAX_ENTRIES} 个条目）`);

  let totalSize = 0;
  for (const entry of entries) {
    safeEntryName(entry.entryName);
    if (entry.header.encripted) throw new Error(`暂不支持加密压缩包：${entry.entryName}`);
    if (entry.header.size > MAX_ENTRY_SIZE) throw new Error(`压缩包内单个文件超过 128 MB：${entry.entryName}`);
    totalSize += entry.header.size;
    if (totalSize > MAX_TOTAL_SIZE) throw new Error("压缩包解压后总大小超过 512 MB 安全限制");
  }

  const root = await mkdtemp(path.join(tmpdir(), "lego-scan-archive-"));
  try {
    let fileCount = 0;
    let actualTotalSize = 0;
    for (const entry of entries) {
      const name = safeEntryName(entry.entryName);
      if (!name) continue;
      const destination = path.resolve(root, ...name.split("/"));
      const relative = path.relative(root, destination);
      if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
        throw new Error(`压缩包条目超出安全目录：${entry.entryName}`);
      }
      if (entry.isDirectory) {
        await mkdir(destination, { recursive: true });
        continue;
      }
      const data = archive.readFile(entry);
      if (!data) throw new Error(`无法读取压缩包条目：${entry.entryName}`);
      if (data.length > MAX_ENTRY_SIZE) throw new Error(`压缩包内单个文件实际大小超过 128 MB：${entry.entryName}`);
      actualTotalSize += data.length;
      if (actualTotalSize > MAX_TOTAL_SIZE) throw new Error("压缩包实际解压总大小超过 512 MB 安全限制");
      await mkdir(path.dirname(destination), { recursive: true });
      await writeFile(destination, data);
      fileCount += 1;
    }
    return { originalPath, scanCwd: root, kind: "archive", cleanupPath: root, totalFiles: fileCount };
  } catch (error) {
    await rm(root, { recursive: true, force: true });
    throw error;
  }
}

interface TarEntry { name: string; size: number; isDirectory: boolean; data: Buffer; }

function parseTar(buffer: Buffer): TarEntry[] {
  const entries: TarEntry[] = [];
  let offset = 0;
  let longName: string | null = null;
  while (offset + 512 <= buffer.length) {
    const header = buffer.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const name = header.toString("utf8", 0, 100).replace(/\0[\s\S]*$/, "");
    const prefix = header.toString("utf8", 345, 500).replace(/\0[\s\S]*$/, "");
    const size = Number.parseInt(header.toString("ascii", 124, 136).trim(), 8) || 0;
    const typeFlag = String.fromCharCode(header[156] ?? 0x30);
    const dataStart = offset + 512;
    if (dataStart + size > buffer.length) throw new Error("TAR 数据不完整或压缩包已损坏");
    const data = buffer.subarray(dataStart, dataStart + size);
    offset = dataStart + Math.ceil(size / 512) * 512;
    const resolved = longName ?? (prefix ? `${prefix}/${name}` : name);
    if (typeFlag === "L") { longName = data.toString("utf8").replace(/\0[\s\S]*$/, "").trim(); continue; }
    if (typeFlag === "x" || typeFlag === "g") { const match = data.toString("utf8").match(/(?:^|\n)\d+ path=([^\n]+)/); if (match) longName = match[1]!; continue; }
    longName = null;
    if (typeFlag === "5" || resolved.endsWith("/")) { entries.push({ name: resolved, size: 0, isDirectory: true, data: Buffer.alloc(0) }); continue; }
    if (typeFlag !== "0" && typeFlag !== "\0" && typeFlag !== "7") continue;
    entries.push({ name: resolved, size, isDirectory: false, data });
  }
  return entries;
}

async function prepareTarArchive(originalPath: string, gzipped: boolean): Promise<PreparedScanTarget> {
  await assertArchiveSourceSize(originalPath);
  let buffer = await readFile(originalPath);
  if (gzipped) buffer = gunzipSync(buffer, { maxOutputLength: MAX_TOTAL_SIZE });
  const entries = parseTar(buffer);
  if (entries.length > MAX_ENTRIES) throw new Error(`压缩包文件数量超过限制（最多 ${MAX_ENTRIES} 个条目）`);
  let totalSize = 0;
  for (const entry of entries) {
    safeEntryName(entry.name);
    if (entry.size > MAX_ENTRY_SIZE) throw new Error(`压缩包内单个文件超过 128 MB：${entry.name}`);
    totalSize += entry.size;
    if (totalSize > MAX_TOTAL_SIZE) throw new Error("压缩包解压后总大小超过 512 MB 安全限制");
  }
  const root = await mkdtemp(path.join(tmpdir(), "lego-scan-archive-"));
  try {
    let fileCount = 0;
    for (const entry of entries) {
      const name = safeEntryName(entry.name);
      if (!name) continue;
      const destination = path.resolve(root, ...name.split("/"));
      const relative = path.relative(root, destination);
      if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
        throw new Error(`压缩包条目超出安全目录：${entry.name}`);
      }
      if (entry.isDirectory) { await mkdir(destination, { recursive: true }); continue; }
      await mkdir(path.dirname(destination), { recursive: true });
      await writeFile(destination, entry.data);
      fileCount += 1;
    }
    return { originalPath, scanCwd: root, kind: "archive", cleanupPath: root, totalFiles: fileCount };
  } catch (error) {
    await rm(root, { recursive: true, force: true });
    throw error;
  }
}

export async function prepareScanTarget(originalPath: string): Promise<PreparedScanTarget> {
  let metadata;
  try {
    metadata = await stat(originalPath);
  } catch {
    throw new Error(`扫描目标不存在或无法访问：${originalPath}`);
  }

  if (metadata.isDirectory()) return { originalPath, scanCwd: originalPath, kind: "directory", totalFiles: 0 };
  if (!metadata.isFile()) throw new Error(`扫描目标不是普通文件或目录：${originalPath}`);

  const extension = path.extname(originalPath).toLowerCase();
  if (ZIP_EXTENSIONS.has(extension)) return prepareArchive(originalPath);
  if (extension === ".tar" || extension === ".tgz" || (extension === ".gz" && originalPath.toLowerCase().endsWith(".tar.gz"))) return prepareTarArchive(originalPath, extension !== ".tar");
  if (UNSUPPORTED_ARCHIVES.has(extension)) {
    throw new Error(`暂不支持 ${extension} 压缩格式；当前支持 ZIP、APK、JAR、WAR、EAR、WHL、VSIX、NUPKG、TAR、TGZ（tar.gz）。RAR、7Z 等请先转换为支持的格式`);
  }
  if (!SCANNABLE_FILES.test(originalPath)) {
    throw new Error(`该文件类型不属于源码或配置文件，暂无法检查：${path.basename(originalPath)}`);
  }
  return {
    originalPath,
    scanCwd: path.dirname(originalPath),
    kind: "file",
    include: [path.basename(originalPath)],
    totalFiles: 1,
  };
}

export async function cleanupScanTarget(target: Pick<PreparedScanTarget, "cleanupPath">): Promise<void> {
  if (target.cleanupPath) await rm(target.cleanupPath, { recursive: true, force: true });
}

export async function prepareScanTargets(originalPaths: readonly string[]): Promise<PreparedScanTarget[]> {
  const prepared: PreparedScanTarget[] = [];
  try {
    for (const originalPath of originalPaths) prepared.push(await prepareScanTarget(originalPath));
    return prepared;
  } catch (error) {
    await Promise.allSettled(prepared.map((target) => cleanupScanTarget(target)));
    throw error;
  }
}
