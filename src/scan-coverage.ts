import { access, readFile } from "node:fs/promises";
import path from "node:path";
import fg from "fast-glob";

export type ProjectLanguage = "javascript" | "typescript" | "php" | "java" | "csharp" | "cpp" | "python" | "unknown";

const patterns: readonly [ProjectLanguage, RegExp, string[]][] = [
  ["typescript", /\.(?:ts|tsx|mts|cts)$/i, ["**/*.{ts,tsx,mts,cts}" ]],
  ["javascript", /\.(?:js|jsx|mjs|cjs)$/i, ["**/*.{js,jsx,mjs,cjs}" ]],
  ["php", /\.php$/i, ["**/*.php"]],
  ["java", /\.(?:java|jsp)$/i, ["**/*.{java,jsp}"]],
  ["csharp", /\.(?:cs|cshtml)$/i, ["**/*.{cs,cshtml}"]],
  ["cpp", /\.(?:c|h|cc|cpp|cxx|hpp)$/i, ["**/*.{c,h,cc,cpp,cxx,hpp}"]],
  ["python", /\.py$/i, ["**/*.py"]],
];

export async function detectProjectLanguages(cwd: string): Promise<ProjectLanguage[]> {
  const entries = new Set<ProjectLanguage>();
  const queue = ["package.json", "composer.json", "pom.xml", "requirements.txt", "pyproject.toml"];
  for (const file of queue) {
    try { await access(path.join(cwd, file)); if (file === "package.json") entries.add("javascript"); if (file === "composer.json") entries.add("php"); if (file === "pom.xml") entries.add("java"); if (file.includes("requirements") || file.includes("pyproject")) entries.add("python"); } catch { /* optional manifest */ }
  }
  const source = await readFile(path.join(cwd, "package.json"), "utf8").catch(() => "");
  if (/typescript|@types\//i.test(source)) entries.add("typescript");
  // 语言检测只需采样：使用流式遍历并在采样足够后提前结束，避免整盘扫描时遍历数分钟
  const stream = fg.stream(["**/*.{ts,tsx,mts,cts,js,jsx,mjs,cjs,php,java,jsp,cs,cshtml,c,h,cc,cpp,cxx,hpp,py}"], {
    cwd,
    onlyFiles: true,
    unique: true,
    suppressErrors: true,
    deep: 40,
    followSymbolicLinks: false,
    ignore: ["**/{node_modules,.git,dist,build,coverage,venv,.venv,env,site-packages,__pycache__,.tox}/**"],
  });
  let sampled = 0;
  for await (const entry of stream) {
    entries.add(languageFromFile(String(entry)));
    sampled += 1;
    if (sampled >= 2_000) break;
  }
  entries.delete("unknown");
  return [...entries].length ? [...entries] : ["unknown"];
}

const PROJECT_AUDIT_PATTERNS = [
  "**/.env*",
  "**/*.{json,json5,yaml,yml,toml,ini,conf,config,properties,xml}",
  "**/{Dockerfile,Containerfile,package-lock.json,composer.lock}",
];

export function includePatternsForLanguages(languages: readonly ProjectLanguage[]): string[] {
  return [...new Set([
    ...languages.flatMap((language) => patterns.find(([name]) => name === language)?.[2] ?? []),
    ...PROJECT_AUDIT_PATTERNS,
  ])];
}

export function languageFromFile(file: string): ProjectLanguage {
  return patterns.find(([, pattern]) => pattern.test(file))?.[0] ?? "unknown";
}
