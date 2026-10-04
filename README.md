# Lego Security Scanner

`v0.3.0` 采用乐高式模块化架构：每项扫描能力都是可独立注册、组合和复用的积木模块。

## 架构

```text
扫描配置
  → 模块注册表
  → 预设展开
  → 依赖与版本解析
  → 冲突及循环检查
  → 规则过滤
  → 文件扫描
  → 标准化报告
```

核心积木：

- `@lego-scan/security`：密钥、动态代码和命令注入检查
- `@lego-scan/credentials`：硬编码密钥、私钥和云访问密钥检查
- `@lego-scan/configuration`：TLS 等安全配置检查
- `@lego-scan/testing`：跳过测试、聚焦测试、空测试和弱断言检查
- `@lego-scan/dependency-audit`：npm audit 与 Composer audit 依赖漏洞检查
- `@lego-scan/osv`：基于 OSV 漏洞数据库的依赖漏洞查询
- `@lego-scan/git-history`：Git 历史中的凭据泄露检查
- `@lego-scan/recommended`：装配内置静态检查积木的默认预设
- `@lego-scan/audit`：装配全部内置积木的一键全量审计预设

未指定模块或预设时，扫描器自动使用推荐预设。显式设置 `moduleIds` 时，仅装配指定模块及其传递依赖。

## 一键全量审计

同时执行代码审计（静态规则）与漏洞审计（依赖漏洞、Git 历史泄密）：

```powershell
node dist/cli.js . --audit
```

等价于 `--preset @lego-scan/audit`，会额外运行 npm audit / Composer audit、OSV 漏洞库查询和 Git 历史凭据检查（存在对应锁文件或 Git 仓库时）。

Web 面板（`npm run panel`）创建扫描任务时可勾选「依赖漏洞审计」复选框，为该任务装配同样的漏洞审计积木。

仓库根目录的 `dispositions.json` 登记了本仓库自身已核实的误报（环境变量注入、规则源码自触发等），配合 `--dispositions` 使用可让报告聚焦真实问题：

```powershell
node dist/cli.js . --exclude tools/** --dispositions dispositions.json
```

`tools/` 下为 Seay/RIPS/VCG 外部审计工具自带的第三方代码，扫描业务代码时建议排除。

## 扫描目标

命令行目标可以是目录、单个源码/配置文件或压缩包，可混合指定多个：

```powershell
node dist/cli.js .
node dist/cli.js D:\projects\my-app
node dist/cli.js C:\inetpub\www\config.php --audit
node dist/cli.js app.zip --audit
node dist/cli.js index.php app.zip D:\code
```

以上命令在 cmd 与 PowerShell 中均可直接复制运行，注意不要把说明性文字跟在命令后面（cmd 不支持 `#` 注释）。依次为：当前目录递归扫描、任意目录、单个文件、压缩包（ZIP/APK/JAR/WAR/EAR/WHL/VSIX/NUPKG）、混合目标。

单文件目标支持常见源码与配置类型（js/ts/php/java/cs/py/json/yaml/xml/Dockerfile/.env 等）；压缩包会先在临时目录安全解压（含路径穿越与体积防护）再扫描；不支持的文件类型会给出明确错误。`node dist/cli.js --whole-computer --audit` 可扫描本机全部固定磁盘。

## 标准基线

- NIST SSDF `1.1`
- OWASP ASVS `5.0.0`
- OWASP WSTG `4.2`
- OWASP SAMM `2.2.0`
- MITRE CWE `4.20`

标准映射用于问题追踪和测试规划，不表示仅运行扫描器即可证明完全合规。

## 安装和验证

要求 Node.js 20+：

```powershell
npm install
npm run verify
node dist/cli.js .
```

生成 JSON 报告：

```powershell
node dist/cli.js . --format json --output scan-report.json
```

## 选择积木

只启用测试检查：

```ts
import { scan } from "lego-security-scanner";

const result = await scan({
  cwd: process.cwd(),
  moduleIds: ["@lego-scan/testing"],
});
```

## 创建自定义积木

```ts
import {
  patternRule,
  type ScannerModule,
} from "lego-security-scanner";

export const baseModule: ScannerModule = {
  id: "@company/base-security",
  version: "1.0.0",
  rules: [
    patternRule({
      id: "company/no-debugger",
      description: "禁止提交调试语句",
      severity: "medium",
      confidence: "high",
      category: "security",
      pattern: /debugger\s*;/,
      message: "发现 debugger 语句。",
      suggestion: "提交前移除 debugger。",
    }),
  ],
};
```

## 依赖积木

```ts
export const strictModule: ScannerModule = {
  id: "@company/strict-security",
  version: "1.0.0",
  dependencies: [
    { id: "@company/base-security", version: "^1.0.0" },
  ],
  rules: [],
};
```

解析器会自动：

- 补齐传递依赖
- 按依赖优先顺序装配
- 校验 SemVer 版本范围
- 拒绝缺失依赖
- 拒绝循环依赖
- 拒绝冲突模块
- 拒绝重复模块、预设和规则 ID

## 注册表和预设

```ts
import {
  ScannerModuleRegistry,
  scan,
  type ScanPreset,
} from "lego-security-scanner";

const ciPreset: ScanPreset = {
  id: "@company/ci",
  modules: ["@company/strict-security", "@lego-scan/testing"],
  rules: {
    severityOverrides: {
      "security/no-hardcoded-secret": "critical",
    },
  },
};

const registry = new ScannerModuleRegistry();
registry.registerModule(baseModule);
registry.registerModule(strictModule);
registry.registerPreset(ciPreset);

const result = await scan({
  cwd: process.cwd(),
  registry,
  preset: "@company/ci",
});
```

## 兼容旧插件

原有 `ScannerPlugin` 接口继续可用，扫描器会自动将旧插件转换为无依赖积木并参与统一装配：

```ts
await scan({ cwd: process.cwd(), plugins: [legacyPlugin] });
```

## 测试与门禁

```powershell
npm run check
npm test
npm run build
```

一次完成全部验证：

```powershell
npm run verify
```

当前扫描器负责静态规则与测试代码检查，不能替代依赖漏洞数据库、人工审计、动态测试、模糊测试和渗透测试。
