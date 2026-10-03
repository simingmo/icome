import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { access, mkdir, readFile, realpath, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import fg from "fast-glob";
import { DEFAULT_EXCLUDE, TEST_EXCLUDE, isTestPath, scan } from "./scanner.js";
import { createAuditSuiteModule } from "./modules/audit-suite-module.js";
import { configurationModule, credentialsModule, dependencyAuditModule, gitHistoryModule, osvModule, securityModule, testingModule } from "./modules/builtin-modules.js";
import { renderJson } from "./reporters.js";
import { detectProjectLanguages, includePatternsForLanguages, type ProjectLanguage } from "./scan-coverage.js";
import { diffScanResults } from "./report-diff.js";
import type { ScanResult } from "./contracts.js";
import { cleanupScanTarget, prepareScanTarget } from "./scan-target.js";
import { aiAnalyzerFromEnvironment } from "./ai.js";
import type { DashboardPayload, DashboardReport, Job, PanelOptions, PublicJob, SeverityName, ToolStatus as PanelToolStatus } from "./panel-types.js";

export type { PanelOptions } from "./panel-types.js";

const severityText: Record<SeverityName, string> = { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "提示" };
const statusText: Record<Job["status"], string> = { queued: "排队中", running: "扫描中", succeeded: "扫描完成", partial: "部分完成（含诊断）", failed: "扫描失败", "no-files": "没有可检查文件" };
const MAX_REQUEST_BYTES = 64 * 1024;
const MAX_SCAN_FILES = 10_000;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "::1"]);
function escapeHtml(value: unknown): string { return String(value ?? "").replace(/[&<>"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[char] as string)); }
function secureHeaders(contentType: string): Record<string, string> { return { "content-type": contentType, "cache-control": "no-store", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer" }; }
function tokenMatches(actual: string | undefined, expected: string): boolean { if (!actual) return false; const left = Buffer.from(actual); const right = Buffer.from(expected); return left.length === right.length && timingSafeEqual(left, right); }
function isAuthorized(req: IncomingMessage, token: string): boolean { const header = req.headers.authorization; return Boolean(header?.startsWith("Bearer ") && tokenMatches(header.slice(7), token)); }
function publicTarget(job: Job): string { return job.targetKind === "archive" ? path.basename(job.cwd) : job.cwd; }
function sanitizeResult(result: ScanResult | undefined): ScanResult | undefined { if (!result) return undefined; const { scannedFileList: _scannedFileList, ...rest } = result; return { ...rest, findings: rest.findings.map(({ evidence: _evidence, ...finding }) => ({ ...finding, evidence: "[REDACTED]" })), diagnostics: rest.diagnostics.map(({ details: _details, message: _message, ...diagnostic }) => ({ ...diagnostic, message: "扫描诊断已隐藏" })) }; }
function publicJob(job: Job): PublicJob { return { id: job.id, status: job.status, createdAt: job.createdAt, ...(job.finishedAt ? { finishedAt: job.finishedAt } : {}), target: publicTarget(job), targetKind: job.targetKind, tools: job.tools, ...(job.dependencyAudit ? { dependencyAudit: job.dependencyAudit } : {}), totalFiles: job.totalFiles, ...(job.languages ? { languages: job.languages } : {}), ...(job.result ? { result: sanitizeResult(job.result)! } : {}), ...(job.error ? { error: job.status === "failed" ? "扫描失败，请查看本地报告" : job.error } : {}) }; }
function renderTools(tools: PanelToolStatus[]): string { return tools.map((tool) => `<label title="${escapeHtml(tool.reason || "可用")}"><input type="checkbox" data-tool value="${escapeHtml(tool.id)}" ${tool.available ? "" : "disabled"}> ${escapeHtml(tool.label)}${tool.available ? "" : "（不可用）"}</label>`).join("") + '<span class="muted">不勾选时仅运行内置规则</span>'; }

function renderReportRow(report: DashboardReport): string {
  return `<div class="row"><span>${escapeHtml(report.id.slice(0, 8))}</span><span class="path">${escapeHtml(report.scanPath)}</span><span>${escapeHtml(report.reportName)}</span><span class="path">${escapeHtml(report.problem ? `问题：${report.problem}；建议：${report.suggestion}；位置：${report.filePath}` : (report.error || report.reportPath))}</span><span class="sev-${escapeHtml(report.severity)}">${escapeHtml(severityText[report.severity] ?? "—")}</span><span>${escapeHtml(statusText[report.status] ?? report.status)}${report.fingerprint ? ` <button class="ai-button" onclick="analyze('${escapeHtml(report.id)}','${escapeHtml(report.fingerprint)}',this)">AI 分析</button>` : ""}</span></div>`;
}

function renderReportRows(reports: readonly DashboardReport[]): string {
  if (!reports.length) return '<span class="muted">暂无报告</span>';
  const groups = new Map<string, DashboardReport[]>();
  for (const report of reports) {
    const list = groups.get(report.id) ?? [];
    list.push(report);
    groups.set(report.id, list);
  }
  const head = '<div class="row row-head"><span>任务</span><span>扫描目录</span><span>问题报告</span><span>具体问题/位置</span><span>等级</span><span>状态</span></div>';
  let html = "";
  let first = true;
  for (const [id, rows] of groups) {
    const lead = rows[0]!;
    html += `<details class="job-group" data-job="${escapeHtml(id)}"${first ? " open" : ""}><summary><span>任务 ${escapeHtml(id.slice(0, 8))}</span><span class="path">${escapeHtml(lead.scanPath)}</span><span>${rows.length} 条</span><span class="muted">${escapeHtml(statusText[lead.status] ?? lead.status)}</span><span><button class="ai-button" onclick="event.preventDefault();showFiles('${escapeHtml(id)}')">文件清单</button></span></summary>${head}${rows.map(renderReportRow).join("")}</details>`;
    first = false;
  }
  return html;
}
function renderPanelHtml(input: { currentDirectory: string; tools: PanelToolStatus[]; dashboard: DashboardPayload }): string {
  const dashboard = input.dashboard;
  const currentDirectory = escapeHtml(input.currentDirectory);
  const toolsHtml = renderTools(input.tools);
  const metricsHtml = [["扫描任务", String(dashboard.jobs)], ["漏洞总数", String(dashboard.findings)], ["高危及以上", String(dashboard.high)], ["已扫描 / 发现文件", `${dashboard.files} / ${dashboard.totalFiles}`]].map(([label, value]) => `<div class="card">${label}<div class="metric">${value}</div></div>`).join("");
  const severityHtml = (Object.entries(dashboard.severity) as [SeverityName, number][]).map(([key, value]) => `<div><span class="sev-${key}">${severityText[key] ?? key}：${value}</span><div class="bar"><div class="fill" style="width:${(value / (dashboard.findings || 1)) * 100}%"></div></div></div>`).join("");
  const rowsHtml = renderReportRows(dashboard.reports);
  const initialTruncated = "";
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>LEGO Security Panel</title><style>*{box-sizing:border-box}body{margin:0;background:#0b1020;color:#e8eefc;font:14px system-ui,-apple-system,Segoe UI,sans-serif}main{max-width:1180px;margin:0 auto;padding:28px}.hero{display:flex;justify-content:space-between;align-items:end;gap:20px;margin-bottom:24px}.muted{color:#91a0bd}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.card,.panel{min-width:0;background:#121a2e;border:1px solid #243454;border-radius:8px;padding:18px;box-shadow:0 10px 25px #0002}.metric{font-size:30px;font-weight:700;margin-top:8px}.mode{display:flex;gap:18px;align-items:center;margin:12px 0}.form{display:grid;grid-template-columns:1fr auto auto;gap:10px;margin:12px 0}.form input{background:#0d1426;color:#fff;border:1px solid #32466f;border-radius:8px;padding:12px}.form select{background:#0d1426;color:#fff;border:1px solid #32466f;border-radius:8px;padding:12px;cursor:pointer}.form input:disabled{opacity:.55;cursor:not-allowed}.target{margin:8px 0;color:#b9c8e8;overflow-wrap:anywhere}.checks{display:flex;flex-wrap:wrap;gap:14px;align-items:center;margin:12px 0}.checks label{white-space:normal}.scope{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:flex-end}.scope select{max-width:100%;background:#0d1426;color:#fff;border:1px solid #32466f;border-radius:8px;padding:9px}.button{background:#5b8cff;color:#fff;border:0;border-radius:8px;padding:11px 16px;cursor:pointer}.ai-button{background:#263d70;color:#dce7ff;border:1px solid #5274b8;border-radius:6px;padding:4px 7px;cursor:pointer;font-size:12px}.bar{height:12px;background:#253352;border-radius:8px;overflow:hidden;margin:8px 0}.fill{height:100%;background:#5b8cff}.rows{margin-top:18px}.pager{margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}.job-group{border:1px solid #243454;border-radius:8px;margin:10px 0;padding:0 14px;background:#0f1729}.job-group summary{cursor:pointer;padding:12px 0;display:grid;grid-template-columns:80px minmax(120px,1fr) 70px 100px 90px;gap:12px;align-items:center;color:#c6d4f0;font-weight:600}.job-group summary:hover{color:#fff}.job-group[open] summary{border-bottom:1px solid #243454;margin-bottom:4px}.file-list{padding:10px 2px;border-top:1px dashed #243454;margin-top:8px;max-height:320px;overflow-y:auto}.file-list div{padding:1px 0;color:#b9c8e8;font-size:12px;overflow-wrap:anywhere}.tabs{display:flex;gap:6px;margin-right:12px}.tab{padding:8px 16px;border:1px solid #2c3e64;background:#0d1426;color:#b9c8e8;border-radius:8px;cursor:pointer;font-size:13px}.tab.active{background:#2f6df6;border-color:#2f6df6;color:#fff}.spin-icon{display:inline-block;margin-right:6px;transition:transform .5s ease}.spinning .spin-icon{animation:spin .9s linear infinite}.spinning{opacity:.7;pointer-events:none;transition:opacity .3s}@keyframes spin{to{transform:rotate(360deg)}}.file-row:hover{background:#1a2540;border-radius:4px}.code-pre{background:#0d1426;border:1px solid #243454;border-radius:8px;padding:10px;overflow:auto;max-height:420px;font:12px ui-monospace,Consolas,monospace;white-space:pre;margin:4px 0 10px}.code-line{display:block}.code-bad{background:#4a1620}.code-tag{margin-right:8px;font-size:11px}.row{display:grid;grid-template-columns:90px minmax(140px,1fr) minmax(170px,1.2fr) minmax(240px,1.8fr) 80px 100px;gap:12px;padding:12px 0;border-bottom:1px solid #243454;align-items:center}.row-head{color:#91a0bd;font-weight:600}.path{overflow-wrap:anywhere}.sev-critical{color:#ff6b81}.sev-high{color:#ff9b6b}.sev-medium{color:#ffd166}.sev-low{color:#70d6ff}.sev-info{color:#9aa7bd}@media(max-width:940px){.hero{align-items:flex-start;flex-direction:column}.scope{justify-content:flex-start}.row{grid-template-columns:repeat(6,minmax(0,1fr));font-size:12px;gap:8px}}@media(max-width:750px){main{padding:16px}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.form{grid-template-columns:1fr}.row{grid-template-columns:1fr 1fr}.row-head{display:none}.row:not(.row-head) span{min-width:0}.row:not(.row-head) span:nth-child(1)::before{content:"任务："}.row:not(.row-head) span:nth-child(2)::before{content:"目录："}.row:not(.row-head) span:nth-child(3)::before{content:"报告："}.row:not(.row-head) span:nth-child(4)::before{content:"问题："}.row:not(.row-head) span:nth-child(5)::before{content:"等级："}.row:not(.row-head) span:nth-child(6)::before{content:"状态："}}@media(max-width:480px){.grid{grid-template-columns:1fr 1fr;gap:8px}.card,.panel{padding:14px}.metric{font-size:24px}.scope select,.scope .button{flex:1 1 100%}}</style></head><body><main><section class="hero"><div><h1>LEGO Security Panel</h1><div class="muted">本地离线源码安全审计面板</div></div><div class="scope"><div class="tabs"><button class="tab active" id="tab-report" type="button" onclick="switchTab('report')">扫描报告</button><button class="tab" id="tab-files" type="button" onclick="switchTab('files')">文件清单</button></div><select id="scope" onchange="loadPage(1)"><option value="latest">最近一次扫描</option><option value="all">全部历史累计</option></select><select id="type" onchange="loadPage(1)"><option value="all">全部类型</option><option value="source">仅真实源码</option><option value="test">仅测试代码</option></select><button class="button" id="refresh-btn" onclick="refreshNow()"><span class="spin-icon">⟳</span>刷新</button></div></section><section class="panel" id="page-files" style="display:none"><h2>文件清单</h2><div class="muted">选择扫描任务，列出目录中的全部文件（未被检查的文件标注「未检查」）；点击文件行可预览源码（问题行高亮）。</div><div class="form" style="align-items:center;flex-wrap:wrap"><select id="files-job" style="max-width:420px" onchange="loadFilesList()"></select><input id="files-filter" placeholder="按路径筛选，例如 server.xml" oninput="renderFilesList()" style="flex:1;min-width:180px"><label style="display:flex;align-items:center;gap:6px;color:#b9c8e8;margin:0;white-space:nowrap"><input type="checkbox" id="files-only-bad" onchange="renderFilesList()"> 仅显示有问题的文件</label></div><div id="files-list" class="file-list"></div></section><section class="panel report-section"><h2>创建扫描任务</h2><div class="muted">可扫描目录、单个源码或配置文件，以及 ZIP、APK、JAR、TAR、TGZ（tar.gz）等压缩包（RAR、7Z 请先转换为支持格式）。</div><div class="form" style="grid-template-columns:auto 1fr auto auto"><select id="drives" onchange="pickDrive(this)" title="选择盘符，快速填入扫描路径"><option value="">盘符</option></select><input id="cwd" value="${currentDirectory}" placeholder="请输入目录或文件，例如 E:\\项目\\app.zip" oninput="updateTarget()" onchange="updateTarget()"><button class="button" onclick="resetDirectory()">恢复当前目录</button><button class="button" onclick="start()">开始扫描</button></div><div id="target" class="target">最终扫描目标：${currentDirectory}</div><label style="display:flex;align-items:center;gap:8px;margin:8px 0;color:#b9c8e8"><input type="checkbox" id="includeTests"> 包含测试目录（默认排除 tests 与 *.test/*.spec 文件）</label><label style="display:flex;align-items:center;gap:8px;margin:8px 0;color:#b9c8e8"><input type="checkbox" id="dependencyAudit"> 依赖漏洞审计（npm/composer audit、OSV 漏洞库、Git 历史泄密）</label><div class="checks" id="tools">${toolsHtml}</div><div id="form-message" class="muted"></div></section><section class="grid report-section" id="metrics">${metricsHtml}</section><section class="panel report-section" style="margin-top:18px"><h2>严重度分布</h2><div id="severity">${severityHtml}</div></section><section class="panel report-section" style="margin-top:18px"><h2>历史报告与漏洞位置 <button class="button" style="padding:6px 10px;font-size:12px" onclick="expandAll(true)">全部展开</button> <button class="button" style="padding:6px 10px;font-size:12px" onclick="expandAll(false)">全部折叠</button></h2><div id="rows" class="rows">${rowsHtml}</div><div id="pager" class="pager"></div><div id="truncated" class="muted" role="status"></div><div id="refresh-error" class="muted" role="status"></div></section></main><script>const esc=s=>String(s??'').replace(/[&<>\"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c]));const panelToken=new URLSearchParams(globalThis.location?.hash?.slice(1)||'').get('token')||'';async function api(u,o={}){const headers={...(o.headers||{}),...(panelToken?{authorization:'Bearer '+panelToken}:{})};const r=await fetch(u,{...o,headers});const d=await r.json();if(!r.ok)throw new Error(d.error||('请求失败：'+r.status));return d}let currentDirectory='';async function loadConfig(){const d=await api('/api/config');currentDirectory=d.currentDirectory;const input=document.querySelector('#cwd');if(!input.value)input.value=currentDirectory;updateTarget()}function updateTarget(){const selected=document.querySelector('#cwd').value.trim()||'尚未填写扫描目标';document.querySelector('#target').textContent='最终扫描目标：'+selected}window.addEventListener('pageshow',updateTarget);window.addEventListener('focus',updateTarget);document.addEventListener('visibilitychange',updateTarget);function resetDirectory(){document.querySelector('#cwd').value=currentDirectory;updateTarget();document.querySelector('#form-message').textContent=''}async function loadTools(){const d=await api('/api/tools');document.querySelector('#tools').innerHTML=d.tools.map(t=>'<label title="'+esc(t.reason||'可用')+'"><input type="checkbox" data-tool value="'+esc(t.id)+'" '+(t.available?'':'disabled')+'> '+esc(t.label)+(t.available?'':'（不可用）')+'</label>').join('')+'<span class="muted">不勾选时仅运行内置规则</span>'}async function waitForScan(id){const message=document.querySelector('#form-message');for(let attempt=0;attempt<900;attempt+=1){const job=await api('/api/scans/'+encodeURIComponent(id));message.textContent='任务 '+id.slice(0,8)+'：'+(statusText[job.status]||job.status);if(!['queued','running'].includes(job.status)){await load();return job}await new Promise(resolve=>setTimeout(resolve,1000))}throw new Error('扫描等待超时，请检查后台任务状态')}async function start(){const message=document.querySelector('#form-message');message.textContent='正在创建任务…';try{const cwd=document.querySelector('#cwd').value.trim();if(!cwd)throw new Error('请填写扫描目录或文件');document.querySelector('#target').textContent='最终扫描目标：'+cwd;const tools=[...document.querySelectorAll('input[data-tool]:checked')].map(x=>x.value);const job=await api('/api/scans',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({cwd,tools,includeTests:document.querySelector('#includeTests').checked,dependencyAudit:document.querySelector('#dependencyAudit').checked})});message.textContent='任务 '+job.id.slice(0,8)+'：'+(statusText[job.status]||job.status);await waitForScan(job.id)}catch(e){message.textContent='扫描失败：'+e.message}}const severityText={critical:'严重',high:'高危',medium:'中危',low:'低危',info:'提示'};async function analyze(jobId,fingerprint,button){button.disabled=true;button.textContent='分析中…';try{const d=await api('/api/scans/'+encodeURIComponent(jobId)+'/findings/'+encodeURIComponent(fingerprint)+'/ai-analysis',{method:'POST'});alert('AI 分析\\n\\n风险：'+d.risk+'\\n\\n说明：'+d.summary+'\\n\\n修复建议：'+d.remediation)}catch(e){alert('AI 分析失败：'+e.message)}finally{button.disabled=false;button.textContent='AI 分析'}}const statusText={queued:'排队中',running:'扫描中',succeeded:'扫描完成',partial:'部分完成（含诊断）',failed:'扫描失败','no-files':'没有可检查文件'};function isTestPath(p){const inner=String(p||'').replace(/^[^!]*!\\//,'');return /(?:^|[\\/])(?:tests?|__tests__|spec)(?:[\\/]|$)/i.test(inner)||/\\.(?:test|spec)\\.[cm]?[jt]sx?$/i.test(inner)}const rowState=new Map();let lastReports=[];let currentPage=1;const filesCache=new Map();let currentFilesJob='';let filesData=null;function switchTab(name){const isFiles=name==='files';document.getElementById('page-files').style.display=isFiles?'':'none';document.querySelectorAll('.report-section').forEach(s=>{s.style.display=isFiles?'none':''});document.getElementById('tab-report').classList.toggle('active',!isFiles);document.getElementById('tab-files').classList.toggle('active',isFiles);if(isFiles)loadJobOptions()}async function showFiles(jobId){switchTab('files');const sel=document.getElementById('files-job');if([...sel.options].some(o=>o.value===jobId))sel.value=jobId;await loadFilesList(jobId)}async function loadJobOptions(){const sel=document.getElementById('files-job');try{const d=await api('/api/scans');const opts=(d.jobs||[]).map(j=>'<option value="'+esc(j.id)+'">'+esc(j.target)+'（'+esc(statusText[j.status]||j.status)+' · '+j.totalFiles+' 个文件）</option>').join('');if(sel.dataset.opts!==opts){sel.innerHTML=opts||'<option value="">暂无扫描任务</option>';sel.dataset.opts=opts}if(!sel.value&&(d.jobs||[]).length)await loadFilesList(d.jobs[0].id)}catch(e){alert('获取任务列表失败：'+e.message)}}async function loadFilesList(jobId){jobId=jobId||document.getElementById('files-job').value;if(!jobId){filesData=null;document.getElementById('files-list').innerHTML='<span class="muted">暂无扫描任务，请先在「扫描报告」页创建扫描</span>';return}if(!filesCache.has(jobId)){try{filesCache.set(jobId,await api('/api/scans/'+encodeURIComponent(jobId)+'/files'))}catch(e){alert('获取文件清单失败：'+e.message);return}}currentFilesJob=jobId;filesData=filesCache.get(jobId);renderFilesList()}function renderFilesList(){const box=document.getElementById('files-list');if(!filesData){box.innerHTML='';return}box.dataset.job=currentFilesJob;const q=(document.getElementById('files-filter').value||'').toLowerCase();const onlyBad=document.getElementById('files-only-bad').checked;const all=filesData.files||[];const files=all.filter(f=>(!q||String(f.path).toLowerCase().includes(q))&&(!onlyBad||f.findings>0));box.innerHTML='<div class="muted" style="padding:8px 0">共 '+filesData.total+' 个文件，实际检查 '+(filesData.checked??filesData.total)+' 个'+(filesData.truncated?'（仅列出前 '+all.length+' 个）':'')+'，当前显示 '+files.length+' 个，点击文件行可预览源码（问题行高亮）</div>'+(files.length?files.map(f=>{const badge=f.findings?'<span class="sev-'+f.topSeverity+'" style="margin-right:8px;white-space:nowrap">'+f.findings+' 个问题</span>':(f.checked===false?'<span class="muted" style="margin-right:8px;white-space:nowrap">未检查</span>':'<span class="muted" style="margin-right:8px;white-space:nowrap">无问题</span>');return '<div class="path file-row" style="padding:2px 0;word-break:break-all;cursor:pointer" onclick="toggleSource(this,\\''+encodeURIComponent(f.path).replace(/'/g,'%27')+'\\')">'+badge+esc(f.path)+'</div>'}).join(''):'<span class="muted">没有符合筛选条件的文件</span>')}const sourceCache=new Map();async function toggleSource(row,encPath){let box=row.nextElementSibling;if(box&&box.dataset.code==='1'){box.style.display=box.style.display==='none'?'':'none';return}const filePath=decodeURIComponent(encPath);const jobId=row.closest('.file-list').dataset.job;const cacheKey=jobId+'|'+filePath;if(!sourceCache.has(cacheKey)){try{sourceCache.set(cacheKey,await api('/api/scans/'+encodeURIComponent(jobId)+'/file?path='+encPath))}catch(e){alert('读取文件失败：'+e.message);return}}const d=sourceCache.get(cacheKey);if(!box){box=document.createElement('div');row.after(box)}box.dataset.code='1';const bad=new Map();for(const f of (d.findings||[]))bad.set(f.line,f);box.innerHTML='<div class="muted" style="padding:4px 0">'+esc(d.path)+' · 共 '+d.totalLines+' 行'+(d.truncated?'（仅显示前 2000 行）':'')+' · '+(d.findings||[]).length+' 个问题</div><pre class="code-pre">'+d.content.split('\\n').map((l,i)=>{const f=bad.get(i+1);return '<span class="code-line'+(f?' code-bad':'')+'">'+(f?'<span class="code-tag sev-'+f.severity+'">行 '+f.line+' · '+esc(f.ruleId)+'</span>':'')+String(i+1).padStart(5,' ')+'  '+esc(l)+'</span>'}).join('\\n')+'</pre>';box.style.display=''}function loadPage(p){currentPage=p;load()}function renderPager(d){const size=d.pageSize||50;const maxPage=Math.max(1,Math.ceil((d.totalReports||0)/size));const el=document.querySelector('#pager');if(!d.totalReports){el.innerHTML='<span class="muted">暂无明细</span>';return}el.innerHTML='<span class="muted">第 '+d.page+' / '+maxPage+' 页 · 共 '+d.totalReports+' 条明细</span> <button class="button" style="padding:6px 10px;font-size:12px"'+(d.page<=1?' disabled':'')+' onclick="loadPage('+(d.page-1)+')">上一页</button> <button class="button" style="padding:6px 10px;font-size:12px"'+(d.page>=maxPage?' disabled':'')+' onclick="loadPage('+(d.page+1)+')">下一页</button> <button class="button" style="padding:6px 10px;font-size:12px" onclick="loadPage(1)">第一页</button> <button class="button" style="padding:6px 10px;font-size:12px" onclick="loadPage('+maxPage+')">末页</button>'}function renderRows(reports){lastReports=reports;const groups=new Map();for(const r of reports){if(!groups.has(r.id))groups.set(r.id,[]);groups.get(r.id).push(r)}const head='<div class="row row-head"><span>任务</span><span>扫描目录</span><span>问题报告</span><span>具体问题/位置</span><span>等级</span><span>状态</span></div>';let html=reports.length?'':'<span class="muted">暂无报告</span>';let first=true;for(const[id,rows]of groups){const lead=rows[0];const open=rowState.has(id)?rowState.get(id):first;html+='<details class="job-group" data-job="'+esc(id)+'"'+(open?' open':'')+'><summary><span>任务 '+esc(id.slice(0,8))+'</span><span class="path">'+esc(lead.scanPath)+'</span><span>'+rows.length+' 条</span><span class="muted">'+esc(statusText[lead.status]||lead.status)+'</span><span><button class="ai-button" onclick="event.preventDefault();showFiles(\\''+esc(id)+'\\')">文件清单</button></span></summary>'+head+rows.map(r=>'<div class="row"><span>'+esc(r.id.slice(0,8))+'</span><span class="path">'+esc(r.scanPath)+'</span><span>'+esc(r.reportName)+'</span><span class="path">'+esc(r.problem?('问题：'+r.problem+'；建议：'+r.suggestion+'；位置：'+r.filePath):(r.error||r.reportPath))+'</span><span class="sev-'+esc(r.severity||'info')+'">'+esc(severityText[r.severity]||'—')+'</span><span>'+esc(statusText[r.status]||r.status)+'</span></div>').join('')+'</details>';first=false}const el=document.querySelector('#rows');el.innerHTML=html;el.querySelectorAll('details.job-group').forEach(d=>{d.addEventListener('toggle',()=>rowState.set(d.dataset.job,d.open))})}function expandAll(open){for(const d of document.querySelectorAll('#rows details.job-group'))rowState.set(d.dataset.job,open);renderRows(lastReports)}let latestLoad=0;async function load(){updateTarget();const requestId=++latestLoad;const scope=document.querySelector('#scope').value;const type=document.querySelector('#type').value;try{const d=await api('/api/dashboard?scope='+scope+'&type='+type+'&page='+currentPage);if(requestId!==latestLoad||scope!==document.querySelector('#scope').value||type!==document.querySelector('#type').value)return;const reports=d.reports;document.querySelector('#metrics').innerHTML=[['扫描任务',d.jobs],['漏洞总数',d.findings],['高危及以上',d.high],['已扫描 / 发现文件',d.files+' / '+d.totalFiles]].map(x=>'<div class="card">'+x[0]+'<div class="metric">'+x[1]+'</div></div>').join('');document.querySelector('#severity').innerHTML=Object.entries(d.severity).map(([k,v])=>'<div><span class="sev-'+k+'">'+(severityText[k]||k)+'：'+v+'</span><div class="bar"><div class="fill" style="width:'+((v/(d.findings||1))*100)+'%"></div></div></div>').join('');renderRows(reports);renderPager(d);document.querySelector('#truncated').textContent='';document.querySelector('#refresh-error').textContent=''}catch(e){if(requestId===latestLoad)document.querySelector('#refresh-error').textContent='仪表盘刷新失败：'+e.message}}async function refreshNow(){const b=document.getElementById('refresh-btn');if(!b||b.classList.contains('spinning'))return;b.classList.add('spinning');try{await load()}finally{setTimeout(()=>b.classList.remove('spinning'),400)}}document.querySelectorAll('#rows details.job-group').forEach(d=>{d.addEventListener('toggle',()=>rowState.set(d.dataset.job,d.open))});async function loadDrives(){try{const d=await api('/api/drives');const sel=document.getElementById('drives');if(sel)sel.innerHTML='<option value="">盘符</option>'+(d.drives||[]).map(x=>'<option value="'+esc(x)+'">'+esc(x)+'</option>').join('')}catch(e){/* 盘符获取失败不影响其他功能 */}}
function pickDrive(sel){if(sel.value){document.getElementById('cwd').value=sel.value;updateTarget();sel.value=''}}
Promise.all([loadConfig(),loadTools(),load(),loadDrives()]).catch(e=>document.querySelector('#form-message').textContent='加载失败：'+e.message);setInterval(()=>load(),4000)</script></body></html>`;
}

function json(res: ServerResponse, value: unknown, status = 200): void { const body = JSON.stringify(value); res.writeHead(status, secureHeaders("application/json; charset=utf-8")); res.end(body); }
async function body(req: IncomingMessage): Promise<Record<string, unknown>> { let text = ""; let size = 0; for await (const chunk of req) { size += Buffer.byteLength(chunk); if (size > MAX_REQUEST_BYTES) throw new Error("请求体超过 64 KB 安全限制"); text += chunk; } return text ? JSON.parse(text) as Record<string, unknown> : {}; }
async function persist(job: Job, dir: string): Promise<void> { await mkdir(dir, { recursive: true }); await writeFile(path.join(dir, `${job.id}.json`), JSON.stringify(job, null, 2), "utf8"); }

export function resolveScanPath(value: unknown, base = process.cwd()): string {
  const input = String(value ?? ".").trim().replace(/^(["'])(.*)\1$/, "$2").trim();
  if (/^[A-Za-z]:[\\/]/.test(input) || /^\\\\/.test(input)) return path.win32.normalize(input);
  return path.resolve(base, input || ".");
}

function isWithin(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

async function resolveAllowedTarget(value: unknown, base: string, allowedRoots: readonly string[], allowAll = false): Promise<string> {
  const requested = resolveScanPath(value, base);
  let target: string;
  try { target = await realpath(requested); }
  catch { throw new Error("扫描目标不存在或无法访问"); }
  if (allowAll) return target;
  const roots = await Promise.all(allowedRoots.map(async (root) => {
    try { return await realpath(root); }
    catch { throw new Error("允许的扫描根目录不存在或无法访问"); }
  }));
  if (!roots.some((root) => isWithin(root, target))) throw new Error("扫描目标超出允许的本地目录范围（面板默认仅允许启动目录，可用 --allow <路径> 或 --allow-all 放开）");
  return target;
}

async function resolveAllowedDirectory(value: unknown, base: string, allowedRoots: readonly string[], allowAll = false): Promise<string> {
  const target = await resolveAllowedTarget(value, base, allowedRoots, allowAll);
  if (!(await stat(target)).isDirectory()) throw new Error("目标不是目录");
  return target;
}

async function exists(file: string): Promise<boolean> { try { await access(file); return true; } catch { return false; } }
async function countTargetFiles(cwd: string, include: string[], includeTests: boolean): Promise<number> {
  const stream = fg.stream(include, { cwd, onlyFiles: true, unique: true, suppressErrors: true, deep: 40, followSymbolicLinks: false, ignore: [...DEFAULT_EXCLUDE, ...(includeTests ? [] : TEST_EXCLUDE), "**/.scan-reports/**", "**/test-results*.json", "**/tools/**"] });
  let count = 0;
  for await (const _entry of stream) {
    count += 1;
    if (count > MAX_SCAN_FILES) throw new Error(`扫描文件数量超过安全限制（最多 ${MAX_SCAN_FILES} 个）`);
  }
  return count;
}
async function getToolStatuses(): Promise<PanelToolStatus[]> {
  const root = path.resolve(process.cwd(), "tools");
  const ripsReady = await exists(path.join(root, "php", "php.exe")) && await exists(path.join(root, "rips-wrapper.php"));
  const vcgReady = await exists(path.join(root, "vcg-app", "VisualCodeGrepper.exe")) && await exists(path.join(root, "vcg-wrapper.ps1"));
  return [
    { id: "seay", label: "Seay", available: false, reason: "Seay 2.1 是 GUI 工具，尚无可验证的无头扫描接口" },
    { id: "rips", label: "RIPS", available: ripsReady, ...(ripsReady ? {} : { reason: "缺少 PHP 运行时或 RIPS 包装脚本" }) },
    { id: "vcg", label: "VCG", available: vcgReady, ...(vcgReady ? {} : { reason: "缺少 VCG 程序或包装脚本" }) },
  ];
}

function buildDashboard(jobMap: Map<string, Job>, scope: "latest" | "all", type: "all" | "source" | "test" = "all", page = 1, pageSize = 50): DashboardPayload {
  const all = [...jobMap.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  const selected = scope === "all" ? all : all.slice(0, 1);
  const matchesType = (file: string): boolean => type === "all" || (type === "test" ? isTestPath(file) : Boolean(file) && !isTestPath(file));
  const selectedFindings = selected.flatMap((job) => (job.result?.findings ?? []).filter((finding) => matchesType(finding.file)));
  const results = scope === "all" ? [...new Map(selectedFindings.map((finding) => [finding.fingerprint, finding])).values()] : selectedFindings;
  const severity: Record<SeverityName, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  results.forEach((finding) => { severity[finding.severity] += 1; });
  const matchedJobs = selected.filter((job) => job.status !== "queued" && job.status !== "running");
  const matchedFiles = matchedJobs.reduce((count, job) => count + (type === "all" ? (job.result?.scannedFiles ?? 0) : new Set((job.result?.findings ?? []).filter((finding) => matchesType(finding.file)).map((finding) => finding.file)).size), 0);
  const matchedTotalFiles = matchedJobs.reduce((count, job) => count + (type === "all" ? job.totalFiles : new Set((job.result?.findings ?? []).filter((finding) => matchesType(finding.file)).map((finding) => finding.file)).size), 0);
  const visibleJobs = matchedJobs.filter((job) => (job.result?.findings ?? []).some((finding) => matchesType(finding.file)) || (job.result?.findings.length ?? 0) === 0);
  const allReports = visibleJobs.flatMap((job): DashboardReport[] => {
    const matchingFindings = (job.result?.findings ?? []).filter((finding) => matchesType(finding.file));
    const hasFindings = matchingFindings.length > 0;
    const hasResultReport = Boolean(job.result?.findings.length) || job.status === "failed" || job.status === "partial";
    const reportName = hasResultReport && job.result ? `${job.id}.result.json` : job.status === "no-files" ? "未生成（没有可检查的文件）" : job.status === "failed" ? `${job.id}.json` : "未生成（未发现问题）";
    return hasFindings
      ? matchingFindings.map((finding) => ({
          id: job.id,
          fingerprint: finding.fingerprint,
          reportName,
          scanPath: publicTarget(job),
          filePath: `${job.targetKind === "archive" ? `${path.basename(job.cwd)}!/${finding.file.replaceAll("\\", "/")}` : job.targetKind === "file" ? path.basename(job.cwd) : finding.file}:${finding.line}:${finding.column}`,
          reportPath: reportName,
          severity: finding.severity,
          status: job.status,
          problem: finding.message,
          suggestion: finding.suggestion,
          error: "",
        }))
      : [{
          id: job.id,
          reportName,
          scanPath: publicTarget(job),
          filePath: "",
          reportPath: hasResultReport ? reportName : "",
          severity: "info",
          status: job.status,
          problem: "",
          suggestion: "",
          error: job.status === "failed" ? "扫描失败，请查看本地报告" : job.error ?? (job.status === "no-files" ? "没有找到受支持的源码或配置文件，实际检查 0 个文件" : job.status === "succeeded" ? "未发现问题，无需生成报告" : ""),
        }];
  });
  const safePageSize = Math.min(Math.max(1, Math.trunc(pageSize)), 500);
  const maxPage = Math.max(1, Math.ceil(allReports.length / safePageSize));
  const safePage = Math.min(Math.max(1, Math.trunc(page)), maxPage);
  return {
    scope,
    latestJobId: all[0]?.id,
    jobs: selected.length,
    findings: results.length,
    high: severity.high + severity.critical,
    files: matchedFiles,
    totalFiles: matchedTotalFiles,
    truncated: Math.max(0, allReports.length - allReports.slice((safePage - 1) * safePageSize, safePage * safePageSize).length),
    page: safePage,
    pageSize: safePageSize,
    totalReports: allReports.length,
    severity,
    reports: allReports.slice((safePage - 1) * safePageSize, safePage * safePageSize),
  };
}

export function createPanelServer(options: PanelOptions = {}) {
  const panelCwd = path.resolve(options.cwd ?? process.cwd());
  const allowedRoots = (options.allowedRoots?.length ? options.allowedRoots : [panelCwd]).map((root) => path.resolve(root));
  const fixedReportsDir = options.reportsDir ? path.resolve(options.reportsDir) : undefined;
  const reportsDir = fixedReportsDir ?? path.resolve(panelCwd, ".scan-reports");
  const jobs = new Map<string, Job>();
  const queue: Job[] = [];
  const maxConcurrency = Math.max(1, Math.trunc(options.maxConcurrency ?? 2));
  const maxQueuedJobs = Math.max(1, Math.trunc(options.maxQueuedJobs ?? 20));
  const maxRetainedJobs = Math.max(maxConcurrency, Math.trunc(options.maxRetainedJobs ?? 100));
  const authToken = options.authToken?.trim();
  const scanRunner = options.scanRunner ?? scan;
  const aiAnalyzer = options.aiAnalyzer ?? aiAnalyzerFromEnvironment();
  let activeJobs = 0;
  const trimJobs = (): void => {
    const completed = [...jobs.values()].filter((job) => !["queued", "running"].includes(job.status)).sort((a, b) => a.createdAt.localeCompare(b.createdAt));
    while (jobs.size >= maxRetainedJobs && completed.length) jobs.delete(completed.shift()!.id);
  };
  const schedule = (): void => {
    while (activeJobs < maxConcurrency) {
      const job = queue.shift();
      if (!job) return;
      activeJobs += 1;
      void runJob(job, scanRunner).catch(() => undefined).finally(() => {
        activeJobs -= 1;
        schedule();
      });
    }
  };
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
      if (url.pathname.startsWith("/api/") && authToken && !isAuthorized(req, authToken)) { json(res, { error: "未授权访问", code: "UNAUTHORIZED" }, 401); return; }
      if (req.method === "GET" && url.pathname === "/") { const tools = await getToolStatuses(); const dashboard = buildDashboard(jobs, "latest"); const page = renderPanelHtml({ currentDirectory: panelCwd, tools, dashboard }); res.writeHead(200, secureHeaders("text/html; charset=utf-8")); res.end(page); return; }
      if (req.method === "GET" && url.pathname === "/api/dashboard") {
        const type = url.searchParams.get("type");
        const page = Number.parseInt(url.searchParams.get("page") ?? "1", 10);
        const pageSize = Number.parseInt(url.searchParams.get("pageSize") ?? "50", 10);
        json(res, buildDashboard(jobs, url.searchParams.get("scope") === "all" ? "all" : "latest", type === "source" || type === "test" ? type : "all", Number.isFinite(page) ? page : 1, Number.isFinite(pageSize) ? pageSize : 50));
        return;
      }
      if (req.method === "GET" && url.pathname === "/api/config") { json(res, { currentDirectory: panelCwd }); return; }
      if (req.method === "GET" && url.pathname === "/api/drives") {
        const drives: string[] = [];
        if (process.platform === "win32") {
          for (let code = 65; code <= 90; code += 1) {
            const letter = `${String.fromCharCode(code)}:\\`;
            try { const info = await stat(letter); if (info.isDirectory()) drives.push(letter); } catch { /* 盘符不存在，跳过 */ }
          }
        } else drives.push("/");
        json(res, { drives });
        return;
      }
      if (req.method === "GET" && url.pathname === "/api/tools") { json(res, { tools: await getToolStatuses() }); return; }
      if (req.method === "POST" && url.pathname === "/api/scans") {
        const input = await body(req);
        const requestedTools = Array.isArray(input.tools) ? input.tools.map(String) : [];
        const includeTests = input.includeTests === true;
        const dependencyAudit = input.dependencyAudit === true;
        const statuses = await getToolStatuses();
        const knownTools = new Set(statuses.map((tool) => tool.id));
        const unknown = requestedTools.filter((name) => !knownTools.has(name as PanelToolStatus["id"]));
        const unavailable = statuses.filter((tool) => requestedTools.includes(tool.id) && !tool.available);
        if (unknown.length) { json(res, { error: `未知外部工具：${unknown.join(", ")}` }, 400); return; }
        if (unavailable.length) { json(res, { error: unavailable.map((tool) => `${tool.label}：${tool.reason}`).join("；") }, 400); return; }
        let cwd: string;
        let target;
        try {
          cwd = await resolveAllowedTarget(input.cwd ?? panelCwd, panelCwd, allowedRoots, options.allowAll === true);
          target = await prepareScanTarget(cwd);
        } catch (error) { json(res, { error: error instanceof Error ? error.message : String(error) }, 400); return; }
        if (queue.length >= maxQueuedJobs) { await cleanupScanTarget(target); json(res, { error: "扫描队列已满，请稍后重试", code: "QUEUE_FULL" }, 429); return; }
        trimJobs();
        const id = randomUUID();
        const taskReportsDir = reportsDir;
        let languages: ProjectLanguage[];
        try { languages = await detectProjectLanguages(target.scanCwd); }
        catch (error) { await cleanupScanTarget(target); json(res, { error: `识别项目语言失败：${error instanceof Error ? error.message : String(error)}` }, 400); return; }
        const include = target.include ?? includePatternsForLanguages(languages);
        let totalFiles: number;
        try { totalFiles = target.kind === "directory" ? await countTargetFiles(target.scanCwd, include, includeTests) : target.totalFiles; }
        catch (error) {
          await cleanupScanTarget(target);
          const message = error instanceof Error ? error.message : String(error);
          json(res, { error: message.includes("安全限制") ? `${message}。整盘或超大目录请改为指定具体项目目录（如 D:\\projects\\my-app）或单个文件` : message }, 400);
          return;
        }
        const job: Job = {
          id,
          status: "queued",
          createdAt: new Date().toISOString(),
          cwd,
          scanCwd: target.scanCwd,
          targetKind: target.kind,
          includeTests,
          ...(dependencyAudit ? { dependencyAudit } : {}),
          ...(target.include ? { include: target.include } : {}),
          ...(target.cleanupPath ? { cleanupPath: target.cleanupPath } : {}),
          reportsDir: taskReportsDir,
          tools: requestedTools,
          totalFiles,
          languages,
        };
        jobs.set(id, job);
        queue.push(job);
        schedule();
        json(res, publicJob(job), 202); return;
      }
      if (req.method === "GET" && url.pathname === "/api/scans") {
        const list = [...jobs.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt)).map((job) => ({ id: job.id, target: publicTarget(job), targetKind: job.targetKind, status: job.status, createdAt: job.createdAt, totalFiles: job.totalFiles }));
        json(res, { jobs: list });
        return;
      }
      if (req.method === "GET" && url.pathname === "/api/languages") {
        let cwd: string;
        try { cwd = await resolveAllowedDirectory(url.searchParams.get("cwd") ?? panelCwd, panelCwd, allowedRoots, options.allowAll === true); }
        catch (error) { json(res, { error: error instanceof Error ? error.message : String(error) }, 400); return; }
        const languages = await detectProjectLanguages(cwd);
        json(res, { languages, include: includePatternsForLanguages(languages) }); return;
      }
      if (req.method === "GET" && url.pathname === "/api/diff") {
        const all = [...jobs.values()].filter((job) => job.result).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
        if (all.length < 2) { json(res, { added: [], fixed: [], unchanged: [], message: "至少需要两次成功扫描" }); return; }
        json(res, diffScanResults(all[1]!.result!, all[0]!.result!)); return;
      }
      const aiMatch = url.pathname.match(/^\/api\/scans\/([^/]+)\/findings\/([^/]+)\/ai-analysis$/);
      if (req.method === "POST" && aiMatch) {
        if (!aiAnalyzer) { json(res, { error: "尚未配置 AI 服务，请设置 LEGO_AI_BASE_URL 和 LEGO_AI_MODEL" }, 503); return; }
        const job = jobs.get(aiMatch[1]!);
        const finding = job?.result?.findings.find((item) => item.fingerprint === aiMatch[2]);
        if (!job || !finding) { json(res, { error: "任务或漏洞不存在" }, 404); return; }
        try { json(res, await aiAnalyzer.analyze(finding)); }
        catch (error) { json(res, { error: error instanceof Error ? error.message : String(error), code: "AI_ANALYSIS_FAILED" }, 502); }
        return;
      }
      if (req.method === "GET" && url.pathname.startsWith("/api/scans/") && url.pathname.endsWith("/files")) {
        const jobId = url.pathname.split("/")[3] ?? "";
        const job = jobs.get(jobId);
        if (!job) { json(res, { error: "任务不存在" }, 404); return; }
        const scanned = job.result?.scannedFileList ?? [];
        const rank: Record<SeverityName, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        const byFile = new Map<string, { count: number; top: SeverityName }>();
        for (const finding of job.result?.findings ?? []) {
          const key = finding.file.replaceAll("\\", "/");
          const entry = byFile.get(key) ?? { count: 0, top: "info" as SeverityName };
          entry.count += 1;
          if (rank[finding.severity] < rank[entry.top]) entry.top = finding.severity;
          byFile.set(key, entry);
        }
        const items: { path: string; findings: number; checked: boolean; topSeverity?: SeverityName }[] = [];
        const seen = new Set<string>();
        const pushItem = (full: string, key: string | null): void => {
          if (seen.has(full)) return;
          seen.add(full);
          const summary = key ? byFile.get(key) : undefined;
          items.push({ path: full, findings: summary?.count ?? 0, checked: Boolean(key), ...(summary ? { topSeverity: summary.top } : {}) });
        };
        for (const relative of scanned) {
          const key = relative.replaceAll("\\", "/");
          const full = job.targetKind === "directory" ? path.join(job.cwd, key) : job.targetKind === "file" ? job.cwd : `${path.basename(job.cwd)}!/${key}`;
          pushItem(full, key);
        }
        if (job.targetKind === "archive") {
          const base = path.basename(job.cwd);
          for (const relative of job.archiveFiles ?? []) pushItem(`${base}!/${relative}`, null);
        }
        if (job.targetKind === "directory") {
          // 补充目录中未被检查的文件（类型不支持、超过大小限制等），让清单覆盖目录全部文件
          try {
            const all = fg.stream("**/*", { cwd: job.cwd, onlyFiles: true, unique: true, suppressErrors: true, deep: 40, followSymbolicLinks: false, ignore: [...DEFAULT_EXCLUDE, "**/.scan-reports/**", ...(job.includeTests ? [] : TEST_EXCLUDE)] });
            let listed = 0;
            for await (const entry of all as AsyncIterable<string>) {
              listed += 1;
              if (listed > 5_000) break;
              pushItem(path.join(job.cwd, String(entry)), null);
            }
          } catch { /* 枚举失败时仅返回已扫描的文件清单 */ }
        }
        json(res, { files: items.slice(0, 2_000), total: items.length, checked: scanned.length, truncated: Math.max(0, items.length - 2_000) });
        return;
      }
      if (req.method === "GET" && url.pathname.startsWith("/api/scans/") && url.pathname.endsWith("/file")) {
        const jobId = url.pathname.split("/")[3] ?? "";
        const job = jobs.get(jobId);
        if (!job) { json(res, { error: "任务不存在" }, 404); return; }
        const requested = url.searchParams.get("path") ?? "";
        const root = path.resolve(job.targetKind === "archive" ? job.scanCwd : job.cwd);
        let entry: string;
        let absolute: string;
        if (job.targetKind === "directory") {
          // 目录任务：允许预览目录内任意文件（含未被检查的），但必须位于扫描根目录之内
          const relative = path.relative(root, path.resolve(requested));
          if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) { json(res, { error: "该文件不在本任务的扫描目录内" }, 403); return; }
          entry = relative.replaceAll("\\", "/");
          absolute = path.resolve(root, entry);
        } else {
          const files = job.result?.scannedFileList ?? [];
          const found = files.find((relative) => {
            const key = relative.replaceAll("\\", "/");
            const full = job.targetKind === "file" ? job.cwd : `${path.basename(job.cwd)}!/${key}`;
            return full === requested;
          });
          if (!found) { json(res, { error: "该文件不在本任务的扫描范围内" }, 403); return; }
          entry = found;
          absolute = job.targetKind === "file" ? path.resolve(job.cwd) : path.resolve(root, found);
        }
        // 防越界：用相对路径判断，兼容盘根目录（如 F:\）这类自带尾部分隔符的 root
        const guard = path.relative(root, absolute);
        if (guard.startsWith("..") || path.isAbsolute(guard)) { json(res, { error: "路径越界" }, 403); return; }
        let content: string;
        try {
          const info = await stat(absolute);
          if (info.size > 512 * 1024) { json(res, { error: "文件超过 512KB，请在本地编辑器中查看" }, 413); return; }
          content = await readFile(absolute, "utf8");
        } catch { json(res, { error: "文件已不可访问（压缩包扫描的临时目录可能已清理，请重新扫描该压缩包）" }, 410); return; }
        const lines = content.split("\n");
        const truncated = lines.length > 2_000;
        const key = entry.replaceAll("\\", "/");
        const findings = (job.result?.findings ?? [])
          .filter((finding) => finding.file.replaceAll("\\", "/") === key)
          .map(({ line, column, severity, ruleId, message }) => ({ line, column, severity, ruleId, message }));
        json(res, { path: requested, content: truncated ? lines.slice(0, 2_000).join("\n") : content, totalLines: lines.length, truncated, findings });
        return;
      }
      if (req.method === "GET" && url.pathname.startsWith("/api/scans/")) { const job = jobs.get(url.pathname.split("/").pop() ?? ""); if (!job) { json(res, { error: "任务不存在" }, 404); return; } json(res, publicJob(job)); return; }
      json(res, { error: "Not found" }, 404);
    } catch (error) { console.error("[panel] 请求处理失败:", error); json(res, { error: "请求处理失败", code: "INTERNAL_ERROR" }, 500); }
  });
  return { server, reportsDir };
}
function toolOptions(name: string, languages: readonly ProjectLanguage[]): { command: string; args: string[]; timeoutMs: number } | undefined {
  const root = path.resolve(process.cwd(), "tools");
  const vcgLanguage = languages.includes("java") ? "JAVA" : languages.includes("csharp") ? "CS" : languages.includes("cpp") ? "CPP" : "PHP";
  if (name === "vcg") return { command: "powershell.exe", args: ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path.join(root, "vcg-wrapper.ps1"), "-Target", "{cwd}", "-Language", vcgLanguage], timeoutMs: 120_000 };
  if (name === "rips") return { command: path.join(root, "php", "php.exe"), args: [path.join(root, "rips-wrapper.php"), "{cwd}"], timeoutMs: 120_000 };
  return undefined;
}

async function runJob(job: Job, scanRunner: typeof scan): Promise<void> {
  job.status = "running";
  try {
    const include = job.include ?? includePatternsForLanguages(job.languages ?? ["unknown"]);
    const external = Object.fromEntries(job.tools.map((name) => [name, toolOptions(name, job.languages ?? [])]).filter((entry): entry is [string, { command: string; args: string[]; timeoutMs: number }] => Boolean(entry[1])));
    const suiteOptions = Object.fromEntries(Object.entries(external).map(([name, value]) => [name, value]));
    const auditSuite = Object.keys(suiteOptions).length ? createAuditSuiteModule(suiteOptions) : undefined;
    const modules = auditSuite ? [auditSuite] : [];
    const defaultModules = [securityModule, credentialsModule, configurationModule, testingModule];
    const auditModules = job.dependencyAudit ? [dependencyAuditModule, osvModule, gitHistoryModule] : [];
    const moduleIds = [...defaultModules.map((module) => module.id), ...auditModules.map((module) => module.id), ...(auditSuite ? [auditSuite.id] : [])];
    job.result = await scanRunner({
      cwd: job.scanCwd,
      include,
      includeTests: Boolean(job.includeTests),
      exclude: ["**/.scan-reports/**", "**/coverage/**", "**/test-results*.json", "**/tools/**"],
      modules,
      moduleIds,
    });
    job.status = job.result.status === "failed" ? "failed" : job.result.scannedFiles === 0 ? "no-files" : job.result.status === "partial" ? "partial" : "succeeded";
    if (job.status === "failed") job.error = job.result.diagnostics.map((item) => item.message).join("; ") || "扫描失败";
    if (job.status === "partial") job.error = "扫描部分完成，请检查诊断信息和报告";
    if (job.status === "no-files") job.error = "没有找到受支持的源码或配置文件，实际检查 0 个文件";
  } catch (error) { job.status = "failed"; job.error = error instanceof Error ? error.message : String(error); }
  if (job.targetKind === "archive") {
    // 压缩包任务：清理临时目录前记录全部内部文件，供文件清单展示（含未检查的条目）
    try {
      const all = fg.stream("**/*", { cwd: job.scanCwd, onlyFiles: true, unique: true, suppressErrors: true, deep: 40, followSymbolicLinks: false });
      const collected: string[] = [];
      for await (const entry of all as AsyncIterable<string>) {
        collected.push(String(entry).replaceAll("\\", "/"));
        if (collected.length >= 5_000) break;
      }
      job.archiveFiles = collected;
    } catch { /* 枚举失败时仅保留实际扫描的文件清单 */ }
  }
  job.finishedAt = new Date().toISOString();
  try {
    await persist(job, job.reportsDir);
    if (job.result && (job.result.findings.length > 0 || job.status === "failed" || job.status === "partial")) {
      await writeFile(path.join(job.reportsDir, `${job.id}.result.json`), renderJson(job.result), "utf8");
    }
  } catch (error) {
    job.status = "failed";
    job.error = "扫描结果无法写入本地报告目录";
    job.finishedAt = new Date().toISOString();
  } finally {
    await cleanupScanTarget(job);
    delete job.cleanupPath;
  }
}

export async function startPanel(options: PanelOptions = {}): Promise<{ url: string; close: () => void; authToken?: string }> {
  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? 4173;
  const authToken = options.authToken?.trim() || (!LOOPBACK_HOSTS.has(host.toLowerCase()) ? randomBytes(32).toString("base64url") : undefined);
  if (!LOOPBACK_HOSTS.has(host.toLowerCase()) && !authToken) throw new Error("非回环地址必须启用访问令牌");
  const panelOptions: PanelOptions = authToken ? { ...options, authToken } : options;
  const { server } = createPanelServer(panelOptions);
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(port, host, () => resolve()); });
  const address = server.address() as AddressInfo;
  const actualPort = address.port;
  const baseUrl = `http://${host}:${actualPort}`;
  return { url: authToken ? `${baseUrl}/#token=${encodeURIComponent(authToken)}` : baseUrl, close: () => server.close(), ...(authToken ? { authToken } : {}) };
}
