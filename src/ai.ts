import type { Finding } from "./contracts.js";

export interface AiAnalysis {
  summary: string;
  risk: string;
  remediation: string;
  model: string;
}

export interface AiAnalyzer {
  analyze(finding: Finding): Promise<AiAnalysis>;
}

export interface OpenAiCompatibleOptions {
  baseUrl: string;
  apiKey?: string;
  model: string;
  timeoutMs?: number;
}

interface ChatResponse {
  choices?: Array<{ message?: { content?: string } }>;
}

function endpoint(baseUrl: string): string {
  const value = baseUrl.replace(/\/+$/, "");
  return value.endsWith("/chat/completions") ? value : `${value}/v1/chat/completions`;
}

function parseContent(content: string, model: string): AiAnalysis {
  try {
    const parsed = JSON.parse(content) as Partial<AiAnalysis>;
    if (typeof parsed.summary === "string" && typeof parsed.risk === "string" && typeof parsed.remediation === "string") {
      return { summary: parsed.summary, risk: parsed.risk, remediation: parsed.remediation, model };
    }
  } catch {
    // Accept plain-text model responses and expose them as a summary.
  }
  return { summary: content.trim(), risk: "模型未返回结构化风险评级。", remediation: "请结合扫描规则和代码上下文人工确认修复方案。", model };
}

export function createOpenAiCompatibleAnalyzer(options: OpenAiCompatibleOptions): AiAnalyzer {
  const timeoutMs = options.timeoutMs ?? 30_000;
  return {
    async analyze(finding): Promise<AiAnalysis> {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const response = await fetch(endpoint(options.baseUrl), {
          method: "POST",
          headers: { "content-type": "application/json", ...(options.apiKey ? { authorization: `Bearer ${options.apiKey}` } : {}) },
          body: JSON.stringify({
            model: options.model,
            temperature: 0.2,
            response_format: { type: "json_object" },
            messages: [
              { role: "system", content: "你是软件安全审计助手。只根据提供的漏洞元数据回答，不要臆造源码内容。返回 JSON：summary、risk、remediation。使用简体中文。" },
              { role: "user", content: JSON.stringify({ ruleId: finding.ruleId, message: finding.message, severity: finding.severity, confidence: finding.confidence, category: finding.category, file: finding.file, line: finding.line, suggestion: finding.suggestion, references: finding.references }) },
            ],
          }),
          signal: controller.signal,
        });
        if (!response.ok) throw new Error(`AI 服务返回 HTTP ${response.status}`);
        const data = await response.json() as ChatResponse;
        const content = data.choices?.[0]?.message?.content;
        if (!content) throw new Error("AI 服务未返回分析内容");
        return parseContent(content, options.model);
      } finally {
        clearTimeout(timer);
      }
    },
  };
}

export function aiAnalyzerFromEnvironment(env: NodeJS.ProcessEnv = process.env): AiAnalyzer | undefined {
  const baseUrl = env.LEGO_AI_BASE_URL?.trim();
  const model = env.LEGO_AI_MODEL?.trim();
  if (!baseUrl || !model) return undefined;
  return createOpenAiCompatibleAnalyzer({ baseUrl, model, ...(env.LEGO_AI_API_KEY ? { apiKey: env.LEGO_AI_API_KEY } : {}) });
}
