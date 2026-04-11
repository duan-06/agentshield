/**
 * Llama Shield API 客户端
 * Express 后端通过此服务调用 Python Llama Shield 的 AI 检测功能
 */

import axios from 'axios';
import type { AxiosInstance } from 'axios';
import jwt from 'jsonwebtoken';

const LLAMA_SHIELD_URL = process.env.LLAMA_SHIELD_URL || 'http://localhost:18000';
const LLAMA_SHIELD_TIMEOUT_MS = Number.parseInt(process.env.LLAMA_SHIELD_TIMEOUT_MS || '180000', 10);
const LLAMA_SHIELD_BATCH_ITEMS = Number.parseInt(process.env.LLAMA_SHIELD_BATCH_ITEMS || '20', 10);
const LLAMA_SHIELD_BATCH_CONCURRENCY = Number.parseInt(process.env.LLAMA_SHIELD_BATCH_CONCURRENCY || '2', 10);
const LLAMA_SHIELD_CHAT_MAX_TOKENS = Number.parseInt(process.env.LLAMA_SHIELD_CHAT_MAX_TOKENS || '2048', 10);
const LLAMA_SHIELD_SECRET = process.env.LLAMA_SHIELD_SECRET || process.env.JWT_SECRET || '';

export interface ScanResult {
  is_blocked: boolean;
  decision: string;
  blocked_by?: string;
  blocked_reason?: string;
  score: number;
  output_text?: string;
  metadata?: Record<string, any>;
}

export interface ChatRequest {
  messages: Array<{
    role: 'user' | 'assistant' | 'system';
    content: string;
  }>;
  temperature?: number;
  max_tokens?: number;
}

export interface ChatResponse {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: Array<{
    index: number;
    message: {
      role: string;
      content: string;
    };
    finish_reason: string;
  }>;
  usage: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

class LlamaShieldService {
  private client: AxiosInstance;
  private token: string = '';

  private formatUpstreamError(error: any): string {
    const status = error?.response?.status;
    const detail = error?.response?.data?.detail;
    const data = error?.response?.data;
    const code = error?.code;
    const message = error?.message;

    if (typeof detail === 'string' && detail.trim()) {
      return status ? `HTTP ${status}: ${detail}` : detail;
    }

    if (detail && typeof detail === 'object') {
      const reason = detail.blocked_reason || detail.error || JSON.stringify(detail);
      return status ? `HTTP ${status}: ${reason}` : String(reason);
    }

    if (typeof data?.message === 'string' && data.message.trim()) {
      return status ? `HTTP ${status}: ${data.message}` : data.message;
    }

    if (typeof message === 'string' && message.trim()) {
      return status ? `HTTP ${status}: ${message}` : message;
    }

    if (typeof code === 'string' && code.trim()) {
      return `Upstream error code: ${code}`;
    }

    return 'Upstream scan error';
  }

  private async sleep(ms: number): Promise<void> {
    await new Promise(resolve => setTimeout(resolve, ms));
  }

  private isTransientUpstreamError(error: any): boolean {
    const status = error?.response?.status;
    const code = String(error?.code || '').toUpperCase();
    const msg = String(error?.message || '').toLowerCase();

    if (status === 503 || status === 504 || status === 529 || status === 429) return true;
    if (code.includes('ECONNRESET') || code.includes('ETIMEDOUT') || code.includes('ECONNABORTED')) return true;
    if (msg.includes('timeout') || msg.includes('overloaded') || msg.includes('temporarily unavailable')) return true;
    return false;
  }

  private buildServiceToken(): string | null {
    if (!LLAMA_SHIELD_SECRET) return null;
    try {
      return jwt.sign(
        {
          sub: 'agentshield-backend',
          role: 'service',
        },
        LLAMA_SHIELD_SECRET,
        {
          algorithm: 'HS256',
          expiresIn: '1h',
        }
      );
    } catch (error: any) {
      console.error('Failed to build Llama Shield service token:', error.message);
      return null;
    }
  }

  private getAuthHeaders(): Record<string, string> {
    // 优先使用服务间认证 token，避免前端 JWT 与 Python SECRET_KEY 不一致导致 401。
    const serviceToken = this.buildServiceToken();
    if (serviceToken) {
      return { Authorization: `Bearer ${serviceToken}` };
    }
    if (this.token) {
      return { Authorization: `Bearer ${this.token}` };
    }
    return {};
  }

  private getBatchItemsLimit(): number {
    if (Number.isFinite(LLAMA_SHIELD_BATCH_ITEMS) && LLAMA_SHIELD_BATCH_ITEMS > 0) {
      return Math.min(100, LLAMA_SHIELD_BATCH_ITEMS);
    }
    return 20;
  }

  private getBatchConcurrency(): number {
    if (Number.isFinite(LLAMA_SHIELD_BATCH_CONCURRENCY) && LLAMA_SHIELD_BATCH_CONCURRENCY > 0) {
      return Math.min(6, LLAMA_SHIELD_BATCH_CONCURRENCY);
    }
    return 2;
  }

  private getChatMaxTokens(): number {
    if (Number.isFinite(LLAMA_SHIELD_CHAT_MAX_TOKENS) && LLAMA_SHIELD_CHAT_MAX_TOKENS > 0) {
      return Math.min(8192, LLAMA_SHIELD_CHAT_MAX_TOKENS);
    }
    return 2048;
  }

  private async postBatchChunk(
    chunkMessages: Array<Array<{ role: string; content: string }>>
  ): Promise<ScanResult[]> {
    const response = await this.client.post('/api/v1/scan/input/batch', {
      items: chunkMessages.map(messages => ({ messages })),
    }, {
      headers: this.getAuthHeaders()
    });

    const results = response.data?.results;
    if (!Array.isArray(results)) {
      throw new Error('Invalid batch scan response format');
    }

    return results.map((r: any) => ({
      is_blocked: !!r.is_blocked,
      decision: r.decision || (r.is_blocked ? 'BLOCK' : 'ALLOW'),
      blocked_by: r.blocked_by || undefined,
      blocked_reason: r.blocked_reason || undefined,
      score: typeof r.score === 'number' ? r.score : 0,
    }));
  }

  constructor() {
    this.client = axios.create({
      baseURL: LLAMA_SHIELD_URL,
      timeout: Number.isFinite(LLAMA_SHIELD_TIMEOUT_MS) && LLAMA_SHIELD_TIMEOUT_MS > 0
        ? LLAMA_SHIELD_TIMEOUT_MS
        : 180000,
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  /**
   * 设置认证 Token
   */
  setToken(token: string) {
    this.token = token;
  }

  /**
   * 扫描用户输入（越狱/注入检测）
   */
  async scanInput(messages: Array<{ role: string; content: string }>): Promise<ScanResult> {
    const maxAttempts = 3;
    let lastError: any = null;

    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      // 使用完整聊天入口进行检测（若命中策略会返回403）
      const response = await this.client.post('/api/v1/chat', {
        messages,
        temperature: 0,
        max_tokens: this.getChatMaxTokens(),
        stream: false,
      }, {
        headers: this.getAuthHeaders()
      });

      const outputText = response.data?.choices?.[0]?.message?.content;

      // 如果没有报错，说明输入被允许
      return {
        is_blocked: false,
        decision: 'ALLOW',
        score: 0,
        output_text: typeof outputText === 'string' ? outputText : undefined,
      };
    } catch (error: any) {
      lastError = error;
      if (error.response?.status === 403) {
        const detail = error.response.data?.detail || error.response.data || {};
        return {
          is_blocked: true,
          decision: 'BLOCK',
          blocked_by: detail.blocked_by || 'Unknown',
          blocked_reason: detail.blocked_reason || 'Request blocked',
          score: detail.score || 1.0,
        };
      }

      if (attempt < maxAttempts && this.isTransientUpstreamError(error)) {
        const backoffMs = attempt * 1200;
        console.warn(`Llama Shield scanInput transient error, retrying attempt ${attempt + 1}/${maxAttempts} in ${backoffMs}ms:`, error.message);
        // eslint-disable-next-line no-await-in-loop
        await this.sleep(backoffMs);
        continue;
      }

      // 主链路失败时自动回退到仅输入扫描，避免单条评估直接 ERROR。
      try {
        // eslint-disable-next-line no-await-in-loop
        const fallback = await this.scanInputOnly(messages);
        if (fallback.decision !== 'ERROR') {
          console.warn('scanInput fallback to scanInputOnly succeeded');
          return {
            ...fallback,
            output_text: fallback.output_text,
          };
        }
      } catch (fallbackError: any) {
        console.error('scanInput fallback failed:', fallbackError?.message || fallbackError);
      }

      // 非策略阻断错误（如超时/网络问题）标记为 ERROR，避免统计被误判为 ALLOW。
      const errorText = this.formatUpstreamError(error);
      console.error('Llama Shield scanInput error:', errorText);
      return {
        is_blocked: false,
        decision: 'ERROR',
        blocked_by: 'SystemError',
        blocked_reason: errorText,
        score: 0,
      };
    }
    }

    const finalErrorText = this.formatUpstreamError(lastError);
    console.error('Llama Shield scanInput error after retries:', finalErrorText);
    return {
      is_blocked: false,
      decision: 'ERROR',
      blocked_by: 'SystemError',
      blocked_reason: finalErrorText,
      score: 0,
    };
  }

  /**
   * 仅执行输入扫描（快速路径）
   * 使用 /api/v1/scan/input，不触发模型生成与输出扫描。
   */
  async scanInputOnly(messages: Array<{ role: string; content: string }>): Promise<ScanResult> {
    try {
      const response = await this.client.post('/api/v1/scan/input', {
        messages,
      }, {
        headers: this.getAuthHeaders()
      });

      const data = response.data || {};

      return {
        is_blocked: false,
        decision: data.decision || 'ALLOW',
        score: typeof data.score === 'number' ? data.score : 0.12,
      };
    } catch (error: any) {
      if (error.response?.status === 403) {
        const detail = error.response.data?.detail || error.response.data || {};
        return {
          is_blocked: true,
          decision: 'BLOCK',
          blocked_by: detail.blocked_by || 'Unknown',
          blocked_reason: detail.blocked_reason || 'Request blocked',
          score: detail.score || 1.0,
        };
      }
      console.error('Llama Shield scanInputOnly error:', error.message);
      return {
        is_blocked: false,
        decision: 'ERROR',
        blocked_by: 'SystemError',
        blocked_reason: error.message || 'Upstream scan error',
        score: 0,
      };
    }
  }

  /**
   * 批量输入扫描（快速路径）
   * 使用 /api/v1/scan/input/batch，减少高条数评测时的 HTTP 往返开销。
   */
  async scanInputBatchOnly(
    batchMessages: Array<Array<{ role: string; content: string }>>
  ): Promise<ScanResult[]> {
    if (batchMessages.length === 0) return [];

    const out: ScanResult[] = new Array(batchMessages.length);
    const chunkSize = this.getBatchItemsLimit();
    const chunkConcurrency = this.getBatchConcurrency();

    const chunks: Array<{ start: number; items: Array<Array<{ role: string; content: string }>> }> = [];
    for (let i = 0; i < batchMessages.length; i += chunkSize) {
      chunks.push({
        start: i,
        items: batchMessages.slice(i, i + chunkSize),
      });
    }

    try {
      let nextChunk = 0;

      const worker = async () => {
        while (true) {
          const current = nextChunk;
          nextChunk += 1;
          if (current >= chunks.length) return;

          const chunk = chunks[current];

          try {
            const chunkResults = await this.postBatchChunk(chunk.items);
            for (let offset = 0; offset < chunkResults.length; offset += 1) {
              out[chunk.start + offset] = chunkResults[offset];
            }
          } catch (chunkError: any) {
            console.error('Llama Shield batch chunk failed, fallback chunk to single scan:', chunkError.message);
            for (let offset = 0; offset < chunk.items.length; offset += 1) {
              // eslint-disable-next-line no-await-in-loop
              out[chunk.start + offset] = await this.scanInputOnly(chunk.items[offset]);
            }
          }
        }
      };

      await Promise.all(Array.from({ length: chunkConcurrency }, () => worker()));
      return out;
    } catch (error: any) {
      console.error('Llama Shield scanInputBatchOnly error, fallback to single scan:', error.message);

      // 稳定性优先：批量端点异常时自动回退逐条扫描
      for (const messages of batchMessages) {
        // eslint-disable-next-line no-await-in-loop
        out.push(await this.scanInputOnly(messages));
      }
      return out;
    }
  }

  /**
   * 完整聊天（含输入/输出扫描）
   */
  async chat(request: ChatRequest): Promise<ChatResponse> {
    const response = await this.client.post<ChatResponse>('/api/v1/chat', request);
    return response.data;
  }

  /**
   * 多模态扫描（文本 + 图像）
   * 使用分层路由：轻量层（OCR+PromptGuard） → 疑似层（MiniMax） → 融合决策
   */
  async scanMultimodal(
    messages: Array<{ role: string; content: string }>,
    imageBase64?: string,
    imageUrl?: string
  ): Promise<ScanResult> {
    try {
      const response = await this.client.post('/api/v1/scan/multimodal', {
        messages,
        imageBase64: imageBase64 || undefined,
        imageUrl: imageUrl || undefined,
      }, {
        headers: this.getAuthHeaders(),
        timeout: 30000, // 多模态可能较慢，给 30 秒
      });

      const data = response.data || {};

      return {
        is_blocked: false,
        decision: data.decision || 'ALLOW',
        score: typeof data.score === 'number' ? data.score : 0.0,
        metadata: data.metadata,
      };
    } catch (error: any) {
      if (error.response?.status === 403) {
        const detail = error.response.data?.detail || error.response.data || {};
        return {
          is_blocked: true,
          decision: 'BLOCK',
          blocked_by: detail.blocked_by || 'Unknown',
          blocked_reason: detail.blocked_reason || 'Request blocked',
          score: detail.score || 1.0,
          metadata: detail.metadata,
        };
      }
      console.error('Llama Shield multimodal scan error:', error.message);
      // 网络错误时回退到纯文本扫描
      return await this.scanInputOnly(messages);
    }
  }

  /**
   * 健康检查
   */
  async healthCheck(): Promise<boolean> {
    try {
      const response = await this.client.get('/health');
      return response.data.status === 'healthy';
    } catch {
      return false;
    }
  }

  /**
   * 获取风险类别
   */
  async getCategories() {
    const response = await this.client.get('/api/tests/categories');
    return response.data;
  }

  /**
   * 获取统计信息
   */
  async getStats() {
    const response = await this.client.get('/api/v1/stats');
    return response.data;
  }
}

// 导出单例
export const llamaShieldService = new LlamaShieldService();
