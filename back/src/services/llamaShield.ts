/**
 * Llama Shield API 客户端
 * Express 后端通过此服务调用 Python Llama Shield 的 AI 检测功能
 */

import axios from 'axios';
import type { AxiosInstance } from 'axios';

const LLAMA_SHIELD_URL = process.env.LLAMA_SHIELD_URL || 'http://localhost:18000';
const LLAMA_SHIELD_TIMEOUT_MS = Number.parseInt(process.env.LLAMA_SHIELD_TIMEOUT_MS || '180000', 10);
const LLAMA_SHIELD_BATCH_ITEMS = Number.parseInt(process.env.LLAMA_SHIELD_BATCH_ITEMS || '20', 10);
const LLAMA_SHIELD_BATCH_CONCURRENCY = Number.parseInt(process.env.LLAMA_SHIELD_BATCH_CONCURRENCY || '2', 10);

export interface ScanResult {
  is_blocked: boolean;
  decision: string;
  blocked_by?: string;
  blocked_reason?: string;
  score: number;
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

  private async postBatchChunk(
    chunkMessages: Array<Array<{ role: string; content: string }>>
  ): Promise<ScanResult[]> {
    const response = await this.client.post('/api/v1/scan/input/batch', {
      items: chunkMessages.map(messages => ({ messages })),
    }, {
      headers: this.token ? { Authorization: `Bearer ${this.token}` } : {}
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
    this.client.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  }

  /**
   * 扫描用户输入（越狱/注入检测）
   */
  async scanInput(messages: Array<{ role: string; content: string }>): Promise<ScanResult> {
    try {
      // 使用完整聊天入口进行检测（若命中策略会返回403）
      await this.client.post('/api/v1/chat', {
        messages,
        temperature: 0,
        max_tokens: 1,
        stream: false,
      }, {
        headers: this.token ? { Authorization: `Bearer ${this.token}` } : {}
      });

      // 如果没有报错，说明输入被允许
      return {
        is_blocked: false,
        decision: 'ALLOW',
        score: 0,
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
      // 非策略阻断错误（如超时/网络问题）标记为 ERROR，避免统计被误判为 ALLOW。
      console.error('Llama Shield scanInput error:', error.message);
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
   * 仅执行输入扫描（快速路径）
   * 使用 /api/v1/scan/input，不触发模型生成与输出扫描。
   */
  async scanInputOnly(messages: Array<{ role: string; content: string }>): Promise<ScanResult> {
    try {
      const response = await this.client.post('/api/v1/scan/input', {
        messages,
      }, {
        headers: this.token ? { Authorization: `Bearer ${this.token}` } : {}
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
