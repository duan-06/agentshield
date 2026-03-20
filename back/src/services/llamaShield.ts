/**
 * Llama Shield API 客户端
 * Express 后端通过此服务调用 Python Llama Shield 的 AI 检测功能
 */

import axios from 'axios';

const LLAMA_SHIELD_URL = process.env.LLAMA_SHIELD_URL || 'http://localhost:8000';

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
  private client: axios.AxiosInstance;
  private token: string = '';

  constructor() {
    this.client = axios.create({
      baseURL: LLAMA_SHIELD_URL,
      timeout: 60000,
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
      // 其他错误，返回允许（保守策略）
      console.error('Llama Shield scanInput error:', error.message);
      return {
        is_blocked: false,
        decision: 'ALLOW',
        score: 0,
      };
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
