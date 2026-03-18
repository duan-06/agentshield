/**
 * Llama Shield 客户端
 * 用于从 Express 后端调用 Python FastAPI 服务
 */

import axios, { AxiosInstance } from 'axios';

interface Message {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

interface ChatRequest {
  messages: Message[];
  temperature?: number;
  max_tokens?: number;
  stream?: boolean;
}

interface ScanResult {
  is_blocked: boolean;
  decision: string;
  blocked_by?: string;
  blocked_reason?: string;
  score: number;
  metadata?: Record<string, any>;
}

interface ChatResponse {
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

export class LlamaShieldClient {
  private client: AxiosInstance;
  private baseURL: string;
  private token: string;

  constructor(baseURL: string = 'http://localhost:8000', token: string = '') {
    this.baseURL = baseURL;
    this.token = token;
    this.client = axios.create({
      baseURL,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
        ...(token && { Authorization: `Bearer ${token}` }),
      },
    });
  }

  /**
   * 调用 Llama Shield 的聊天接口
   * 包含输入扫描、推理和输出扫描
   */
  async chat(request: ChatRequest): Promise<ChatResponse> {
    try {
      const response = await this.client.post<ChatResponse>('/api/v1/chat', request);
      return response.data;
    } catch (error: any) {
      if (error.response?.status === 403) {
        // 请求被阻断
        const detail = error.response.data.detail;
        throw new LlamaShieldBlockedError(
          detail.blocked_reason || 'Request blocked by security policy',
          detail.blocked_by || 'Unknown',
          detail.request_id || 'unknown'
        );
      }
      throw new LlamaShieldError(`Chat request failed: ${error.message}`);
    }
  }

  /**
   * 仅扫描输入（不进行推理）
   * 用于快速检测恶意输入
   */
  async scanInput(messages: Message[]): Promise<ScanResult> {
    try {
      // 调用 chat 接口，但只关心输入扫描阶段
      // 实际上会进行完整的 chat 流程，但我们可以在错误处理中捕获阻断信息
      const response = await this.client.post('/api/v1/chat', {
        messages,
        temperature: 0.7,
        max_tokens: 1,
      });
      
      return {
        is_blocked: false,
        decision: 'ALLOW',
        score: 0,
      };
    } catch (error: any) {
      if (error.response?.status === 403) {
        const detail = error.response.data.detail;
        return {
          is_blocked: true,
          decision: 'BLOCK',
          blocked_by: detail.blocked_by || 'Unknown',
          blocked_reason: detail.blocked_reason || 'Request blocked',
          score: 1.0,
        };
      }
      throw new LlamaShieldError(`Input scan failed: ${error.message}`);
    }
  }

  /**
   * 获取系统统计信息
   */
  async getStats(): Promise<any> {
    try {
      const response = await this.client.get('/api/v1/stats');
      return response.data;
    } catch (error: any) {
      throw new LlamaShieldError(`Failed to get stats: ${error.message}`);
    }
  }

  /**
   * 健康检查
   */
  async healthCheck(): Promise<boolean> {
    try {
      const response = await this.client.get('/health');
      return response.data.status === 'healthy';
    } catch (error) {
      return false;
    }
  }

  /**
   * 设置认证令牌
   */
  setToken(token: string): void {
    this.token = token;
    this.client.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  }
}

/**
 * Llama Shield 错误基类
 */
export class LlamaShieldError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LlamaShieldError';
  }
}

/**
 * 请求被阻断错误
 */
export class LlamaShieldBlockedError extends LlamaShieldError {
  constructor(
    message: string,
    public blockedBy: string,
    public requestId: string
  ) {
    super(message);
    this.name = 'LlamaShieldBlockedError';
  }
}

// 导出单例实例
export const llamaShieldClient = new LlamaShieldClient(
  process.env.LLAMA_SHIELD_URL || 'http://localhost:8000',
  process.env.LLAMA_SHIELD_TOKEN || ''
);
