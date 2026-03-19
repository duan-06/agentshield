/**
 * 测试模式配置
 * 用于在模拟模式和真实 Llama Shield 模式之间切换
 */

export interface TestModeConfig {
  // 是否启用模拟模式
  useMockMode: boolean;
  // 模拟模式的延迟（毫秒）
  mockDelay: number;
  // 是否启用详细日志
  verbose: boolean;
}

// 从环境变量读取配置
export const testModeConfig: TestModeConfig = {
  useMockMode: process.env.USE_MOCK_MODE !== 'false', // 默认启用模拟模式
  mockDelay: parseInt(process.env.MOCK_DELAY || '500', 10), // 默认 500ms 延迟
  verbose: process.env.VERBOSE_MODE === 'true',
};

// 日志函数
export function logTestMode(message: string, data?: any) {
  if (testModeConfig.verbose) {
    console.log(`[TestMode] ${message}`, data || '');
  }
}

// 获取当前模式信息
export function getTestModeInfo(): string {
  return testModeConfig.useMockMode
    ? `模拟模式 (延迟: ${testModeConfig.mockDelay}ms)`
    : '真实模式 (Llama Shield)';
}
