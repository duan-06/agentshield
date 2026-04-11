import axios from 'axios';
import { useAuthStore } from '../store/authStore';

const API_BASE_URL = '/api';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
});

// Add token to requests
apiClient.interceptors.request.use((config) => {
  const token = useAuthStore.getState().token;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Handle expired/invalid token globally
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error?.response?.status;
    const message = error?.response?.data?.message;

    if (status === 401 && (message === 'Invalid token' || message === 'Token expired' || message === 'No token provided')) {
      useAuthStore.getState().logout();
      if (typeof window !== 'undefined' && window.location.pathname !== '/login') {
        window.location.href = '/login';
      }
    }

    return Promise.reject(error);
  }
);

export const authAPI = {
  register: (username: string, email: string, password: string) =>
    apiClient.post('/auth/register', { username, email, password }),
  
  login: (username: string, password: string) =>
    apiClient.post('/auth/login', { username, password }),
};

export const testsAPI = {
  getCategories: () => apiClient.get('/tests/categories'),

  evaluate: (categoryId: number, input: string, evaluationCriteria?: string) =>
    apiClient.post('/tests/evaluate', { categoryId, input, evaluationCriteria }),

  // 多模态评估（支持文本 + 图像）
  evaluateMultimodal: (categoryId: number, input: string, imageBase64?: string, imageUrl?: string) =>
    apiClient.post('/tests/evaluate-multimodal', {
      categoryId,
      input,
      imageBase64: imageBase64 || undefined,
      imageUrl: imageUrl || undefined,
    }),

  getHistory: () => apiClient.get('/tests/history'),

  getStats: () => apiClient.get('/tests/stats'),

  getTestMode: () => apiClient.get('/tests/mode'),

  saveDatasetTest: (payload: {
    categoryId: number;
    fileName: string;
    fileSize: number;
    stats?: any;
    prompts?: string[];
    promptItems?: Array<{ prompt: string; expectedDecision?: 'block' | 'allow' }>;
  }) => apiClient.post('/tests/dataset-test', payload),

  getTestResult: (id: number) =>
    apiClient.get(`/tests/result/${id}`),

  getDatasetResult: (id: number) =>
    apiClient.get(`/tests/dataset-result/${id}`),
};

export const statsAPI = {
  getCharts: () => apiClient.get('/stats/charts'),
  
  getOverview: () => apiClient.get('/stats/overview'),
};

export default apiClient;
