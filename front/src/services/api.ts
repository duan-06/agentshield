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
  
  getHistory: () => apiClient.get('/tests/history'),
  
  getStats: () => apiClient.get('/tests/stats'),
};

export const statsAPI = {
  getCharts: () => apiClient.get('/stats/charts'),
  
  getOverview: () => apiClient.get('/stats/overview'),
};

export default apiClient;
