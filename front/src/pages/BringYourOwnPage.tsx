import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Send, History, X } from 'lucide-react';
import { useAuthStore } from '../store/authStore';
import { testsAPI } from '../services/api';

interface TestResult {
  id: number;
  input: string;
  output: string;
  riskLevel: string;
  riskScore: number;
  createdAt: string;
  category: { name: string };
}

export default function BringYourOwnPage() {
  const [categoryId, setCategoryId] = useState(1);
  const [evaluationCriteria, setEvaluationCriteria] = useState('');
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showHistory, setShowHistory] = useState(false);
  const [history, setHistory] = useState<TestResult[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  const handleEvaluate = async () => {
    if (!input.trim()) {
      setError('请输入要测试的内容');
      return;
    }

    setLoading(true);
    setError('');
    setOutput('');

    try {
      const response = await testsAPI.evaluate(categoryId, input, evaluationCriteria);
      setOutput(response.data.data.output || '评估完成');
    } catch (err: any) {
      setError(err.response?.data?.message || '评估失败');
    } finally {
      setLoading(false);
    }
  };

  const fetchHistory = async () => {
    setHistoryLoading(true);
    try {
      const response = await testsAPI.getHistory();
      setHistory(response.data.data);
    } catch (err) {
      setError('Failed to load history');
    } finally {
      setHistoryLoading(false);
    }
  };

  const handleShowHistory = () => {
    setShowHistory(true);
    fetchHistory();
  };

  const getRiskColor = (level: string) => {
    switch (level) {
      case 'critical':
        return 'text-red-400 bg-red-500/20';
      case 'high':
        return 'text-orange-400 bg-orange-500/20';
      case 'medium':
        return 'text-yellow-400 bg-yellow-500/20';
      case 'low':
        return 'text-green-400 bg-green-500/20';
      default:
        return 'text-gray-400 bg-gray-500/20';
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 pt-8">
      <div className="max-w-7xl mx-auto px-4 py-8">
        <div className="flex justify-between items-center mb-8">
          <h1 className="text-3xl font-bold text-white">Bring Your Own Risk</h1>
          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={handleShowHistory}
            className="flex items-center gap-2 px-4 py-2 bg-purple-500/20 hover:bg-purple-500/30 text-purple-300 rounded transition-colors"
          >
            <History className="w-4 h-4" />
            历史记录
          </motion.button>
        </div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="space-y-6"
        >
          {/* Error Message */}
          {error && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="p-4 bg-red-500/20 border border-red-500/50 rounded text-red-300"
            >
              {error}
            </motion.div>
          )}

          {/* Evaluation Criteria */}
          <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-white mb-4">评估标准</h3>
            <textarea
              value={evaluationCriteria}
              onChange={(e) => setEvaluationCriteria(e.target.value)}
              placeholder="描述您的评估标准，例如：响应是否在语法上正确？"
              className="w-full h-24 px-4 py-3 bg-slate-700/50 border border-slate-600 rounded text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 transition-colors resize-none"
            />
          </div>

          {/* User Input */}
          <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-white mb-4">用户输入</h3>
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="输入要测试的内容..."
              className="w-full h-32 px-4 py-3 bg-slate-700/50 border border-slate-600 rounded text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 transition-colors resize-none"
            />
            <button
              onClick={handleEvaluate}
              disabled={loading}
              className="mt-4 flex items-center gap-2 px-6 py-2 bg-blue-500 hover:bg-blue-600 disabled:bg-gray-600 text-white font-semibold rounded transition-colors"
            >
              <Send className="w-4 h-4" />
              {loading ? '评估中...' : '评估'}
            </button>
          </div>

          {/* Output */}
          <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-white mb-4">评估结果</h3>
            <div className="min-h-32 px-4 py-3 bg-slate-700/50 border border-slate-600 rounded text-gray-300 font-mono text-sm whitespace-pre-wrap break-words">
              {output || '评估结果将显示在这里...'}
            </div>
          </div>
        </motion.div>
      </div>

      {/* History Modal */}
      {showHistory && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4"
          onClick={() => setShowHistory(false)}
        >
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.95 }}
            onClick={(e) => e.stopPropagation()}
            className="bg-slate-800 border border-slate-700 rounded-lg max-w-2xl w-full max-h-96 overflow-y-auto"
          >
            {/* Modal Header */}
            <div className="sticky top-0 bg-slate-800 border-b border-slate-700 px-6 py-4 flex justify-between items-center">
              <h2 className="text-xl font-bold text-white">测试历史</h2>
              <button
                onClick={() => setShowHistory(false)}
                className="text-gray-400 hover:text-white transition-colors"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-6">
              {historyLoading ? (
                <div className="text-center text-gray-400">加载中...</div>
              ) : history.length === 0 ? (
                <div className="text-center text-gray-400">暂无测试记录</div>
              ) : (
                <div className="space-y-4">
                  {history.map((result) => (
                    <motion.div
                      key={result.id}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="bg-slate-700/50 border border-slate-600 rounded p-4"
                    >
                      <div className="flex justify-between items-start mb-2">
                        <div>
                          <p className="text-sm text-gray-400">
                            {new Date(result.createdAt).toLocaleString()}
                          </p>
                          <p className="text-gray-300 mt-1">{result.category.name}</p>
                        </div>
                        <span className={`px-3 py-1 rounded text-sm font-semibold ${getRiskColor(result.riskLevel)}`}>
                          {result.riskLevel.toUpperCase()}
                        </span>
                      </div>
                      <p className="text-gray-400 text-sm mb-2">
                        <span className="font-semibold">输入:</span> {result.input.substring(0, 100)}...
                      </p>
                      <p className="text-gray-500 text-xs">
                        风险评分: {result.riskScore.toFixed(2)}
                      </p>
                    </motion.div>
                  ))}
                </div>
              )}
            </div>
          </motion.div>
        </motion.div>
      )}
    </div>
  );
}
