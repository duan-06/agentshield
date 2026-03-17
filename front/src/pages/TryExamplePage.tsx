import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Send, ChevronDown } from 'lucide-react';
import { useAuthStore } from '../store/authStore';
import { testsAPI } from '../services/api';

interface RiskCategory {
  id: number;
  name: string;
  description: string;
}

interface DropdownItem {
  id: number;
  name: string;
  description: string;
}

export default function TryExamplePage() {
  const [categories, setCategories] = useState<RiskCategory[]>([]);
  const [selectedCategoryId, setSelectedCategoryId] = useState<number | null>(null);
  const [selectedSubcategoryId, setSelectedSubcategoryId] = useState<number | null>(null);
  const [expandedCategory, setExpandedCategory] = useState<number | null>(null);
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Mock subcategories data - in real app this would come from API
  const subcategoriesMap: { [key: number]: DropdownItem[] } = {
    1: [
      { id: 1, name: 'Prompt Injection', description: '检测和阻止 Prompt 注入攻击' },
      { id: 2, name: 'SQL Injection', description: '防止 SQL 注入攻击' },
      { id: 3, name: 'Command Injection', description: '防止命令注入攻击' },
    ],
    2: [
      { id: 4, name: 'Jailbreak Attempt', description: '识别越狱尝试' },
      { id: 5, name: 'Role Bypass', description: '防止角色绕过' },
    ],
    3: [
      { id: 6, name: 'Harmful Content', description: '过滤有害内容' },
      { id: 7, name: 'Inappropriate Language', description: '检测不当语言' },
    ],
    4: [
      { id: 8, name: 'Data Leakage', description: '防止数据泄露' },
      { id: 9, name: 'Privacy Violation', description: '防止隐私侵犯' },
    ],
  };

  useEffect(() => {
    fetchCategories();
  }, []);

  const fetchCategories = async () => {
    try {
      const response = await testsAPI.getCategories();
      setCategories(response.data.data);
      if (response.data.data.length > 0) {
        setSelectedCategoryId(response.data.data[0].id);
        setExpandedCategory(response.data.data[0].id);
        setSelectedSubcategoryId(subcategoriesMap[response.data.data[0].id]?.[0]?.id || null);
      }
    } catch (err) {
      setError('Failed to load categories');
    }
  };

  const handleCategoryClick = (categoryId: number) => {
    setSelectedCategoryId(categoryId);
    setExpandedCategory(expandedCategory === categoryId ? null : categoryId);
    const subcats = subcategoriesMap[categoryId];
    if (subcats && subcats.length > 0) {
      setSelectedSubcategoryId(subcats[0].id);
    }
  };

  const handleSubcategoryClick = (subcategoryId: number) => {
    setSelectedSubcategoryId(subcategoryId);
  };

  const handleEvaluate = async () => {
    if (!selectedCategoryId || !input.trim()) {
      setError('请选择类别并输入内容');
      return;
    }

    setLoading(true);
    setError('');
    setOutput('');

    try {
      // Use selectedSubcategoryId if available, otherwise use selectedCategoryId
      const categoryToUse = selectedSubcategoryId || selectedCategoryId;
      const response = await testsAPI.evaluate(categoryToUse, input);
      setOutput(response.data.data.output || '评估完成');
    } catch (err: any) {
      setError(err.response?.data?.message || '评估失败');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 pt-8">
      <div className="max-w-7xl mx-auto px-4 py-8">
        <div className="flex gap-6">
          {/* Left Sidebar - Risk Categories */}
          <div className="w-80 flex-shrink-0">
            <motion.div
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.6 }}
              className="space-y-4"
            >
              <h2 className="text-xl font-bold text-white mb-6">Example Risks</h2>
              {categories.map((category) => (
                <div key={category.id} className="bg-slate-800/50 backdrop-blur-sm border border-slate-700 rounded-lg overflow-hidden">
                  {/* Category Header */}
                  <button
                    onClick={() => handleCategoryClick(category.id)}
                    className={`w-full px-4 py-3 flex items-center justify-between transition-colors ${
                      selectedCategoryId === category.id
                        ? 'bg-blue-500/20 text-blue-300'
                        : 'bg-slate-700/50 text-gray-300 hover:bg-slate-700'
                    }`}
                  >
                    <span className="font-semibold text-left">{category.name}</span>
                    <motion.div
                      animate={{ rotate: expandedCategory === category.id ? 180 : 0 }}
                      transition={{ duration: 0.2 }}
                    >
                      <ChevronDown className="w-4 h-4" />
                    </motion.div>
                  </button>

                  {/* Subcategories */}
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{
                      height: expandedCategory === category.id ? 'auto' : 0,
                      opacity: expandedCategory === category.id ? 1 : 0,
                    }}
                    transition={{ duration: 0.2 }}
                    className="overflow-hidden border-t border-slate-700"
                  >
                    <div className="bg-slate-800/30">
                      {subcategoriesMap[category.id]?.map((subcategory) => (
                        <button
                          key={subcategory.id}
                          onClick={() => handleSubcategoryClick(subcategory.id)}
                          className={`w-full text-left px-4 py-2 text-sm transition-colors border-b border-slate-700/50 last:border-b-0 ${
                            selectedSubcategoryId === subcategory.id
                              ? 'bg-blue-500/30 text-blue-200'
                              : 'text-gray-400 hover:bg-slate-700/50'
                          }`}
                        >
                          <div className="font-medium">{subcategory.name}</div>
                          <div className="text-xs opacity-75 mt-0.5">{subcategory.description}</div>
                        </button>
                      ))}
                    </div>
                  </motion.div>
                </div>
              ))}
            </motion.div>
          </div>

          {/* Right Content Area */}
          <div className="flex-1">
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

              {/* Header */}
              <div className="flex items-center justify-between">
                <h1 className="text-3xl font-bold text-white">General Harm</h1>
                <button className="px-4 py-2 bg-slate-700/50 hover:bg-slate-700 text-gray-300 rounded transition-colors text-sm">
                  Show prompt
                </button>
              </div>

              {/* Evaluation Criteria */}
              <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700 rounded-lg p-6">
                <h3 className="text-lg font-semibold text-white mb-4">Evaluation Criteria</h3>
                <p className="text-gray-300">
                  Texts deemed universally harmful are those that pose harm across all contexts and audiences.
                </p>
              </div>

              {/* Input Section */}
              <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700 rounded-lg p-6">
                <h3 className="text-lg font-semibold text-white mb-4">User Prompt</h3>
                <textarea
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder="输入要测试的内容..."
                  className="w-full h-24 px-4 py-3 bg-slate-700/50 border border-slate-600 rounded text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 transition-colors resize-none"
                />
              </div>

              {/* Question */}
              <div className="text-white font-semibold">
                Is the user message harmful by common-sense?
              </div>

              {/* Action Buttons */}
              <div className="flex gap-4">
                <button
                  onClick={handleEvaluate}
                  disabled={loading}
                  className="flex-1 flex items-center justify-center gap-2 px-6 py-3 bg-slate-600 hover:bg-slate-500 disabled:bg-gray-600 text-white font-semibold rounded transition-colors"
                >
                  <Send className="w-4 h-4" />
                  {loading ? '评估中...' : 'Evaluate'}
                </button>
                <button className="px-6 py-3 bg-slate-700/50 hover:bg-slate-700 text-white font-semibold rounded transition-colors flex items-center gap-2">
                  <input type="checkbox" className="w-4 h-4" />
                  Thinking
                </button>
              </div>

              {/* Output Section */}
              {output && (
                <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700 rounded-lg p-6">
                  <h3 className="text-lg font-semibold text-white mb-4">评估结果</h3>
                  <div className="min-h-32 px-4 py-3 bg-slate-700/50 border border-slate-600 rounded text-gray-300 font-mono text-sm whitespace-pre-wrap break-words">
                    {output}
                  </div>
                </div>
              )}
            </motion.div>
          </div>
        </div>
      </div>
    </div>
  );
}
