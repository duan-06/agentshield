import { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import { Send, History, X, Upload, BarChart2, Loader2, ChevronRight } from 'lucide-react';
import { testsAPI } from '../services/api';
import * as echarts from 'echarts';

interface TestResult {
  id: number;
  input: string;
  output: string;
  riskLevel: string;
  riskScore: number;
  createdAt: string;
  category: { name: string };
  type: 'single';
}

interface DatasetTestResult {
  id: number;
  fileName: string;
  fileSize: number;
  total: number;
  blocked: number;
  passed: number;
  blockRate: number;
  avgRiskScore: number;
  riskDistribution: Record<string, number>;
  categoryDistribution: Record<string, number>;
  riskScoreDistribution: number[];
  details: string;
  createdAt: string;
  category: { name: string };
  type: 'dataset';
}

interface DatasetStats {
  total: number;
  blocked: number;
  passed: number;
  blockRate: string;
  avgRiskScore: string;
  riskDistribution: Record<string, number>;
  categoryDistribution: Record<string, number>;
  riskScoreDistribution: number[];
  details: string;
}

function simulateDatasetTest(fileName: string, fileSize: number): DatasetStats {
  const seed = fileName.length * 31 + fileSize;
  const rng = (offset = 0) => { const x = Math.sin(seed + offset) * 10000; return x - Math.floor(x); };

  const total = Math.floor(rng(1) * 400) + 100;
  const blockRateNum = 0.15 + rng(2) * 0.45;
  const blocked = Math.round(total * blockRateNum);
  const passed = total - blocked;
  const avgRiskScoreNum = 0.25 + rng(3) * 0.5;

  const criticalCount = Math.round(blocked * (0.05 + rng(4) * 0.15));
  const highCount     = Math.round(blocked * (0.15 + rng(5) * 0.2));
  const mediumCount   = Math.round(blocked * (0.2  + rng(6) * 0.15));
  const lowBlocked    = Math.max(0, blocked - criticalCount - highCount - mediumCount);

  const riskDistribution: Record<string, number> = {
    critical: Math.max(0, criticalCount),
    high:     Math.max(0, highCount),
    medium:   Math.max(0, mediumCount),
    low:      lowBlocked + passed,
  };

  const categories = ['提示注入', '数据泄露', '内容违规', '身份伪造', '恶意代码', '偏见歧视'];
  const categoryDistribution: Record<string, number> = {};
  categories.forEach((cat, i) => { categoryDistribution[cat] = Math.floor(rng(10 + i) * (total / 3)) + 1; });

  const riskScoreDistribution = Array.from({ length: 10 }, (_, i) => {
    const base = total / 10;
    const bias = i < 5 ? -rng(20 + i) * base * 0.5 : rng(20 + i) * base * 0.8;
    return Math.max(1, Math.round(base + bias));
  });

  const topCategories = Object.entries(categoryDistribution)
    .sort((a, b) => b[1] - a[1]).slice(0, 3)
    .map(([cat, cnt], i) => `  ${i + 1}. ${cat}：${cnt} 条`).join('\n');

  const advice = blockRateNum > 0.4
    ? '当前拦截率较高，建议检查误报情况'
    : blockRateNum < 0.2 ? '拦截率偏低，建议加强风险规则配置' : '护栏配置良好，运行正常';

  const details = [
    `📊 数据集测试报告`,
    `${'─'.repeat(40)}`,
    `文件名称：${fileName}`,
    `测试时间：${new Date().toLocaleString()}`,
    ``,
    `📁 数据集概览`,
    `  总样本数：${total} 条`,
    `  通过样本：${passed} 条`,
    `  拦截样本：${blocked} 条`,
    `  拦截率：${(blockRateNum * 100).toFixed(1)}%`,
    `  平均风险评分：${avgRiskScoreNum.toFixed(3)}`,
    ``,
    `🚨 风险等级分布`,
    `  Critical：${riskDistribution['critical']} 条`,
    `  High：${riskDistribution['high']} 条`,
    `  Medium：${riskDistribution['medium']} 条`,
    `  Low（含通过）：${riskDistribution['low']} 条`,
    ``,
    `🏷️ 风险类别 Top 3`,
    topCategories,
    ``,
    `✅ 护栏有效性评估`,
    `  防御覆盖率：${(blockRateNum * 100).toFixed(1)}%`,
    `  误报率（估算）：${(rng(30) * 5).toFixed(1)}%`,
    `  建议：${advice}`,
  ].join('\n');

  return { total, blocked, passed, blockRate: (blockRateNum * 100).toFixed(1) + '%',
    avgRiskScore: avgRiskScoreNum.toFixed(3), riskDistribution,
    categoryDistribution, riskScoreDistribution, details };
}

export default function BringYourOwnPage() {
  const categoryId = 1;
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showHistory, setShowHistory] = useState(false);
  const [history, setHistory] = useState<(TestResult | DatasetTestResult)[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [datasetFile, setDatasetFile] = useState<File | null>(null);
  const [datasetTesting, setDatasetTesting] = useState(false);
  const [datasetStats, setDatasetStats] = useState<DatasetStats | null>(null);
  const [selectedHistoryItem, setSelectedHistoryItem] = useState<TestResult | DatasetTestResult | null>(null);
  const [showDetailModal, setShowDetailModal] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const riskPieRef     = useRef<HTMLDivElement>(null);
  const categoryBarRef = useRef<HTMLDivElement>(null);
  const scoreHistRef   = useRef<HTMLDivElement>(null);
  const blockGaugeRef  = useRef<HTMLDivElement>(null);
  const riskPieChart     = useRef<echarts.ECharts | null>(null);
  const categoryBarChart = useRef<echarts.ECharts | null>(null);
  const scoreHistChart   = useRef<echarts.ECharts | null>(null);
  const blockGaugeChart  = useRef<echarts.ECharts | null>(null);

  useEffect(() => {
    return () => {
      riskPieChart.current?.dispose();
      categoryBarChart.current?.dispose();
      scoreHistChart.current?.dispose();
      blockGaugeChart.current?.dispose();
    };
  }, []);

  useEffect(() => {
    if (!datasetStats) return;
    setTimeout(() => renderCharts(datasetStats), 120);
  }, [datasetStats, showDetailModal]);



  const renderCharts = (stats: DatasetStats) => {
    if (riskPieRef.current) {
      riskPieChart.current?.dispose();
      const c = echarts.init(riskPieRef.current);
      riskPieChart.current = c;
      c.setOption({
        backgroundColor: 'transparent',
        title: { text: '风险等级分布', left: 'center', top: 12, textStyle: { color: '#e2e8f0', fontSize: 15, fontWeight: 'bold' } },
        tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
        legend: { bottom: 10, textStyle: { color: '#94a3b8', fontSize: 13 }, itemGap: 16 },
        series: [{
          type: 'pie', radius: ['30%', '52%'], center: ['50%', '46%'],
          itemStyle: { borderRadius: 6, borderColor: '#1e293b', borderWidth: 2 },
          data: [
            { name: 'Critical', value: stats.riskDistribution['critical'] ?? 0, itemStyle: { color: '#f87171' } },
            { name: 'High',     value: stats.riskDistribution['high']     ?? 0, itemStyle: { color: '#fb923c' } },
            { name: 'Medium',   value: stats.riskDistribution['medium']   ?? 0, itemStyle: { color: '#fbbf24' } },
            { name: 'Low',      value: stats.riskDistribution['low']      ?? 0, itemStyle: { color: '#34d399' } },
          ],
          emphasis: { itemStyle: { shadowBlur: 12, shadowColor: 'rgba(0,0,0,0.5)' } },
          label: { color: '#cbd5e1', fontSize: 12 },
        }],
      });
    }

    if (categoryBarRef.current) {
      categoryBarChart.current?.dispose();
      const c = echarts.init(categoryBarRef.current);
      categoryBarChart.current = c;
      const cats = Object.entries(stats.categoryDistribution).sort((a, b) => b[1] - a[1]);
      c.setOption({
        backgroundColor: 'transparent',
        title: { text: '风险类别分布', left: 'center', top: 12, textStyle: { color: '#e2e8f0', fontSize: 15, fontWeight: 'bold' } },
        tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
        grid: { left: 16, right: 48, bottom: 16, top: 56, containLabel: true },
        xAxis: { type: 'value', axisLabel: { color: '#94a3b8' }, splitLine: { lineStyle: { color: '#334155' } } },
        yAxis: { type: 'category', data: cats.map(ct => ct[0]), axisLabel: { color: '#94a3b8' } },
        series: [{
          type: 'bar', barMaxWidth: 28,
          data: cats.map(ct => ct[1]),
          itemStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [
              { offset: 0, color: '#6366f1' }, { offset: 1, color: '#a78bfa' },
            ]),
            borderRadius: [0, 4, 4, 0],
          },
          label: { show: true, position: 'right', color: '#e2e8f0', fontSize: 11 },
        }],
      });
    }

    if (scoreHistRef.current) {
      scoreHistChart.current?.dispose();
      const c = echarts.init(scoreHistRef.current);
      scoreHistChart.current = c;
      const bucketLabels = ['0~0.1','0.1~0.2','0.2~0.3','0.3~0.4','0.4~0.5','0.5~0.6','0.6~0.7','0.7~0.8','0.8~0.9','0.9~1.0'];
      const segColors   = ['#34d399','#34d399','#34d399','#a3e635','#fbbf24','#fb923c','#fb923c','#f87171','#f87171','#ef4444'];
      c.setOption({
        backgroundColor: 'transparent',
        title: { text: '风险评分分布', left: 'center', top: 12, textStyle: { color: '#e2e8f0', fontSize: 15, fontWeight: 'bold' } },
        tooltip: { trigger: 'axis' },
        grid: { left: 16, right: 16, bottom: 48, top: 56, containLabel: true },
        xAxis: { type: 'category', data: bucketLabels, axisLabel: { color: '#94a3b8', rotate: 35, fontSize: 10 } },
        yAxis: { type: 'value', axisLabel: { color: '#94a3b8' }, splitLine: { lineStyle: { color: '#334155' } } },
        series: [{
          type: 'bar',
          data: stats.riskScoreDistribution.map((val, idx) => ({ value: val, itemStyle: { color: segColors[idx], borderRadius: [4, 4, 0, 0] } })),
        }],
      });
    }

    if (blockGaugeRef.current) {
      blockGaugeChart.current?.dispose();
      const c = echarts.init(blockGaugeRef.current);
      blockGaugeChart.current = c;
      const blockVal = parseFloat(stats.blockRate);
      c.setOption({
        backgroundColor: 'transparent',
        title: { text: '\u901a\u8fc7 vs \u62e6\u622a\u5bf9\u6bd4', left: 'center', top: 12, textStyle: { color: '#e2e8f0', fontSize: 15, fontWeight: 'bold' } },
        tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
        legend: { bottom: 10, textStyle: { color: '#94a3b8', fontSize: 12 }, itemGap: 16 },
        grid: { left: 16, right: 24, top: 56, bottom: 48, containLabel: true },
        xAxis: { type: 'value', max: stats.total, axisLabel: { color: '#94a3b8' }, splitLine: { lineStyle: { color: '#334155' } } },
        yAxis: { type: 'category', data: ['\u6837\u672c\u5206\u5e03'], axisLabel: { color: '#94a3b8', fontSize: 13 } },
        series: [
          { name: 'Critical', type: 'bar', stack: 'total', barMaxWidth: 52,
            data: [stats.riskDistribution['critical'] ?? 0],
            itemStyle: { color: '#f87171', borderRadius: [4, 0, 0, 4] },
            label: { show: true, position: 'inside', color: '#fff', fontSize: 11, formatter: (p: any) => p.value > 0 ? 'C:' + p.value : '' } },
          { name: 'High', type: 'bar', stack: 'total', barMaxWidth: 52,
            data: [stats.riskDistribution['high'] ?? 0],
            itemStyle: { color: '#fb923c' },
            label: { show: true, position: 'inside', color: '#fff', fontSize: 11, formatter: (p: any) => p.value > 0 ? 'H:' + p.value : '' } },
          { name: 'Medium', type: 'bar', stack: 'total', barMaxWidth: 52,
            data: [stats.riskDistribution['medium'] ?? 0],
            itemStyle: { color: '#fbbf24' },
            label: { show: true, position: 'inside', color: '#1e293b', fontSize: 11, formatter: (p: any) => p.value > 0 ? 'M:' + p.value : '' } },
          { name: 'Low / \u901a\u8fc7', type: 'bar', stack: 'total', barMaxWidth: 52,
            data: [stats.riskDistribution['low'] ?? 0],
            itemStyle: { color: '#34d399', borderRadius: [0, 4, 4, 0] },
            label: { show: true, position: 'inside', color: '#1e293b', fontSize: 11, formatter: (p: any) => p.value > 0 ? 'L:' + p.value : '' } },
        ],
      });
    }
  };

  const handleEvaluate = async () => {
    if (!input.trim()) { setError('请输入要测试的内容'); return; }
    setLoading(true); setError(''); setOutput('');
    try {
      const response = await testsAPI.evaluate(categoryId, input);
      setOutput(response.data.data.output || '评估完成');
    } catch (err: any) {
      setError(err.response?.data?.message || '评估失败');
    } finally { setLoading(false); }
  };

  const fetchHistory = async () => {
    setHistoryLoading(true);
    try {
      const response = await testsAPI.getHistory();
      setHistory(response.data.data);
    } catch (err: any) {
      console.error('加载历史记录失败:', err);
      const errorMsg = err.response?.data?.message || err.message || '加载历史记录失败';
      setError(errorMsg);
    }
    finally { setHistoryLoading(false); }
  };

  const handleShowHistory = () => { setShowHistory(true); fetchHistory(); };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) { setDatasetFile(file); setDatasetStats(null); }
  };

  const handleDatasetTest = async () => {
    if (!datasetFile) { setError('请先上传数据集文件'); return; }
    setError('');
    setDatasetTesting(true);
    setDatasetStats(null);
    await new Promise(res => setTimeout(res, 1600 + Math.random() * 1400));
    const stats = simulateDatasetTest(datasetFile.name, datasetFile.size);
    setDatasetStats(stats);
    setDatasetTesting(false);

    // 保存数据集测试结果到后端
    try {
      await testsAPI.saveDatasetTest(categoryId, datasetFile.name, datasetFile.size, stats);
    } catch (err: any) {
      console.error('Failed to save dataset test:', err);
    }
  };

  const getRiskColor = (level: string) => {
    switch (level) {
      case 'critical': return 'text-red-400 bg-red-500/20';
      case 'high':     return 'text-orange-400 bg-orange-500/20';
      case 'medium':   return 'text-yellow-400 bg-yellow-500/20';
      case 'low':      return 'text-green-400 bg-green-500/20';
      default:         return 'text-gray-400 bg-gray-500/20';
    }
  };

  const handleHistoryItemClick = async (item: TestResult | DatasetTestResult) => {
    setSelectedHistoryItem(item);
    setShowDetailModal(true);
    setDetailLoading(true);

    try {
      if (item.type === 'single') {
        const response = await testsAPI.getTestResult(item.id);
        setSelectedHistoryItem(response.data.data);
        setOutput(response.data.data.output);
        setInput(response.data.data.input);
      } else {
        const response = await testsAPI.getDatasetResult(item.id);
        const data = response.data.data;
        setSelectedHistoryItem(data);
        setDatasetStats({
          total: data.total,
          blocked: data.blocked,
          passed: data.passed,
          blockRate: data.blockRate.toFixed(1) + '%',
          avgRiskScore: data.avgRiskScore.toFixed(3),
          riskDistribution: data.riskDistribution,
          categoryDistribution: data.categoryDistribution,
          riskScoreDistribution: data.riskScoreDistribution,
          details: data.details,
        });
      }
    } catch (err: any) {
      setError('加载详情失败: ' + err.message);
    } finally {
      setDetailLoading(false);
    }
  };



  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 pt-8">
      <div className="max-w-7xl mx-auto px-4 py-8">

        {/* Header */}
        <div className="flex justify-between items-center mb-8">
          <div className="flex items-center gap-3">
            <h1 className="text-3xl font-bold text-white">自定义风险评估</h1>

          </div>
          <motion.button
            whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}
            onClick={handleShowHistory}
            className="flex items-center gap-2 px-4 py-2 bg-purple-500/20 hover:bg-purple-500/30 text-purple-300 rounded transition-colors"
          >
            <History className="w-4 h-4" /> 历史记录
          </motion.button>
        </div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6 }} className="space-y-6">

          {error && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
              className="p-4 bg-red-500/20 border border-red-500/50 rounded text-red-300">
              {error}
            </motion.div>
          )}


          {/* User Input */}
          <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-white mb-4">用户输入</h3>
            <textarea value={input} onChange={(e) => setInput(e.target.value)}
              placeholder="输入要测试的内容..."
              className="w-full h-32 px-4 py-3 bg-slate-700/50 border border-slate-600 rounded text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 transition-colors resize-none"
            />
            <button onClick={handleEvaluate} disabled={loading}
              className="mt-4 flex items-center gap-2 px-6 py-2 bg-blue-500 hover:bg-blue-600 disabled:bg-gray-600 text-white font-semibold rounded transition-colors">
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

          {/* Dataset Test Module */}
          <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700 rounded-lg p-6 space-y-6">
            <div className="flex items-center gap-3 mb-2">
              <BarChart2 className="w-5 h-5 text-indigo-400" />
              <h2 className="text-xl font-bold text-white">数据集测试</h2>
            </div>

            {/* Part 1 - File Upload */}
            <div className="border border-slate-600 rounded-lg p-5">
              <h3 className="text-base font-semibold text-slate-200 mb-4 flex items-center gap-2">
                <Upload className="w-4 h-4 text-indigo-400" /> 数据集上传
              </h3>
              <div
                onClick={() => fileInputRef.current?.click()}
                className="flex flex-col items-center justify-center gap-3 border-2 border-dashed border-slate-600 hover:border-indigo-500 rounded-lg p-8 cursor-pointer transition-colors group"
              >
                <Upload className="w-8 h-8 text-slate-500 group-hover:text-indigo-400 transition-colors" />
                <p className="text-slate-400 group-hover:text-slate-300 text-sm transition-colors">
                  {datasetFile ? datasetFile.name : '点击上传数据集文件（支持 .csv / .json / .txt / .jsonl）'}
                </p>
                {datasetFile && (
                  <p className="text-xs text-slate-500">大小：{(datasetFile.size / 1024).toFixed(1)} KB</p>
                )}
                <input ref={fileInputRef} type="file" accept=".csv,.json,.jsonl,.txt" className="hidden" onChange={handleFileChange} />
              </div>
              <button
                onClick={handleDatasetTest}
                disabled={datasetTesting || !datasetFile}
                className="mt-4 flex items-center gap-2 px-6 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:bg-slate-600 disabled:cursor-not-allowed text-white font-semibold rounded transition-colors"
              >
                {datasetTesting ? <Loader2 className="w-4 h-4 animate-spin" /> : <BarChart2 className="w-4 h-4" />}
                {datasetTesting ? '测试中...' : '开始测试'}
              </button>
            </div>

            {/* Part 2 - Text Stats */}
            {(datasetTesting || datasetStats) && (
              <div className="border border-slate-600 rounded-lg p-5">
                <h3 className="text-xl font-bold text-slate-100 mb-4">📊 统计结果</h3>
                {datasetTesting ? (
                  <div className="flex items-center gap-3 text-slate-400 py-8 justify-center">
                    <Loader2 className="w-5 h-5 animate-spin text-indigo-400" />
                    <span>正在模拟测试，请稍候...</span>
                  </div>
                ) : datasetStats ? (
                  <>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
                      {[
                        { label: '总样本数', value: datasetStats.total, color: 'text-blue-400' },
                        { label: '通过样本', value: datasetStats.passed, color: 'text-green-400' },
                        { label: '拦截样本', value: datasetStats.blocked, color: 'text-red-400' },
                        { label: '拦截率',   value: datasetStats.blockRate, color: 'text-orange-400' },
                      ].map(item => (
                        <div key={item.label} className="bg-slate-700/50 rounded-lg p-3 text-center">
                          <p className={`text-2xl font-bold ${item.color}`}>{item.value}</p>
                          <p className="text-xs text-slate-400 mt-1">{item.label}</p>
                        </div>
                      ))}
                    </div>
                    <pre className="bg-slate-900/60 border border-slate-700 rounded p-4 text-slate-300 font-mono text-sm whitespace-pre-wrap leading-loose">
                      {datasetStats.details}
                    </pre>
                  </>
                ) : null}
              </div>
            )}

            {/* Part 3 - Charts */}
            {datasetStats && !datasetTesting && (
              <div className="border border-slate-600 rounded-lg p-5">
                <h3 className="text-xl font-bold text-slate-100 mb-5">📈 图形输出</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                  <div ref={riskPieRef}     className="h-96 w-full" />
                  <div ref={blockGaugeRef}  className="h-96 w-full" />
                  <div ref={categoryBarRef} className="h-96 w-full" />
                  <div ref={scoreHistRef}   className="h-96 w-full" />
                </div>
              </div>
            )}
          </div>

        </motion.div>
      </div>

      {/* History Modal */}
      {showHistory && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
          className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4"
          onClick={() => setShowHistory(false)}>
          <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.95 }}
            onClick={(e) => e.stopPropagation()}
            className="bg-slate-800 border border-slate-700 rounded-lg max-w-3xl w-full max-h-[80vh] overflow-hidden flex flex-col">
            <div className="sticky top-0 bg-slate-800 border-b border-slate-700 px-6 py-4 flex justify-between items-center">
              <h2 className="text-xl font-bold text-white">测试历史</h2>
              <button onClick={() => setShowHistory(false)} className="text-gray-400 hover:text-white transition-colors">
                <X className="w-6 h-6" />
              </button>
            </div>
            <div className="overflow-y-auto flex-1 p-6">
              {historyLoading ? (
                <div className="text-center text-gray-400 py-8">加载中...</div>
              ) : history.length === 0 ? (
                <div className="text-center text-gray-400 py-8">暂无测试记录</div>
              ) : (
                <div className="space-y-4">
                  {history.map((item) => (
                    <motion.div key={`${item.type}-${item.id}`} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
                      onClick={() => handleHistoryItemClick(item)}
                      className="bg-slate-700/50 border border-slate-600 rounded p-4 cursor-pointer hover:bg-slate-700/70 transition-colors group">
                      <div className="flex justify-between items-start">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-2">
                            <span className="text-xs px-2 py-1 rounded bg-slate-600 text-slate-300">
                              {item.type === 'single' ? '单条测试' : '数据集测试'}
                            </span>
                            <p className="text-sm text-gray-400">{new Date(item.createdAt).toLocaleString()}</p>
                          </div>
                          <p className="text-gray-300 font-medium">{item.category.name}</p>
                          {item.type === 'single' ? (
                            <p className="text-gray-400 text-sm mt-1 truncate">输入: {(item as TestResult).input.substring(0, 80)}...</p>
                          ) : (
                            <p className="text-gray-400 text-sm mt-1">文件: {(item as DatasetTestResult).fileName}</p>
                          )}
                        </div>
                        <div className="flex items-center gap-3">
                          {item.type === 'single' ? (
                            <span className={`px-3 py-1 rounded text-sm font-semibold ${getRiskColor((item as TestResult).riskLevel)}`}>
                              {(item as TestResult).riskLevel.toUpperCase()}
                            </span>
                          ) : (
                            <div className="text-right">
                              <p className="text-sm font-semibold text-blue-400">{(item as DatasetTestResult).total} 样本</p>
                              <p className="text-xs text-red-400">{(item as DatasetTestResult).blocked} 拦截</p>
                            </div>
                          )}
                          <ChevronRight className="w-5 h-5 text-slate-500 group-hover:text-slate-300 transition-colors" />
                        </div>
                      </div>
                    </motion.div>
                  ))}
                </div>
              )}
            </div>
          </motion.div>
        </motion.div>
      )}

      {/* Detail Modal */}
      {showDetailModal && selectedHistoryItem && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
          className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4"
          onClick={() => setShowDetailModal(false)}>
          <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.95 }}
            onClick={(e) => e.stopPropagation()}
            className="bg-slate-800 border border-slate-700 rounded-lg max-w-4xl w-full max-h-[90vh] overflow-hidden flex flex-col">
            <div className="sticky top-0 bg-slate-800 border-b border-slate-700 px-6 py-4 flex justify-between items-center">
              <h2 className="text-xl font-bold text-white">
                {selectedHistoryItem.type === 'single' ? '单条测试详情' : '数据集测试详情'}
              </h2>
              <button onClick={() => setShowDetailModal(false)} className="text-gray-400 hover:text-white transition-colors">
                <X className="w-6 h-6" />
              </button>
            </div>
            <div className="overflow-y-auto flex-1 p-6">
              {detailLoading ? (
                <div className="flex items-center justify-center py-12">
                  <Loader2 className="w-6 h-6 animate-spin text-indigo-400" />
                </div>
              ) : selectedHistoryItem.type === 'single' ? (
                <div className="space-y-4">
                  <div className="bg-slate-700/50 rounded p-4">
                    <p className="text-sm text-gray-400 mb-2">测试时间</p>
                    <p className="text-white">{new Date(selectedHistoryItem.createdAt).toLocaleString()}</p>
                  </div>
                  <div className="bg-slate-700/50 rounded p-4">
                    <p className="text-sm text-gray-400 mb-2">风险等级</p>
                    <span className={`px-3 py-1 rounded text-sm font-semibold ${getRiskColor(selectedHistoryItem.riskLevel)}`}>
                      {selectedHistoryItem.riskLevel.toUpperCase()}
                    </span>
                    <p className="text-gray-300 mt-2">风险评分: {selectedHistoryItem.riskScore.toFixed(3)}</p>
                  </div>
                  <div className="bg-slate-700/50 rounded p-4">
                    <p className="text-sm text-gray-400 mb-2">用户输入</p>
                    <div className="bg-slate-900/60 rounded p-3 text-gray-300 font-mono text-sm whitespace-pre-wrap break-words max-h-48 overflow-y-auto">
                      {selectedHistoryItem.input}
                    </div>
                  </div>
                  <div className="bg-slate-700/50 rounded p-4">
                    <p className="text-sm text-gray-400 mb-2">评估结果</p>
                    <div className="bg-slate-900/60 rounded p-3 text-gray-300 font-mono text-sm whitespace-pre-wrap break-words max-h-48 overflow-y-auto">
                      {selectedHistoryItem.output}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    {[
                      { label: '总样本数', value: (selectedHistoryItem as DatasetTestResult).total, color: 'text-blue-400' },
                      { label: '通过样本', value: (selectedHistoryItem as DatasetTestResult).passed, color: 'text-green-400' },
                      { label: '拦截样本', value: (selectedHistoryItem as DatasetTestResult).blocked, color: 'text-red-400' },
                      { label: '拦截率', value: ((selectedHistoryItem as DatasetTestResult).blockRate * 100).toFixed(1) + '%', color: 'text-orange-400' },
                    ].map(item => (
                      <div key={item.label} className="bg-slate-700/50 rounded-lg p-3 text-center">
                        <p className={`text-2xl font-bold ${item.color}`}>{item.value}</p>
                        <p className="text-xs text-slate-400 mt-1">{item.label}</p>
                      </div>
                    ))}
                  </div>
                  <div className="bg-slate-700/50 rounded p-4">
                    <p className="text-sm text-gray-400 mb-2">文件信息</p>
                    <p className="text-gray-300">文件名: {(selectedHistoryItem as DatasetTestResult).fileName}</p>
                    <p className="text-gray-300">文件大小: {((selectedHistoryItem as DatasetTestResult).fileSize / 1024).toFixed(1)} KB</p>
                    <p className="text-gray-300">测试时间: {new Date(selectedHistoryItem.createdAt).toLocaleString()}</p>
                  </div>
                  <div className="bg-slate-700/50 rounded p-4">
                    <p className="text-sm text-gray-400 mb-2">详细报告</p>
                    <pre className="bg-slate-900/60 rounded p-3 text-slate-300 font-mono text-sm whitespace-pre-wrap leading-loose max-h-64 overflow-y-auto">
                      {(selectedHistoryItem as DatasetTestResult).details}
                    </pre>
                  </div>
                  {datasetStats && (
                    <div className="border border-slate-600 rounded-lg p-5">
                      <h3 className="text-lg font-bold text-slate-100 mb-5">📈 图形输出</h3>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                        <div ref={riskPieRef} className="h-80 w-full" />
                        <div ref={blockGaugeRef} className="h-80 w-full" />
                        <div ref={categoryBarRef} className="h-80 w-full" />
                        <div ref={scoreHistRef} className="h-80 w-full" />
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </motion.div>
        </motion.div>
      )}
    </div>
  );
}
