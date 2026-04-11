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
  metrics?: DatasetEvalMetrics | null;
  details: string;
}

interface DatasetEvalMetrics {
  labeledTotal: number;
  truePositive: number;
  trueNegative: number;
  falsePositive: number;
  falseNegative: number;
  accuracy: number;
  falseNegativeRate: number;
  falsePositiveRate: number;
  precision: number;
  recall: number;
}

interface DatasetPromptItem {
  prompt: string;
  expectedDecision?: 'block' | 'allow';
}

function normalizeExpectedDecision(value: unknown): 'block' | 'allow' | undefined {
  if (typeof value !== 'string') return undefined;
  const normalized = value.trim().toLowerCase();
  if (normalized === 'block' || normalized === 'allow') return normalized;
  return undefined;
}

function parseCsvLine(line: string): string[] {
  const cells: string[] = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];

    if (ch === '"') {
      // Handle escaped quote "" inside quoted cells.
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }

    if (ch === ',' && !inQuotes) {
      cells.push(current.trim());
      current = '';
      continue;
    }

    current += ch;
  }

  cells.push(current.trim());
  return cells;
}

function parseCsvPrompts(content: string): DatasetPromptItem[] {
  const lines = content.split(/\r?\n/).filter((line) => line.trim().length > 0);
  if (lines.length === 0) return [];

  const headerCells = parseCsvLine(lines[0]).map((h) => h.toLowerCase());
  const promptIndex = headerCells.findIndex((h) => [
    'prompt',
    'input',
    'text',
    'content',
    'user_input',
    'mutated_prompt',
    'base_prompt',
    'test_case_prompt',
  ].includes(h));
  const expectedIndex = headerCells.findIndex((h) => ['expected_decision', 'expecteddecision', 'expected'].includes(h));

  const startLine = promptIndex >= 0 ? 1 : 0;
  const selectedIndex = promptIndex >= 0 ? promptIndex : 0;

  return lines
    .slice(startLine)
    .map((line) => {
      const cells = parseCsvLine(line);
      const prompt = (cells[selectedIndex] || '').trim();
      const expectedDecision = expectedIndex >= 0
        ? normalizeExpectedDecision(cells[expectedIndex])
        : undefined;
      return { prompt, expectedDecision };
    })
    .filter((item) => item.prompt.length > 0);
}

function extractPrompt(obj: any): string {
  if (!obj || typeof obj !== 'object') return '';
  const candidate =
    obj.prompt ||
    obj.input ||
    obj.text ||
    obj.content ||
    obj.user_input ||
    obj.mutated_prompt ||
    obj.base_prompt ||
    obj.test_case_prompt;
  return typeof candidate === 'string' ? candidate.trim() : '';
}

function extractDatasetItem(obj: any): DatasetPromptItem {
  const prompt = extractPrompt(obj);
  const expectedDecision = normalizeExpectedDecision(
    obj?.expected_decision ?? obj?.expectedDecision ?? obj?.expected
  );
  return { prompt, expectedDecision };
}

function parseMetricsFromDetails(details: string): DatasetEvalMetrics | null {
  const text = details || '';
  const labeledTotal = Number((text.match(/标注样本：\s*(\d+)/)?.[1]) || NaN);
  const accuracy = Number((text.match(/准确率：\s*([\d.]+)%/)?.[1]) || NaN);
  const falseNegativeRate = Number((text.match(/漏报率（该拦截却放行）：\s*([\d.]+)%/)?.[1]) || NaN);
  const falsePositiveRate = Number((text.match(/误报率（该放行却拦截）：\s*([\d.]+)%/)?.[1]) || NaN);
  const confusion = text.match(/TP\/TN\/FP\/FN：\s*(\d+)\/(\d+)\/(\d+)\/(\d+)/);

  if (!Number.isFinite(labeledTotal) || !Number.isFinite(accuracy) || !confusion) return null;

  const truePositive = Number(confusion[1]);
  const trueNegative = Number(confusion[2]);
  const falsePositive = Number(confusion[3]);
  const falseNegative = Number(confusion[4]);

  return {
    labeledTotal,
    truePositive,
    trueNegative,
    falsePositive,
    falseNegative,
    accuracy,
    falseNegativeRate: Number.isFinite(falseNegativeRate) ? falseNegativeRate : 0,
    falsePositiveRate: Number.isFinite(falsePositiveRate) ? falsePositiveRate : 0,
    precision: (truePositive + falsePositive) > 0 ? (truePositive / (truePositive + falsePositive)) * 100 : 0,
    recall: (truePositive + falseNegative) > 0 ? (truePositive / (truePositive + falseNegative)) * 100 : 0,
  };
}

function sanitizeOutputForDisplay(raw: unknown): {
  text: string;
  thinkRemoved: boolean;
} {
  if (typeof raw !== 'string') {
    return { text: '', thinkRemoved: false };
  }

  let text = raw;

  // 1) 去掉成对 <think>...</think> 段
  const pairedThinkPattern = /<think>[\s\S]*?<\/think>/gi;
  const hadPairedThink = pairedThinkPattern.test(text);
  text = text.replace(pairedThinkPattern, '');

  // 2) 兜底：若只出现开标签没有闭标签，直接截掉后续内容
  const openThinkIndex = text.toLowerCase().indexOf('<think>');
  const hadUnclosedThink = openThinkIndex >= 0;
  if (hadUnclosedThink) {
    text = text.slice(0, openThinkIndex);
  }

  // 3) 清理空白
  text = text.replace(/\n{3,}/g, '\n\n').trim();

  return {
    text,
    thinkRemoved: hadPairedThink || hadUnclosedThink,
  };
}

function buildFormalReply(params: {
  decision: string;
  blockedText: string;
  riskLevel: string;
  riskScore: unknown;
  blockedBy: string;
  blockedReason?: string;
}): string {
  const {
    decision,
    blockedText,
    riskLevel,
    riskScore,
    blockedBy,
    blockedReason,
  } = params;

  const scoreText = typeof riskScore === 'number' ? riskScore.toFixed(3) : (riskScore ?? 'N/A');
  const reasonText = blockedReason ? `主要原因为：${blockedReason}。` : '';

  return `系统评估结论如下：当前决策为 ${decision}（是否拦截：${blockedText}），风险等级为 ${riskLevel}，风险评分为 ${scoreText}，判定来源为 ${blockedBy}。${reasonText}`;
}

async function parseDatasetFile(file: File): Promise<DatasetPromptItem[]> {
  const content = await file.text();
  const name = file.name.toLowerCase();

  if (name.endsWith('.csv')) {
    return parseCsvPrompts(content);
  }

  if (name.endsWith('.jsonl')) {
    return content
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => {
        try {
          return extractDatasetItem(JSON.parse(line));
        } catch {
          return { prompt: '' };
        }
      })
      .filter((item) => item.prompt.length > 0);
  }

  if (name.endsWith('.json')) {
    try {
      const parsed = JSON.parse(content);
      if (Array.isArray(parsed)) {
        return parsed
          .map((item) => (typeof item === 'string' ? { prompt: item.trim() } : extractDatasetItem(item)))
          .filter((item) => item.prompt.length > 0);
      }
      if (typeof parsed === 'object') {
        const list = parsed.items || parsed.data || parsed.samples || parsed.prompts;
        if (!Array.isArray(list)) return [];
        return list
          .map((item: any) => (typeof item === 'string' ? { prompt: item.trim() } : extractDatasetItem(item)))
          .filter((item: DatasetPromptItem) => item.prompt.length > 0);
      }
    } catch {
      return [];
    }
    return [];
  }

  // txt: 每行一条 prompt
  return content
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((prompt) => ({ prompt }));
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
  // 多模态图片支持
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [imageBase64, setImageBase64] = useState<string>('');
  const [showImagePreview, setShowImagePreview] = useState(false);
  const [multimodalMetadata, setMultimodalMetadata] = useState<any>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const imageInputRef = useRef<HTMLInputElement>(null);
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
    setLoading(true);
    setError('');
    setOutput('');
    
    try {
      let response;
      // 如果有图片，使用多模态评估接口
      if (imageBase64 || imageFile) {
        response = await testsAPI.evaluateMultimodal(categoryId, input, imageBase64);
      } else {
        // 否则使用普通评估接口
        response = await testsAPI.evaluate(categoryId, input);
      }
      
      const data = response.data.data;
      const isBlocked = data.isBlocked ?? data.scanResult?.is_blocked;
      const riskScore = data.riskScore ?? data.scanResult?.score;
      const riskLevel = data.riskLevel ?? 'unknown';
      const decision = data.decision || data.scanResult?.decision || (isBlocked ? 'BLOCK' : 'ALLOW');
      const blockedBy = data.blockedBy ?? data.scanResult?.blocked_by ?? (isBlocked ? 'Unknown' : 'Pass');
      const blockedReason = data.blockedReason ?? data.scanResult?.blocked_reason ?? '';
      const blockedText = decision === 'ERROR' ? '扫描失败' : (isBlocked ? '是' : '否');

      const summaryLines = [
        `决策: ${decision}`,
        `是否拦截: ${blockedText}`,
        `风险评分: ${typeof riskScore === 'number' ? riskScore.toFixed(3) : riskScore ?? 'N/A'}`,
        `风险等级: ${riskLevel}`,
        `阻断来源: ${blockedBy}`,
      ];

      if (blockedReason) {
        summaryLines.push(`阻断原因: ${blockedReason}`);
      }

      if (data.output) {
        const sanitized = sanitizeOutputForDisplay(data.output);
        summaryLines.push('', '详细输出:');
        summaryLines.push(
          sanitized.text ||
            buildFormalReply({
              decision,
              blockedText,
              riskLevel,
              riskScore,
              blockedBy,
              blockedReason,
            })
        );
      } else {
        summaryLines.push(
          '',
          '详细输出:',
          buildFormalReply({
            decision,
            blockedText,
            riskLevel,
            riskScore,
            blockedBy,
            blockedReason,
          })
        );
      }

      setOutput(summaryLines.join('\n'));
      
      // 保存多模态元数据用于展示
      if (data.metadata) {
        setMultimodalMetadata(data.metadata);
      } else {
        setMultimodalMetadata(null);
      }
    } catch (err: any) {
      setError(err.response?.data?.message || '评估失败');
    } finally {
      setLoading(false);
    }
  };

  // 处理图片文件上传
  const handleImageChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // 验证文件大小（限制 5MB）
    if (file.size > 5 * 1024 * 1024) {
      setError('图片文件大小不能超过 5MB');
      return;
    }

    // 验证文件类型
    if (!file.type.startsWith('image/')) {
      setError('请选择有效的图片文件');
      return;
    }

    setImageFile(file);
    setError('');

    // 转换为 base64
    const reader = new FileReader();
    reader.onload = (e) => {
      const base64String = e.target?.result as string;
      setImageBase64(base64String);
      setShowImagePreview(true);
    };
    reader.onerror = () => {
      setError('读取图片文件失败');
    };
    reader.readAsDataURL(file);
  };

  // 清除图片
  const clearImage = () => {
    setImageFile(null);
    setImageBase64('');
    setShowImagePreview(false);
    setMultimodalMetadata(null);
    if (imageInputRef.current) {
      imageInputRef.current.value = '';
    }
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

    try {
      const promptItems = await parseDatasetFile(datasetFile);
      if (promptItems.length === 0) {
        setError('数据集中未解析到有效 prompt，请检查文件格式（csv/json/jsonl/txt）');
        return;
      }

      const response = await testsAPI.saveDatasetTest({
        categoryId,
        fileName: datasetFile.name,
        fileSize: datasetFile.size,
        promptItems,
      });

      const data = response.data?.data;
      const computed = data?.computedStats;
      if (!computed) {
        setError('后端未返回数据集统计结果');
        return;
      }

      setDatasetStats({
        total: computed.total,
        blocked: computed.blocked,
        passed: computed.passed,
        blockRate: `${computed.blockRate.toFixed(1)}%`,
        avgRiskScore: computed.avgRiskScore.toFixed(3),
        riskDistribution: computed.riskDistribution,
        categoryDistribution: computed.categoryDistribution,
        riskScoreDistribution: computed.riskScoreDistribution,
        metrics: computed.metrics || null,
        details: computed.details,
      });
    } catch (err: any) {
      console.error('Dataset test failed:', err);
      setError(err.response?.data?.message || '数据集测试失败');
    } finally {
      setDatasetTesting(false);
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
        const sanitized = sanitizeOutputForDisplay(response.data.data.output);
        const raw = response.data.data;
        const fallback = buildFormalReply({
          decision: String(raw.decision || 'UNKNOWN'),
          blockedText: raw.isBlocked ? '是' : '否',
          riskLevel: String(raw.riskLevel || 'unknown'),
          riskScore: raw.riskScore,
          blockedBy: String(raw.blockedBy || 'Unknown'),
          blockedReason: raw.blockedReason,
        });
        setOutput(sanitized.text || fallback);
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
          metrics: data.metrics || parseMetricsFromDetails(data.details),
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
            
            {/* 图片上传区域 */}
            <div className="mt-4">
              <label className="text-sm text-slate-400 mb-2 block">上传图片（可选）</label>
              <div
                onClick={() => imageInputRef.current?.click()}
                className="flex items-center justify-center gap-3 border-2 border-dashed border-slate-600 hover:border-purple-500 rounded p-6 cursor-pointer transition-colors group bg-slate-700/20 hover:bg-slate-700/40"
              >
                <Upload className="w-5 h-5 text-slate-500 group-hover:text-purple-400 transition-colors" />
                <span className="text-slate-400 group-hover:text-slate-300 text-sm transition-colors">
                  {imageFile ? `已选择: ${imageFile.name}` : '点击选择图片或拖拽上传（JPG/PNG, ≤5MB）'}
                </span>
                <input
                  ref={imageInputRef}
                  type="file"
                  accept="image/jpeg,image/png,image/jpg"
                  className="hidden"
                  onChange={handleImageChange}
                />
              </div>

              {/* 图片预览 */}
              {showImagePreview && imageBase64 && (
                <div className="mt-4 relative">
                  <div className="flex items-start gap-4">
                    <div className="flex-shrink-0">
                      <img
                        src={imageBase64}
                        alt="预览"
                        className="h-32 w-32 object-cover rounded border border-slate-600"
                      />
                    </div>
                    <div className="flex-1">
                      <p className="text-sm text-slate-400">图片已上传</p>
                      <p className="text-xs text-slate-500 mt-1">大小: {(imageFile!.size / 1024).toFixed(1)} KB</p>
                      <button
                        onClick={clearImage}
                        className="mt-2 flex items-center gap-1 px-3 py-1 text-xs bg-red-500/20 hover:bg-red-500/30 text-red-300 rounded transition-colors"
                      >
                        <X className="w-3 h-3" /> 移除图片
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>

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
            
            {/* 多模态元数据展示 */}
            {multimodalMetadata && (
              <div className="mt-4 border-t border-slate-600 pt-4">
                <h4 className="text-sm font-semibold text-slate-300 mb-3">多模态扫描详情</h4>
                <div className="space-y-2 text-sm">
                  <div>
                    <p className="text-slate-400">
                      <span className="font-semibold text-slate-300">OCR 提取文本：</span>
                    </p>
                    <p className="text-slate-300 ml-4 mt-1 p-2 bg-slate-900/50 rounded border border-slate-700">
                      {multimodalMetadata.ocrText && String(multimodalMetadata.ocrText).trim().length > 0
                        ? multimodalMetadata.ocrText
                        : '（未识别到有效文本）'}
                    </p>
                  </div>
                  {multimodalMetadata.ocrQuality !== undefined && (
                    <p className="text-slate-400">
                      <span className="font-semibold text-slate-300">OCR 质量分：</span>
                      <span className="ml-2 text-cyan-300">{Number(multimodalMetadata.ocrQuality).toFixed(3)}</span>
                    </p>
                  )}
                  {multimodalMetadata.forceHeavyCheck !== undefined && (
                    <p className="text-slate-400">
                      <span className="font-semibold text-slate-300">低质量强制重检：</span>
                      <span className="ml-2 text-amber-300">{multimodalMetadata.forceHeavyCheck ? '是' : '否'}</span>
                    </p>
                  )}
                  {multimodalMetadata.lightScore !== undefined && (
                    <p className="text-slate-400">
                      <span className="font-semibold text-slate-300">轻量层分数：</span>
                      <span className="ml-2 text-purple-300">{multimodalMetadata.lightScore?.toFixed(3)}</span>
                    </p>
                  )}
                  {multimodalMetadata.minimaxScore !== undefined && (
                    <p className="text-slate-400">
                      <span className="font-semibold text-slate-300">MiniMax 重检分数：</span>
                      <span className="ml-2 text-purple-300">{multimodalMetadata.minimaxScore?.toFixed(3)}</span>
                    </p>
                  )}
                </div>
              </div>
            )}
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
                    <span>正在进行真实检测，请稍候...</span>
                  </div>
                ) : datasetStats ? (
                  <>
                    <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3 mb-5">
                      {[
                        { label: '总样本数', value: datasetStats.total, color: 'text-blue-400' },
                        { label: '通过样本', value: datasetStats.passed, color: 'text-green-400' },
                        { label: '拦截样本', value: datasetStats.blocked, color: 'text-red-400' },
                        { label: '拦截率', value: datasetStats.blockRate, color: 'text-orange-400' },
                        { label: '准确率', value: datasetStats.metrics ? `${datasetStats.metrics.accuracy.toFixed(1)}%` : '-', color: 'text-cyan-400' },
                        { label: '漏报率', value: datasetStats.metrics ? `${datasetStats.metrics.falseNegativeRate.toFixed(1)}%` : '-', color: 'text-rose-400' },
                        { label: '误报率', value: datasetStats.metrics ? `${datasetStats.metrics.falsePositiveRate.toFixed(1)}%` : '-', color: 'text-amber-300' },
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
                  <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
                    {[
                      { label: '总样本数', value: (selectedHistoryItem as DatasetTestResult).total, color: 'text-blue-400' },
                      { label: '通过样本', value: (selectedHistoryItem as DatasetTestResult).passed, color: 'text-green-400' },
                      { label: '拦截样本', value: (selectedHistoryItem as DatasetTestResult).blocked, color: 'text-red-400' },
                      { label: '拦截率', value: `${(selectedHistoryItem as DatasetTestResult).blockRate.toFixed(1)}%`, color: 'text-orange-400' },
                      { label: '准确率', value: datasetStats?.metrics ? `${datasetStats.metrics.accuracy.toFixed(1)}%` : '-', color: 'text-cyan-400' },
                      { label: '漏报率', value: datasetStats?.metrics ? `${datasetStats.metrics.falseNegativeRate.toFixed(1)}%` : '-', color: 'text-rose-400' },
                      { label: '误报率', value: datasetStats?.metrics ? `${datasetStats.metrics.falsePositiveRate.toFixed(1)}%` : '-', color: 'text-amber-300' },
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
