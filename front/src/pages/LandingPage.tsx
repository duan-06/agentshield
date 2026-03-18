import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuthStore } from '../store/authStore';
import { motion } from 'framer-motion';
import { Shield, Zap, Lock, BarChart3 } from 'lucide-react';

export default function LandingPage() {
  const navigate = useNavigate();
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);

  const handleExplore = () => {
    const element = document.getElementById('features');
    element?.scrollIntoView({ behavior: 'smooth' });
  };

  const handleTryExample = () => {
    if (isAuthenticated) {
      navigate('/try-example');
    } else {
      navigate('/login');
    }
  };

  const handleBringYourOwn = () => {
    if (isAuthenticated) {
      navigate('/bring-your-own');
    } else {
      navigate('/login');
    }
  };

  return (
    <div className="bg-gradient-to-b from-slate-900 via-slate-800 to-slate-900 flex flex-col">
      {/* Hero Section */}
      <section className="relative h-screen flex items-center justify-center overflow-hidden">
        {/* Background gradient */}
        <div className="absolute inset-0 bg-gradient-to-r from-blue-600/20 via-purple-600/20 to-pink-600/20 blur-3xl" />
        
        <div className="relative z-10 text-center px-4 w-full space-y-12">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
          >
            <Shield className="w-24 h-24 mx-auto text-blue-400 mb-8" />
            <h1 className="text-6xl md:text-7xl font-bold text-white">
              AgentShield
            </h1>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.2 }}
            className="space-y-4"
          >
            <p className="text-2xl md:text-3xl text-gray-300">
              AI 安全护栏系统
            </p>
            <p className="text-lg text-gray-400">
              防护注入攻击、越狱攻击、有害内容过滤
            </p>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.4 }}
            className="pt-12"
          >
            <button
              onClick={handleExplore}
              className="px-8 py-3 bg-blue-500 hover:bg-blue-600 text-white font-semibold rounded-lg transition-colors"
            >
              开始探索
            </button>
          </motion.div>

          {/* Scroll indicator */}
          <motion.div
            animate={{ y: [0, 10, 0] }}
            transition={{ duration: 2, repeat: Infinity }}
            className="absolute bottom-12 left-1/2 transform -translate-x-1/2"
          >
            <div className="text-gray-400 text-sm"></div>
          </motion.div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-20 px-4 bg-slate-800/50">
        <div className="max-w-6xl mx-auto">
          <motion.h2
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            transition={{ duration: 0.6 }}
            className="text-4xl font-bold text-center text-white mb-16"
          >
            核心功能
          </motion.h2>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-8 mb-16">
            {[
              { icon: Lock, title: '注入攻击防护', desc: '检测和阻止 Prompt 注入攻击' },
              { icon: Zap, title: '越狱防护', desc: '识别和防止模型越狱尝试' },
              { icon: Shield, title: '内容过滤', desc: '过滤有害和不当内容' },
              { icon: BarChart3, title: '实时分析', desc: '生成详细的安全分析报告' },
            ].map((feature, idx) => (
              <motion.div
                key={idx}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: idx * 0.1 }}
                className="p-6 bg-slate-700/50 rounded-lg border border-slate-600 hover:border-blue-500 transition-colors"
              >
                <feature.icon className="w-12 h-12 text-blue-400 mb-4" />
                <h3 className="text-xl font-semibold text-white mb-2">{feature.title}</h3>
                <p className="text-gray-400">{feature.desc}</p>
              </motion.div>
            ))}
          </div>

          {/* About Section */}
          <motion.div
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            transition={{ duration: 0.6 }}
            className="bg-slate-700/50 rounded-lg p-8 border border-slate-600 mb-16"
          >
            <h3 className="text-2xl font-bold text-white mb-4">关于项目</h3>
            <p className="text-gray-300 mb-4">
              AgentShield 是一套完整的 AI 安全护栏系统，旨在保护 AI 应用免受各种安全威胁。
              我们提供了一套全面的工具来检测、分析和防止恶意输入和输出。
            </p>
            <p className="text-gray-400">
              项目源代码：
              <a href="#" className="text-blue-400 hover:text-blue-300 ml-2">
                GitHub Repository
              </a>
            </p>
          </motion.div>

          {/* Action Buttons */}
          <div className="grid md:grid-cols-2 gap-8">
            <motion.button
              initial={{ opacity: 0, x: -20 }}
              whileInView={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.6 }}
              onClick={handleTryExample}
              className="py-4 px-8 bg-blue-500 hover:bg-blue-600 text-white font-semibold rounded-lg transition-colors text-lg"
            >
              示例体验
            </motion.button>
            <motion.button
              initial={{ opacity: 0, x: 20 }}
              whileInView={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.6 }}
              onClick={handleBringYourOwn}
              className="py-4 px-8 bg-purple-500 hover:bg-purple-600 text-white font-semibold rounded-lg transition-colors text-lg"
            >
              自定义风险
            </motion.button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-slate-900/80 border-t border-slate-700 py-12 px-4">
        <div className="max-w-6xl mx-auto">
          <div className="grid md:grid-cols-4 gap-8 mb-8">
            {/* Brand */}
            <div>
              <div className="flex items-center gap-2 mb-4">
                <Shield className="w-6 h-6 text-blue-400" />
                <span className="text-lg font-bold text-white">AgentShield</span>
              </div>
              <p className="text-gray-400 text-sm">
                AI 安全护栏系统，保护您的应用免受安全威胁
              </p>
            </div>

            {/* Product */}
            <div>
              <h4 className="text-white font-semibold mb-4">产品</h4>
              <ul className="space-y-2 text-gray-400 text-sm">
                <li><a href="#" className="hover:text-blue-400 transition-colors">示例体验</a></li>
                <li><a href="#" className="hover:text-blue-400 transition-colors">自定义风险</a></li>
                <li><a href="#" className="hover:text-blue-400 transition-colors">文档</a></li>
              </ul>
            </div>

            {/* Resources */}
            <div>
              <h4 className="text-white font-semibold mb-4">资源</h4>
              <ul className="space-y-2 text-gray-400 text-sm">
                <li><a href="#" className="hover:text-blue-400 transition-colors">GitHub</a></li>
                <li><a href="#" className="hover:text-blue-400 transition-colors">API 文档</a></li>
                <li><a href="#" className="hover:text-blue-400 transition-colors">博客</a></li>
              </ul>
            </div>

            {/* Contact */}
            <div>
              <h4 className="text-white font-semibold mb-4">联系我们</h4>
              <ul className="space-y-2 text-gray-400 text-sm">
                <li><a href="mailto:contact@agentshield.com" className="hover:text-blue-400 transition-colors">Email</a></li>
                <li><a href="#" className="hover:text-blue-400 transition-colors">Twitter</a></li>
                <li><a href="#" className="hover:text-blue-400 transition-colors">Discord</a></li>
              </ul>
            </div>
          </div>

          {/* Divider */}
          <div className="border-t border-slate-700 pt-8">
            <div className="flex flex-col md:flex-row justify-between items-center text-gray-400 text-sm">
              <p>© 2024 AgentShield. 由四川大学 C4 小队开发。保留所有权利。</p>
              <div className="flex gap-6 mt-4 md:mt-0">
                <a href="#" className="hover:text-blue-400 transition-colors">隐私政策</a>
                <a href="#" className="hover:text-blue-400 transition-colors">服务条款</a>
                <a href="#" className="hover:text-blue-400 transition-colors">Cookie 设置</a>
              </div>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
