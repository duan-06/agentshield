import { useNavigate, useLocation } from 'react-router-dom';
import { useAuthStore } from '../store/authStore';
import { Shield, LogOut, LogIn, ArrowLeft } from 'lucide-react';
import { motion } from 'framer-motion';

export default function Navbar() {
  const navigate = useNavigate();
  const location = useLocation();
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const logout = useAuthStore((state) => state.logout);
  const user = useAuthStore((state) => state.user);

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  const handleLogin = () => {
    navigate('/login');
  };

  const handleHome = () => {
    navigate('/');
  };

  const handleBack = () => {
    navigate(-1);
  };

  const isOnDetailPage = location.pathname === '/try-example' || location.pathname === '/bring-your-own';

  return (
    <nav className="bg-slate-800/50 backdrop-blur-sm border-b border-slate-700 sticky top-0 z-50">
      <div className="px-6 py-4">
        <div className="flex items-center justify-between">
          {/* Left Section */}
          <div className="flex items-center gap-8">
            {/* Back Button - Always reserve space */}
            <div className="w-5 h-5">
              {isOnDetailPage && (
                <motion.button
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  onClick={handleBack}
                  className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors"
                  title="返回"
                >
                  <ArrowLeft className="w-5 h-5" />
                </motion.button>
              )}
            </div>

            {/* Logo */}
            <button
              onClick={handleHome}
              className="flex items-center gap-2 hover:opacity-80 transition-opacity"
            >
              <Shield className="w-6 h-6 text-blue-400" />
              <span className="text-xl font-bold text-white">AgentShield</span>
            </button>

            {/* Navigation Links */}
            <div className="hidden md:flex items-center gap-6">
              <button
                onClick={handleHome}
                className={`transition-colors ${
                  location.pathname === '/'
                    ? 'text-blue-400 font-semibold'
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                主页
              </button>
              {isAuthenticated && (
                <>
                  <button
                    onClick={() => navigate('/try-example')}
                    className={`transition-colors ${
                      location.pathname === '/try-example'
                        ? 'text-blue-400 font-semibold'
                        : 'text-gray-400 hover:text-white'
                    }`}
                  >
                    示例体验
                  </button>
                  <button
                    onClick={() => navigate('/bring-your-own')}
                    className={`transition-colors ${
                      location.pathname === '/bring-your-own'
                        ? 'text-blue-400 font-semibold'
                        : 'text-gray-400 hover:text-white'
                    }`}
                  >
                    自定义风险
                  </button>
                </>
              )}
            </div>
          </div>

          {/* Right Section */}
          <div className="flex items-center gap-4">
            {isAuthenticated ? (
              <>
                <span className="text-gray-400 text-sm">
                  {user?.username}
                </span>
                <motion.button
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  onClick={handleLogout}
                  className="flex items-center gap-2 px-4 py-2 bg-red-500/20 hover:bg-red-500/30 text-red-300 rounded transition-colors"
                >
                  <LogOut className="w-4 h-4" />
                  <span className="hidden sm:inline">登出</span>
                </motion.button>
              </>
            ) : (
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={handleLogin}
                className="flex items-center gap-2 px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded transition-colors"
              >
                <LogIn className="w-4 h-4" />
                <span className="hidden sm:inline">登录</span>
              </motion.button>
            )}
          </div>
        </div>
      </div>
    </nav>
  );
}
