import React, { useState } from 'react';
import { Shield, Lock, User, AlertCircle, Terminal, ChevronRight } from 'lucide-react';
import { motion } from 'motion/react';
import { User as UserType, UserRole } from '../types';

interface LoginProps {
  onLogin: (user: UserType) => void;
}

const MOCK_USERS: Record<string, { password: string, role: UserRole, email: string }> = {
  'admin': { password: 'password123', role: 'Admin', email: 'admin@sentinel.io' },
  'analyst': { password: 'password123', role: 'Analyst', email: 'analyst@sentinel.io' },
};

export default function Login({ onLogin }: LoginProps) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 1000));

    const userRecord = MOCK_USERS[username.toLowerCase()];
    if (userRecord && userRecord.password === password) {
      onLogin({
        id: Math.random().toString(36).substr(2, 9),
        username: username.charAt(0).toUpperCase() + username.slice(1),
        role: userRecord.role,
        email: userRecord.email,
        lastLogin: new Date().toISOString(),
      });
    } else {
      setError('Invalid credentials. Access denied.');
    }
    setIsLoading(false);
  };

  return (
    <div className="min-h-screen bg-[#050505] flex items-center justify-center p-4 font-sans">
      {/* Background Grid Effect */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#80808012_1px,transparent_1px),linear-gradient(to_bottom,#80808012_1px,transparent_1px)] bg-[size:24px_24px]"></div>
      <div className="absolute inset-0 bg-radial-gradient(circle_at_center,transparent_0%,#050505_100%)"></div>

      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="relative w-full max-w-md"
      >
        <div className="bg-[#0c0c0e] border border-zinc-800/50 rounded-2xl p-8 shadow-2xl shadow-emerald-500/5">
          <div className="flex flex-col items-center mb-8">
            <div className="w-16 h-16 bg-emerald-500/10 border border-emerald-500/20 rounded-2xl flex items-center justify-center mb-4">
              <Shield className="w-8 h-8 text-emerald-500" />
            </div>
            <h1 className="text-2xl font-bold text-zinc-100 tracking-tight">Sentinel OS</h1>
            <p className="text-xs text-zinc-500 uppercase tracking-[0.2em] mt-2">Threat Intelligence Platform</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="space-y-2">
              <label className="text-[10px] uppercase font-bold text-zinc-500 tracking-widest ml-1">Terminal ID</label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-600" />
                <input 
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="admin or analyst"
                  className="w-full bg-[#0a0a0c] border border-zinc-800 rounded-xl py-3 pl-10 pr-4 text-sm text-zinc-200 focus:outline-none focus:border-emerald-500/50 transition-all placeholder:text-zinc-700"
                  required
                />
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-[10px] uppercase font-bold text-zinc-500 tracking-widest ml-1">Access Key</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-600" />
                <input 
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full bg-[#0a0a0c] border border-zinc-800 rounded-xl py-3 pl-10 pr-4 text-sm text-zinc-200 focus:outline-none focus:border-emerald-500/50 transition-all placeholder:text-zinc-700"
                  required
                />
              </div>
            </div>

            {error && (
              <motion.div 
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                className="flex items-center gap-2 text-red-500 bg-red-500/10 border border-red-500/20 p-3 rounded-xl text-xs"
              >
                <AlertCircle className="w-4 h-4" />
                {error}
              </motion.div>
            )}

            <button 
              type="submit"
              disabled={isLoading}
              className="w-full bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-bold py-3 rounded-xl transition-all flex items-center justify-center gap-2 group"
            >
              {isLoading ? (
                <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              ) : (
                <>
                  Initialize Session
                  <ChevronRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                </>
              )}
            </button>
          </form>

          <div className="mt-8 pt-6 border-t border-zinc-800/50">
            <div className="flex items-center gap-2 text-zinc-600 mb-3">
              <Terminal className="w-3 h-3" />
              <span className="text-[10px] uppercase font-bold tracking-widest">System Status</span>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-emerald-500"></div>
                <span className="text-[10px] text-zinc-500">Auth Server: Online</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-emerald-500"></div>
                <span className="text-[10px] text-zinc-500">Encryption: AES-256</span>
              </div>
            </div>
          </div>
        </div>

        <p className="text-center text-zinc-700 text-[10px] mt-6 uppercase tracking-[0.3em]">
          Classified Information • Authorized Personnel Only
        </p>
      </motion.div>
    </div>
  );
}
