import React, { useState } from "react";
import { useAuth } from "../../context/AuthContext";
import { Shield, Terminal, Key, Mail, User, ShieldAlert } from "lucide-react";

export const AuthPage: React.FC = () => {
  const { login, registerUser } = useAuth();
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);
    setLoading(true);

    try {
      if (isLogin) {
        const formData = new FormData();
        formData.append("username", username);
        formData.append("password", password);
        await login(formData);
      } else {
        await registerUser(username, email, password);
        setSuccessMsg("Registration successful! Proceed to Login.");
        setIsLogin(true);
        setPassword("");
      }
    } catch (err: any) {
      setError(err.message || "Something went wrong. Please check your inputs.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-dark-bg flex items-center justify-center p-4 relative overflow-hidden scanline">
      {/* Background Matrix/Grid effect */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#1E2638_1px,transparent_1px),linear-gradient(to_bottom,#1E2638_1px,transparent_1px)] bg-[size:4rem_4rem] opacity-20"></div>
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyber-primary/10 rounded-full blur-3xl pulse-slow"></div>
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-cyber-accent/10 rounded-full blur-3xl pulse-slow" style={{ animationDelay: "1.5s" }}></div>

      {/* Main Auth Container */}
      <div className="w-full max-w-md glass p-8 rounded-xl border border-dark-border/80 glow-blue z-10 relative">
        <div className="flex flex-col items-center mb-8">
          <div className="bg-cyber-primary/10 p-3 rounded-full border border-cyber-primary/30 mb-3 animate-pulse">
            <Shield className="w-10 h-10 text-cyber-accent" />
          </div>
          <h1 className="text-3xl font-extrabold tracking-wider bg-gradient-to-r from-cyber-primary via-cyber-accent to-cyber-success bg-clip-text text-transparent">
            RECONFORGE
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-mono tracking-widest uppercase">
            Attack Surface Discovery Platform
          </p>
        </div>

        {/* Tab switcher */}
        <div className="flex border-b border-dark-border mb-6">
          <button
            onClick={() => { setIsLogin(true); setError(null); }}
            className={`flex-1 pb-3 text-sm font-semibold tracking-wider uppercase transition-colors duration-200 ${
              isLogin ? "text-cyber-accent border-b-2 border-cyber-accent font-bold" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            Authenticate
          </button>
          <button
            onClick={() => { setIsLogin(false); setError(null); }}
            className={`flex-1 pb-3 text-sm font-semibold tracking-wider uppercase transition-colors duration-200 ${
              !isLogin ? "text-cyber-accent border-b-2 border-cyber-accent font-bold" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            Provision Account
          </button>
        </div>

        {/* Status Alerts */}
        {error && (
          <div className="mb-4 p-3 bg-cyber-danger/10 border border-cyber-danger/30 rounded-lg flex items-start space-x-2 text-cyber-danger text-sm">
            <ShieldAlert className="w-5 h-5 flex-shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}
        {successMsg && (
          <div className="mb-4 p-3 bg-cyber-success/10 border border-cyber-success/30 rounded-lg flex items-start space-x-2 text-cyber-success text-sm">
            <Shield className="w-5 h-5 flex-shrink-0 mt-0.5" />
            <span>{successMsg}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-mono text-slate-400 uppercase tracking-widest mb-1.5">
              Operator Username
            </label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-slate-500">
                <User className="w-4 h-4" />
              </span>
              <input
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="e.g. admin_operator"
                className="w-full bg-dark-input border border-dark-border rounded-lg pl-10 pr-3 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyber-accent transition-colors duration-200"
              />
            </div>
          </div>

          {!isLogin && (
            <div>
              <label className="block text-xs font-mono text-slate-400 uppercase tracking-widest mb-1.5">
                Operator Email
              </label>
              <div className="relative">
                <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-slate-500">
                  <Mail className="w-4 h-4" />
                </span>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="operator@reconforge.local"
                  className="w-full bg-dark-input border border-dark-border rounded-lg pl-10 pr-3 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyber-accent transition-colors duration-200"
                />
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs font-mono text-slate-400 uppercase tracking-widest mb-1.5">
              Access Credentials
            </label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-slate-500">
                <Key className="w-4 h-4" />
              </span>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-dark-input border border-dark-border rounded-lg pl-10 pr-3 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyber-accent transition-colors duration-200"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-gradient-to-r from-cyber-primary to-cyber-accent text-white py-3 rounded-lg text-sm font-bold tracking-wider uppercase hover:opacity-90 active:scale-[0.98] transition-all duration-150 flex items-center justify-center space-x-2 shadow-lg cursor-pointer"
          >
            <Terminal className="w-4 h-4" />
            <span>{loading ? "Authenticating..." : isLogin ? "Initialize Terminal" : "Provision Credentials"}</span>
          </button>
        </form>
      </div>
    </div>
  );
};
