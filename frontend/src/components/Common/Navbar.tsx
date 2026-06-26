import React, { useState } from "react";
import { useAuth } from "../../context/AuthContext";
import { Shield, Plus, LogOut, Terminal, Layers, Globe } from "lucide-react";
import { apiCall } from "../../services/api";

interface Project {
  id: string;
  name: string;
  description?: string;
  seed_domains: string[];
}

interface NavbarProps {
  projects: Project[];
  activeProject: Project | null;
  onSelectProject: (p: Project) => void;
  onRefreshProjects: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  projects,
  activeProject,
  onSelectProject,
  onRefreshProjects
}) => {
  const { user, logout } = useAuth();
  const [showModal, setShowModal] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [seedDomains, setSeedDomains] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const handleCreateProject = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSubmitting(true);

    const domainsList = seedDomains
      .split(",")
      .map(d => d.trim().toLowerCase())
      .filter(d => d.length > 0);

    if (domainsList.length === 0) {
      setError("At least one seed domain is required");
      setSubmitting(false);
      return;
    }

    try {
      const newProj = await apiCall("/projects", {
        method: "POST",
        body: JSON.stringify({
          name,
          description,
          seed_domains: domainsList
        })
      });
      setShowModal(false);
      setName("");
      setDescription("");
      setSeedDomains("");
      onRefreshProjects();
      onSelectProject(newProj);
    } catch (err: any) {
      setError(err.message || "Failed to create project");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <>
      <nav className="bg-dark-card border-b border-dark-border px-6 py-4 flex items-center justify-between z-20 relative">
        <div className="flex items-center space-x-6">
          <div className="flex items-center space-x-2">
            <Shield className="w-6 h-6 text-cyber-accent animate-pulse" />
            <span className="font-extrabold tracking-widest text-lg bg-gradient-to-r from-cyber-primary to-cyber-accent bg-clip-text text-transparent">
              RECONFORGE
            </span>
          </div>

          {/* Project Switcher */}
          <div className="flex items-center space-x-2 border-l border-dark-border pl-6">
            <Layers className="w-4 h-4 text-slate-400" />
            <select
              value={activeProject?.id || ""}
              onChange={(e) => {
                const proj = projects.find(p => p.id === e.target.value);
                if (proj) onSelectProject(proj);
              }}
              className="bg-dark-bg border border-dark-border rounded px-2.5 py-1.5 text-sm font-semibold text-slate-200 focus:outline-none focus:border-cyber-accent"
            >
              {projects.length === 0 ? (
                <option value="">No Active Projects</option>
              ) : (
                projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))
              )}
            </select>

            <button
              onClick={() => setShowModal(true)}
              className="bg-cyber-primary/10 border border-cyber-primary/30 hover:bg-cyber-primary/20 text-cyber-accent px-2.5 py-1.5 rounded text-xs font-bold transition-all duration-200 flex items-center space-x-1 cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>New Project</span>
            </button>
          </div>
        </div>

        {/* User Status and Logout */}
        <div className="flex items-center space-x-4">
          <div className="text-right">
            <div className="text-xs font-mono text-slate-400 uppercase tracking-wider">Operator</div>
            <div className="text-sm font-bold text-slate-200">{user?.username}</div>
          </div>
          <button
            onClick={logout}
            className="p-2 bg-dark-bg border border-dark-border hover:border-cyber-danger/50 text-slate-400 hover:text-cyber-danger rounded-lg transition-colors duration-200 cursor-pointer"
            title="Disconnect Terminal"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </nav>

      {/* New Project Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50 animate-fadeIn">
          <div className="bg-dark-card border border-dark-border max-w-md w-full p-6 rounded-lg glass shadow-2xl relative">
            <h2 className="text-xl font-bold mb-1 text-cyber-accent flex items-center space-x-2">
              <Terminal className="w-5 h-5" />
              <span>PROVISION SCANNING SCOPE</span>
            </h2>
            <p className="text-xs text-slate-400 mb-4 font-mono uppercase tracking-wider">Configure authorized target parameters</p>

            {error && <div className="p-3 bg-cyber-danger/10 border border-cyber-danger/30 text-cyber-danger text-sm rounded mb-4">{error}</div>}

            <form onSubmit={handleCreateProject} className="space-y-4">
              <div>
                <label className="block text-xs font-mono text-slate-400 uppercase tracking-widest mb-1.5">Project Designation</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Scope-Omega-Audit"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full bg-dark-input border border-dark-border rounded p-2 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyber-accent"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-400 uppercase tracking-widest mb-1.5">Description (Optional)</label>
                <textarea
                  placeholder="System notes and operation boundaries..."
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className="w-full bg-dark-input border border-dark-border rounded p-2 text-sm text-slate-100 placeholder-slate-500 h-20 focus:outline-none focus:border-cyber-accent resize-none"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-400 uppercase tracking-widest mb-1.5 flex items-center justify-between">
                  <span>Authorized Seed Domains</span>
                  <span className="text-[10px] text-cyber-warning normal-case">Comma-separated</span>
                </label>
                <div className="relative">
                  <span className="absolute top-2.5 left-2.5 text-slate-500">
                    <Globe className="w-4 h-4" />
                  </span>
                  <input
                    type="text"
                    required
                    placeholder="target.org, test-environment.net"
                    value={seedDomains}
                    onChange={(e) => setSeedDomains(e.target.value)}
                    className="w-full bg-dark-input border border-dark-border rounded pl-9 pr-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyber-accent"
                  />
                </div>
              </div>

              <div className="flex justify-end space-x-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 border border-dark-border rounded text-sm font-semibold text-slate-400 hover:text-slate-200 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-4 py-2 bg-gradient-to-r from-cyber-primary to-cyber-accent text-white rounded text-sm font-bold uppercase tracking-wider hover:opacity-90 active:scale-[0.98] transition-all cursor-pointer"
                >
                  {submitting ? "Deploying..." : "Deploy Project"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  );
};
