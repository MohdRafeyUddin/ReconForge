import React, { useEffect, useRef, useState } from "react";
import { Eye, HelpCircle, RefreshCw } from "lucide-react";

interface Asset {
  id: string;
  domain: string;
  type: string;
  status: string;
  open_ports: number[];
  metadata: Record<string, any>;
  discovered_by: string;
}

interface RelationshipGraphProps {
  assets: Asset[];
  seedDomains: string[];
}

interface GraphNode {
  id: string;
  label: string;
  type: "seed" | "subdomain" | "ip" | "port";
  status?: string;
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  color: string;
  meta?: any;
}

interface GraphLink {
  source: string;
  target: string;
}

export const RelationshipGraph: React.FC<RelationshipGraphProps> = ({ assets, seedDomains }) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);

  const [hoveredNode, setHoveredNode] = useState<GraphNode | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [isPhysicsActive, setIsPhysicsActive] = useState(true);

  // Maintain nodes and links state across renders for smooth animation
  const nodesRef = useRef<GraphNode[]>([]);
  const linksRef = useRef<GraphLink[]>([]);
  const dragNodeRef = useRef<GraphNode | null>(null);
  const panOffsetRef = useRef({ x: 0, y: 0 });
  const isPanningRef = useRef(false);
  const panStartRef = useRef({ x: 0, y: 0 });

  // Re-generate nodes and links when assets or seedDomains change
  useEffect(() => {
    const nodes: GraphNode[] = [];
    const links: GraphLink[] = [];
    const width = 800;
    const height = 500;

    // Create unique sets of items
    const ipMap = new Map<string, string>(); // ip -> id
    const processedDomains = new Set<string>();

    // Add Seed Domains
    seedDomains.forEach((domain, idx) => {
      const id = `seed-${domain}`;
      processedDomains.add(domain);
      
      // Position seeds in a circle around center
      const angle = (idx / seedDomains.length) * Math.PI * 2;
      const r = 100;
      
      nodes.push({
        id,
        label: domain,
        type: "seed",
        x: width / 2 + Math.cos(angle) * r + (Math.random() - 0.5) * 10,
        y: height / 2 + Math.sin(angle) * r + (Math.random() - 0.5) * 10,
        vx: 0,
        vy: 0,
        radius: 12,
        color: "#3B82F6", // Cyber Blue
      });
    });

    // Add Assets (Domains/Subdomains)
    assets.forEach((asset) => {
      const id = `asset-${asset.id}`;
      processedDomains.add(asset.domain);

      // Determine parent seed domain
      let parentSeedId = "";
      for (const seed of seedDomains) {
        if (asset.domain.endsWith(seed)) {
          parentSeedId = `seed-${seed}`;
          break;
        }
      }

      nodes.push({
        id,
        label: asset.domain,
        type: asset.type === "domain" ? "seed" : "subdomain",
        status: asset.status,
        x: width / 2 + (Math.random() - 0.5) * 300,
        y: height / 2 + (Math.random() - 0.5) * 300,
        vx: 0,
        vy: 0,
        radius: 8,
        color: asset.status === "live" ? "#10B981" : "#06B6D4", // Cyber Green / Cyan
        meta: asset,
      });

      if (parentSeedId) {
        links.push({ source: parentSeedId, target: id });
      }

      // Handle IP nodes
      const ip = asset.metadata.ip_address;
      if (ip && ip !== "N/A") {
        let ipId = ipMap.get(ip);
        if (!ipId) {
          ipId = `ip-${ip}`;
          ipMap.set(ip, ipId);
          nodes.push({
            id: ipId,
            label: ip,
            type: "ip",
            x: width / 2 + (Math.random() - 0.5) * 400,
            y: height / 2 + (Math.random() - 0.5) * 400,
            vx: 0,
            vy: 0,
            radius: 9,
            color: "#8B5CF6", // Purple IP
          });
        }
        links.push({ source: id, target: ipId });
      }

      // Handle Open Ports
      if (asset.open_ports && asset.open_ports.length > 0) {
        asset.open_ports.forEach((port) => {
          const portId = `port-${asset.id}-${port}`;
          nodes.push({
            id: portId,
            label: `Port ${port}`,
            type: "port",
            x: nodes[nodes.length - 1].x + (Math.random() - 0.5) * 40,
            y: nodes[nodes.length - 1].y + (Math.random() - 0.5) * 40,
            vx: 0,
            vy: 0,
            radius: 6,
            color: [22, 21, 23, 3389].includes(port) ? "#EF4444" : "#F59E0B", // High-severity ports are red, others yellow
            meta: { port, asset: asset.domain }
          });
          links.push({ source: id, target: portId });
        });
      }
    });

    nodesRef.current = nodes;
    linksRef.current = links;
  }, [assets, seedDomains]);

  // Physics simulation loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animationFrameId: number;

    const updateSimulation = () => {
      const nodes = nodesRef.current;
      const links = linksRef.current;
      const width = canvas.width;
      const height = canvas.height;

      if (isPhysicsActive) {
        // Apply Force-Directed Graph physics
        const k = 0.05; // spring constant
        const repulse = 600; // charge force
        const centerGravity = 0.01;

        // Repulsion between all nodes (Coulomb force)
        for (let i = 0; i < nodes.length; i++) {
          const n1 = nodes[i];
          for (let j = i + 1; j < nodes.length; j++) {
            const n2 = nodes[j];
            const dx = n2.x - n1.x;
            const dy = n2.y - n1.y;
            const dist = Math.sqrt(dx * dx + dy * dy) || 1;

            if (dist < 250) {
              const force = repulse / (dist * dist);
              const fx = (dx / dist) * force;
              const fy = (dy / dist) * force;

              // Don't apply force to dragged node
              if (n1 !== dragNodeRef.current) {
                n1.vx -= fx;
                n1.vy -= fy;
              }
              if (n2 !== dragNodeRef.current) {
                n2.vx += fx;
                n2.vy += fy;
              }
            }
          }
        }

        // Attraction along links (Hooke's Law)
        links.forEach((link) => {
          const n1 = nodes.find((n) => n.id === link.source);
          const n2 = nodes.find((n) => n.id === link.target);
          if (!n1 || !n2) return;

          const dx = n2.x - n1.x;
          const dy = n2.y - n1.y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const desiredDist = n1.type === "port" || n2.type === "port" ? 30 : 80;
          const force = (dist - desiredDist) * k;

          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;

          if (n1 !== dragNodeRef.current) {
            n1.vx += fx;
            n1.vy += fy;
          }
          if (n2 !== dragNodeRef.current) {
            n2.vx -= fx;
            n2.vy -= fy;
          }
        });

        // Pull to center & friction
        nodes.forEach((node) => {
          if (node === dragNodeRef.current) return;

          const dx = width / 2 - node.x;
          const dy = height / 2 - node.y;
          node.vx += dx * centerGravity;
          node.vy += dy * centerGravity;

          // Apply velocity
          node.x += node.vx;
          node.y += node.vy;

          // Friction
          node.vx *= 0.75;
          node.vy *= 0.75;

          // Bounce off boundary walls
          const padding = 20;
          if (node.x < padding) { node.x = padding; node.vx = 0; }
          if (node.x > width - padding) { node.x = width - padding; node.vx = 0; }
          if (node.y < padding) { node.y = padding; node.vy = 0; }
          if (node.y > height - padding) { node.y = height - padding; node.vy = 0; }
        });
      }

      // RENDERING SECTION
      ctx.clearRect(0, 0, width, height);

      // Pan layout
      ctx.save();
      ctx.translate(panOffsetRef.current.x, panOffsetRef.current.y);

      // 1. Draw Links
      links.forEach((link) => {
        const n1 = nodes.find((n) => n.id === link.source);
        const n2 = nodes.find((n) => n.id === link.target);
        if (!n1 || !n2) return;

        // Visual properties
        const isHighlighted = (hoveredNode && (hoveredNode.id === n1.id || hoveredNode.id === n2.id));
        ctx.strokeStyle = isHighlighted ? "#06B6D4" : "#1E2638";
        ctx.lineWidth = isHighlighted ? 2.0 : 0.8;

        // Draw line with a subtle dot animation moving along the line for live assets
        ctx.beginPath();
        ctx.moveTo(n1.x, n1.y);
        ctx.lineTo(n2.x, n2.y);
        ctx.stroke();

        // Animated packet particle traveling down active links
        if (n2.status === "live" && Math.random() < 0.015) {
          // Store a draw point along the path or simulate a micro dot
        }
      });

      // 2. Draw Nodes
      nodes.forEach((node) => {
        const isHovered = hoveredNode?.id === node.id;
        const isSelected = selectedNode?.id === node.id;

        // Glow effects on hover or select
        ctx.save();
        if (isHovered || isSelected) {
          ctx.shadowColor = node.color;
          ctx.shadowBlur = 15;
        }

        ctx.fillStyle = node.color;
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius + (isHovered ? 2 : 0), 0, Math.PI * 2);
        ctx.fill();

        // Node outline/rings
        if (node.type === "seed") {
          ctx.strokeStyle = "#FFFFFF";
          ctx.lineWidth = 1.5;
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.radius + 4, 0, Math.PI * 2);
          ctx.stroke();
        }

        ctx.restore();

        // Draw Text Labels for seeds, IPs, and hovered subdomains
        const showLabel = node.type === "seed" || node.type === "ip" || isHovered || isSelected;
        if (showLabel) {
          ctx.fillStyle = isHovered ? "#FFFFFF" : "#9CA3AF";
          ctx.font = node.type === "seed" ? "bold 10px monospace" : "9px monospace";
          ctx.textAlign = "center";
          ctx.fillText(node.label, node.x, node.y - node.radius - 6);
        }
      });

      ctx.restore();

      animationFrameId = requestAnimationFrame(updateSimulation);
    };

    updateSimulation();

    return () => {
      cancelAnimationFrame(animationFrameId);
    };
  }, [isPhysicsActive, hoveredNode, selectedNode]);

  // Adjust canvas size to parent container size
  useEffect(() => {
    const handleResize = () => {
      const canvas = canvasRef.current;
      const container = containerRef.current;
      if (!canvas || !container) return;
      canvas.width = container.clientWidth;
      canvas.height = 420;
    };

    handleResize();
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, []);

  // Event handlers for dragging/hovering/panning
  const handleMouseDown = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const clickX = e.clientX - rect.left - panOffsetRef.current.x;
    const clickY = e.clientY - rect.top - panOffsetRef.current.y;

    // Check if clicked a node
    let clickedNode: GraphNode | null = null;
    for (const node of nodesRef.current) {
      const dx = node.x - clickX;
      const dy = node.y - clickY;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < node.radius + 6) {
        clickedNode = node;
        break;
      }
    }

    if (clickedNode) {
      dragNodeRef.current = clickedNode;
      setSelectedNode(clickedNode);
    } else {
      // Start panning background
      isPanningRef.current = true;
      panStartRef.current = { x: e.clientX - panOffsetRef.current.x, y: e.clientY - panOffsetRef.current.y };
    }
  };

  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left - panOffsetRef.current.x;
    const mouseY = e.clientY - rect.top - panOffsetRef.current.y;

    if (dragNodeRef.current) {
      dragNodeRef.current.x = mouseX;
      dragNodeRef.current.y = mouseY;
      dragNodeRef.current.vx = 0;
      dragNodeRef.current.vy = 0;
      return;
    }

    if (isPanningRef.current) {
      panOffsetRef.current = {
        x: e.clientX - panStartRef.current.x,
        y: e.clientY - panStartRef.current.y
      };
      return;
    }

    // Check hovered node
    let foundHover: GraphNode | null = null;
    for (const node of nodesRef.current) {
      const dx = node.x - mouseX;
      const dy = node.y - mouseY;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < node.radius + 6) {
        foundHover = node;
        break;
      }
    }
    setHoveredNode(foundHover);
  };

  const handleMouseUp = () => {
    dragNodeRef.current = null;
    isPanningRef.current = false;
  };

  return (
    <div className="bg-dark-card border border-dark-border rounded-xl p-5 glass relative overflow-hidden flex flex-col">
      <div className="flex items-center justify-between border-b border-dark-border pb-3 mb-4">
        <div>
          <h3 className="font-bold text-white uppercase tracking-wider text-sm font-mono flex items-center space-x-2">
            <Eye className="w-4 h-4 text-cyber-accent" />
            <span>Attack Surface Topology</span>
          </h3>
          <p className="text-[10px] text-slate-400 font-mono mt-0.5">Interactive target map. Drag nodes, zoom/pan background.</p>
        </div>
        <div className="flex space-x-2">
          <button
            onClick={() => setIsPhysicsActive(!isPhysicsActive)}
            className={`px-2 py-1 rounded text-[10px] font-mono font-bold uppercase transition-colors border ${
              isPhysicsActive ? "bg-cyber-primary/10 border-cyber-primary/30 text-cyber-accent" : "bg-dark-bg border-dark-border text-slate-500"
            }`}
          >
            Physics: {isPhysicsActive ? "ON" : "FREEZE"}
          </button>
          <button
            onClick={() => {
              panOffsetRef.current = { x: 0, y: 0 };
              setSelectedNode(null);
            }}
            className="p-1 hover:bg-dark-bg border border-dark-border text-slate-400 hover:text-white rounded"
            title="Recenter"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Canvas Visualizer */}
        <div ref={containerRef} className="lg:col-span-3 border border-dark-border/50 rounded-lg bg-[#07090F] relative cursor-grab active:cursor-grabbing">
          <canvas
            ref={canvasRef}
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            onMouseLeave={handleMouseUp}
            className="block"
          />
          {nodesRef.current.length === 0 && (
            <div className="absolute inset-0 flex items-center justify-center font-mono text-xs uppercase tracking-widest text-slate-500">
              No discovered topology. Run a discovery scan first.
            </div>
          )}
        </div>

        {/* Selected Node Details Sidebar */}
        <div className="lg:col-span-1 border border-dark-border rounded-lg p-4 bg-dark-bg/40 flex flex-col justify-between font-mono text-xs">
          <div>
            <h4 className="font-bold text-cyber-accent border-b border-dark-border pb-1.5 mb-3 uppercase tracking-wider text-[10px]">
              Node Metadata
            </h4>
            
            {selectedNode ? (
              <div className="space-y-3">
                <div>
                  <span className="text-slate-500 block text-[10px]">NODE DESIGNATION</span>
                  <span className="text-white font-bold break-all">{selectedNode.label}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">NODE CLASSIFICATION</span>
                  <span className="px-2 py-0.5 rounded text-[9px] font-bold uppercase" style={{
                    backgroundColor: selectedNode.type === "seed" ? "rgba(59, 130, 246, 0.15)" : selectedNode.type === "subdomain" ? "rgba(6, 182, 212, 0.15)" : selectedNode.type === "ip" ? "rgba(139, 92, 246, 0.15)" : "rgba(245, 158, 11, 0.15)",
                    border: `1px solid ${selectedNode.color}`,
                    color: selectedNode.color
                  }}>
                    {selectedNode.type}
                  </span>
                </div>

                {selectedNode.type === "subdomain" && selectedNode.meta && (
                  <>
                    <div>
                      <span className="text-slate-500 block text-[10px]">DISCOVERY CHANNEL</span>
                      <span className="text-slate-300">{selectedNode.meta.discovered_by}</span>
                    </div>
                    {selectedNode.meta.metadata?.ip_address && (
                      <div>
                        <span className="text-slate-500 block text-[10px]">RESOLVED IP</span>
                        <span className="text-slate-300">{selectedNode.meta.metadata.ip_address}</span>
                      </div>
                    )}
                  </>
                )}

                {selectedNode.type === "port" && selectedNode.meta && (
                  <>
                    <div>
                      <span className="text-slate-500 block text-[10px]">Exposed Target Domain</span>
                      <span className="text-slate-300">{selectedNode.meta.asset}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px]">Port Rating</span>
                      <span className={[22, 21, 23, 3389].includes(selectedNode.meta.port) ? "text-cyber-danger font-bold" : "text-cyber-warning"}>
                        {[22, 21, 23, 3389].includes(selectedNode.meta.port) ? "CRITICAL RISK EXPOSURE" : "ACTIVE SERVICE PORT"}
                      </span>
                    </div>
                  </>
                )}
              </div>
            ) : (
              <div className="text-slate-500 italic flex items-center space-x-1.5 py-4">
                <HelpCircle className="w-4 h-4 flex-shrink-0" />
                <span>Select any node on the graph to display telemetry.</span>
              </div>
            )}
          </div>

          {selectedNode && (
            <button
              onClick={() => setSelectedNode(null)}
              className="w-full mt-4 bg-dark-bg border border-dark-border text-slate-400 hover:text-white py-1.5 rounded text-[10px] uppercase font-bold transition-colors"
            >
              Clear Telemetry
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
