import React, { useState, useEffect } from 'react';
import { 
  Share2,
  Network,
  Shield, 
  AlertTriangle, 
  Activity, 
  Globe, 
  FileText,
  Upload,
  FileDown,
  ClipboardList,
  Download,
  Search, 
  Terminal, 
  BarChart3, 
  Cpu, 
  Lock, 
  Zap,
  ChevronRight,
  RefreshCw,
  ExternalLink,
  Eye,
  Database,
  Tag,
  Plus,
  Filter,
  Trash2,
  Bell,
  AlertCircle,
  CheckCircle2,
  LayoutGrid,
  Target,
  Crosshair
} from 'lucide-react';
import { 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer, 
  PieChart, 
  Pie, 
  Cell 
} from 'recharts';
import { motion, AnimatePresence } from 'motion/react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { Threat, IOC, Alert, Correlation, LogAnalysisResult, Report, User, MitreTactic, MitreTechnique } from './types';
import { MOCK_THREATS, MOCK_METRICS, MOCK_TIMELINE, MOCK_IOCS, MITRE_TACTICS, MITRE_TECHNIQUES } from './constants';
import { analyzeThreat } from './services/geminiService';
import Login from './components/Login';
import { LogOut } from 'lucide-react';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

const SEVERITY_COLORS = {
  Low: 'text-blue-400 border-blue-400/20 bg-blue-400/10',
  Medium: 'text-yellow-400 border-yellow-400/20 bg-yellow-400/10',
  High: 'text-orange-400 border-orange-400/20 bg-orange-400/10',
  Critical: 'text-red-400 border-red-400/20 bg-red-400/10',
};

const PIE_COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444'];

export default function App() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'analysis' | 'feed' | 'collection' | 'ioc' | 'alerts' | 'ttp' | 'correlations' | 'log-analysis' | 'reports'>('dashboard');
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [threats, setThreats] = useState<Threat[]>(MOCK_THREATS);
  const [iocs, setIocs] = useState<IOC[]>(MOCK_IOCS);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [correlations, setCorrelations] = useState<Correlation[]>([]);
  const [logAnalysisResults, setLogAnalysisResults] = useState<LogAnalysisResult[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);
  const [isAnalyzingLogs, setIsAnalyzingLogs] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isCollecting, setIsCollecting] = useState(false);
  const [collectionResults, setCollectionResults] = useState<any[]>([]);
  const [logInput, setLogInput] = useState('');
  const [showLogModal, setShowLogModal] = useState(false);
  const [showIocModal, setShowIocModal] = useState(false);
  const [newIoc, setNewIoc] = useState({ value: '', type: 'IP' as const, severity: 'Medium' as const, description: '', tags: '' });
  const [iocSearch, setIocSearch] = useState('');
  const [iocFilter, setIocFilter] = useState<'All' | 'IP' | 'Domain' | 'Hash'>('All');
  const [analysisInput, setAnalysisInput] = useState('');
  const [analysisResult, setAnalysisResult] = useState<any>(null);
  const [currentTime, setCurrentTime] = useState(new Date());
  const [toast, setToast] = useState<{ id: string; message: string; severity: string; timestamp: string } | null>(null);

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  // Real-time Suspicious Activity Simulation
  useEffect(() => {
    const simulateSuspiciousActivity = () => {
      const activities = [
        { message: "Multiple failed SSH login attempts from 185.220.101.5", severity: "High" as const, type: "IP", val: "185.220.101.5" },
        { message: "Unusual outbound traffic to update.microsoft-security.com", severity: "Critical" as const, type: "Domain", val: "update.microsoft-security.com" },
        { message: "Suspicious PowerShell execution detected on WS-04", severity: "Medium" as const, type: "System", val: "PowerShell" },
        { message: "New administrative account created on DC-01", severity: "High" as const, type: "System", val: "Admin" },
        { message: "Potential data exfiltration to cloud storage provider", severity: "Medium" as const, type: "Network", val: "Cloud Storage" },
        { message: "Minor policy violation: Unapproved browser extension detected", severity: "Low" as const, type: "System", val: "Extension" },
        { message: "Informational: System update completed on SRV-09", severity: "Low" as const, type: "System", val: "Update" },
      ];

      const randomActivity = activities[Math.floor(Math.random() * activities.length)];
      
      const newAlert: Alert = {
        id: `ALT-${Math.random().toString(36).substr(2, 5).toUpperCase()}`,
        timestamp: new Date().toISOString(),
        message: randomActivity.message,
        severity: randomActivity.severity,
        iocValue: randomActivity.val,
        iocType: randomActivity.type,
        sourceLog: "Real-time monitoring engine"
      };

      setAlerts(prev => [newAlert, ...prev].slice(0, 50));
      setToast({ 
        id: newAlert.id, 
        message: newAlert.message, 
        severity: newAlert.severity, 
        timestamp: newAlert.timestamp 
      });
      
      // Clear toast after 5 seconds
      setTimeout(() => setToast(null), 5000);
    };

    // Initial delay then random intervals
    const timeoutId = setTimeout(() => {
      simulateSuspiciousActivity();
      const intervalId = setInterval(simulateSuspiciousActivity, 45000); // Every 45 seconds
      return () => clearInterval(intervalId);
    }, 10000);

    return () => clearTimeout(timeoutId);
  }, []);

  // Threat Correlation Engine
  useEffect(() => {
    if (alerts.length < 2) return;

    const iocGroups = alerts.reduce((acc, alert) => {
      if (!alert.iocValue) return acc;
      if (!acc[alert.iocValue]) acc[alert.iocValue] = [];
      acc[alert.iocValue].push(alert);
      return acc;
    }, {} as Record<string, Alert[]>);

    const newCorrelations: Correlation[] = [];
    const updatedAlerts = [...alerts];

    Object.entries(iocGroups).forEach(([ioc, group]: [string, Alert[]]) => {
      if (group.length > 1) {
        const correlationId = `CORR-${ioc.replace(/[^a-zA-Z0-9]/g, '').slice(0, 8).toUpperCase()}`;
        
        // Update alerts in this group
        group.forEach(alert => {
          const alertIdx = updatedAlerts.findIndex(a => a.id === alert.id);
          if (alertIdx !== -1) {
            updatedAlerts[alertIdx] = {
              ...updatedAlerts[alertIdx],
              relatedAlertIds: group.filter(a => a.id !== alert.id).map(a => a.id),
              correlationScore: Math.min(group.length * 20, 100)
            };
          }
        });

        // Determine severity based on group
        const severities = group.map(a => a.severity);
        const highestSeverity = severities.includes('Critical') ? 'Critical' : 
                               severities.includes('High') ? 'High' : 
                               severities.includes('Medium') ? 'Medium' : 'Low';

        newCorrelations.push({
          id: correlationId,
          indicator: ioc,
          type: group[0].iocType,
          alerts: group.map(a => a.id),
          severity: highestSeverity,
          lastSeen: group[0].timestamp,
          description: `Correlated activity detected across ${group.length} separate events involving ${ioc}.`
        });
      }
    });

    // Only update if something actually changed to avoid loops
    const hasCorrChanges = JSON.stringify(newCorrelations) !== JSON.stringify(correlations);
    const hasAlertChanges = JSON.stringify(updatedAlerts) !== JSON.stringify(alerts);
    
    if (hasCorrChanges) {
      setCorrelations(newCorrelations);
    }
    if (hasAlertChanges) {
      setAlerts(updatedAlerts);
    }
  }, [alerts, correlations]);

  const handleAnalyzeLogs = async (content: string, fileName: string = 'manual_input.log') => {
    if (!content.trim()) return;
    setIsAnalyzingLogs(true);
    
    // Simulate processing time
    await new Promise(resolve => setTimeout(resolve, 1500));

    const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
    const urlRegex = /https?:\/\/[^\s/$.?#].[^\s]*/g;
    const timestampRegex = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/g;

    const ips = Array.from(new Set(content.match(ipRegex) || []));
    const urls = Array.from(new Set(content.match(urlRegex) || []));
    const timestamps = Array.from(new Set(content.match(timestampRegex) || []));

    const anomalies: LogAnalysisResult['anomalies'] = [];
    
    // Anomaly Detection Logic
    // 1. Brute Force Detection
    const ipCounts: Record<string, number> = {};
    content.split('\n').forEach(line => {
      const match = line.match(ipRegex);
      if (match && (line.toLowerCase().includes('fail') || line.toLowerCase().includes('error'))) {
        match.forEach(ip => {
          ipCounts[ip] = (ipCounts[ip] || 0) + 1;
        });
      }
    });

    Object.entries(ipCounts).forEach(([ip, count]) => {
      if (count > 5) {
        anomalies.push({
          type: 'Brute Force Attempt',
          severity: count > 15 ? 'High' : 'Medium',
          description: `Detected ${count} failed authentication attempts from IP ${ip}.`,
          evidence: content.split('\n').filter(l => l.includes(ip) && (l.toLowerCase().includes('fail') || l.toLowerCase().includes('error'))).slice(0, 3)
        });
      }
    });

    // 2. Known Malicious IOC Match
    ips.forEach(ip => {
      const match = iocs.find(i => i.value === ip && i.severity === 'Critical');
      if (match) {
        anomalies.push({
          type: 'Malicious IP Connection',
          severity: 'Critical',
          description: `Connection detected to known malicious IP ${ip} (${match.tags.join(', ')}).`,
          evidence: content.split('\n').filter(l => l.includes(ip)).slice(0, 2)
        });
      }
    });

    // 3. Beaconing Detection (simplified)
    urls.forEach(url => {
      const occurrences = content.split(url).length - 1;
      if (occurrences > 10) {
        anomalies.push({
          type: 'Potential Beaconing',
          severity: 'Medium',
          description: `High frequency of connections to ${url} (${occurrences} times).`,
          evidence: [`Total occurrences: ${occurrences}`]
        });
      }
    });

    const result: LogAnalysisResult = {
      id: `LOG-${Math.random().toString(36).substr(2, 5).toUpperCase()}`,
      timestamp: new Date().toISOString(),
      fileName,
      entities: { ips, urls, timestamps },
      anomalies,
      summary: anomalies.length > 0 
        ? `Analysis complete. Detected ${anomalies.length} potential security anomalies.`
        : "Analysis complete. No significant anomalies detected in the provided log sample."
    };

    setLogAnalysisResults(prev => [result, ...prev]);
    setIsAnalyzingLogs(false);

    // If critical anomalies found, create alerts
    anomalies.filter(a => a.severity === 'Critical' || a.severity === 'High').forEach(a => {
      const newAlert: Alert = {
        id: `ALT-${Math.random().toString(36).substr(2, 5).toUpperCase()}`,
        timestamp: new Date().toISOString(),
        message: `[Log Analysis] ${a.type}: ${a.description}`,
        severity: a.severity,
        iocValue: a.evidence[0]?.match(ipRegex)?.[0] || '',
        iocType: 'IP',
        sourceLog: a.evidence[0]
      };
      setAlerts(prev => [newAlert, ...prev].slice(0, 50));
    });
  };

  const simulateLogs = () => {
    const logTemplates = [
      "2026-03-19T14:22:01Z [AUTH] Failed login for user admin from 185.220.101.5",
      "2026-03-19T14:22:05Z [AUTH] Failed login for user root from 185.220.101.5",
      "2026-03-19T14:22:10Z [AUTH] Failed login for user support from 185.220.101.5",
      "2026-03-19T14:22:15Z [AUTH] Failed login for user test from 185.220.101.5",
      "2026-03-19T14:22:20Z [AUTH] Failed login for user guest from 185.220.101.5",
      "2026-03-19T14:22:25Z [AUTH] Failed login for user oracle from 185.220.101.5",
      "2026-03-19T14:25:00Z [NET] Outbound connection to http://malicious-c2.com/beacon",
      "2026-03-19T14:25:30Z [NET] Outbound connection to http://malicious-c2.com/beacon",
      "2026-03-19T14:26:00Z [NET] Outbound connection to http://malicious-c2.com/beacon",
      "2026-03-19T14:26:30Z [NET] Outbound connection to http://malicious-c2.com/beacon",
      "2026-03-19T14:27:00Z [NET] Outbound connection to http://malicious-c2.com/beacon",
      "2026-03-19T14:27:30Z [NET] Outbound connection to http://malicious-c2.com/beacon",
      "2026-03-19T14:28:00Z [NET] Outbound connection to http://malicious-c2.com/beacon",
      "2026-03-19T14:28:30Z [NET] Outbound connection to http://malicious-c2.com/beacon",
      "2026-03-19T14:29:00Z [NET] Outbound connection to http://malicious-c2.com/beacon",
      "2026-03-19T14:29:30Z [NET] Outbound connection to http://malicious-c2.com/beacon",
      "2026-03-19T14:30:00Z [NET] Outbound connection to http://malicious-c2.com/beacon",
      "2026-03-19T14:40:00Z [SYS] Suspicious process 'miner.exe' started from /tmp",
      "2026-03-19T14:45:00Z [NET] Connection from 45.33.22.11 (Known Tor Exit Node)"
    ];
    
    const simulatedContent = logTemplates.join('\n');
    handleAnalyzeLogs(simulatedContent, 'simulated_attack.log');
  };

  const generateReport = (type: 'Threat Summary' | 'Incident Report') => {
    setIsGeneratingReport(true);
    setTimeout(() => {
      const newReport: Report = {
        id: `REP-${Math.random().toString(36).substr(2, 5).toUpperCase()}`,
        type,
        timestamp: new Date().toISOString(),
        generatedBy: 'vyshnavitaduka@gmail.com',
        summary: type === 'Threat Summary' 
          ? `Comprehensive summary of ${threats.length} active threats and ${alerts.length} recent alerts.`
          : `Detailed incident report for ${alerts.filter(a => a.severity === 'Critical' || a.severity === 'High').length} high-severity events.`,
        details: type === 'Threat Summary' ? {
          threatCount: threats.length,
          alertCount: alerts.length,
          correlationCount: correlations.length,
          severityBreakdown: {
            Critical: alerts.filter(a => a.severity === 'Critical').length,
            High: alerts.filter(a => a.severity === 'High').length,
            Medium: alerts.filter(a => a.severity === 'Medium').length,
            Low: alerts.filter(a => a.severity === 'Low').length,
          }
        } : {
          incidents: alerts.filter(a => a.severity === 'Critical' || a.severity === 'High').map(a => ({
            id: a.id,
            timestamp: a.timestamp,
            message: a.message,
            severity: a.severity
          }))
        }
      };
      setReports(prev => [newReport, ...prev]);
      setIsGeneratingReport(false);
      setToast({
        id: Date.now().toString(),
        message: `${type} generated successfully.`,
        type: 'success',
        timestamp: new Date().toLocaleTimeString()
      });
    }, 1000);
  };

  const exportToCSV = (report: Report) => {
    let csvContent = "data:text/csv;charset=utf-8,";
    
    if (report.type === 'Threat Summary') {
      csvContent += "Metric,Value\n";
      csvContent += `Threat Count,${report.details.threatCount}\n`;
      csvContent += `Alert Count,${report.details.alertCount}\n`;
      csvContent += `Correlation Count,${report.details.correlationCount}\n`;
      csvContent += `Critical Alerts,${report.details.severityBreakdown.Critical}\n`;
      csvContent += `High Alerts,${report.details.severityBreakdown.High}\n`;
    } else {
      csvContent += "ID,Timestamp,Message,Severity\n";
      report.details.incidents.forEach((inc: any) => {
        csvContent += `${inc.id},${inc.timestamp},"${inc.message}",${inc.severity}\n`;
      });
    }

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `${report.type.replace(' ', '_')}_${report.id}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleAnalyze = async () => {
    if (!analysisInput.trim()) return;
    setIsAnalyzing(true);
    setAnalysisResult(null);
    try {
      const result = await analyzeThreat(analysisInput, 'log');
      setAnalysisResult(result);
    } catch (error) {
      console.error(error);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleCollect = async (source: string) => {
    setIsCollecting(true);
    try {
      const response = await fetch(`/api/threats/collect?source=${source}`);
      const data = await response.json();
      setCollectionResults(prev => [data, ...prev].slice(0, 10));
    } catch (error) {
      console.error("Collection failed:", error);
    } finally {
      setIsCollecting(false);
    }
  };

  const handleParseLogs = () => {
    if (!logInput.trim()) return;
    
    // Simple regex for IPs, Hashes (SHA256), and URLs
    const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
    const hashRegex = /\b[a-fA-F0-9]{64}\b/g;
    const urlRegex = /https?:\/\/[^\s/$.?#].[^\s]*/g;

    const ips = Array.from(new Set(logInput.match(ipRegex) || [])) as string[];
    const hashes = Array.from(new Set(logInput.match(hashRegex) || [])) as string[];
    const urls = Array.from(new Set(logInput.match(urlRegex) || [])) as string[];

    const extracted: string[] = [...ips, ...hashes, ...urls];
    
    // Detection Engine Logic: Match extracted IOCs with stored IOCs
    const newAlerts: Alert[] = [];
    extracted.forEach((val: string) => {
      const match = iocs.find(ioc => ioc.value === val);
      if (match) {
        newAlerts.push({
          id: `ALT-${Math.random().toString(36).substr(2, 5).toUpperCase()}`,
          timestamp: new Date().toISOString(),
          message: `${match.type} ${val} matched with known ${match.tags.join(', ')} source`,
          severity: match.severity,
          iocValue: val,
          iocType: match.type,
          sourceLog: logInput.slice(0, 100) + '...'
        });
      }
    });

    if (newAlerts.length > 0) {
      setAlerts(prev => [...newAlerts, ...prev].slice(0, 50));
      setToast({ 
        id: `toast-${Date.now()}`, 
        message: `${newAlerts.length} threat(s) detected in logs!`, 
        severity: newAlerts[0].severity,
        timestamp: new Date().toLocaleTimeString()
      });
      setTimeout(() => setToast(null), 5000);
      // Optionally switch to alerts tab if matches found
      setActiveTab('alerts');
    }

    if (extracted.length > 0) {
      setCollectionResults(prev => [{
        source: "Log Parser",
        type: "Extracted IOCs",
        data: extracted
      }, ...prev].slice(0, 10));
    }
    
    setLogInput('');
    setShowLogModal(false);
  };

  if (!currentUser) {
    return <Login onLogin={setCurrentUser} />;
  }

  return (
    <div className="min-h-screen bg-[#0a0a0c] text-zinc-300 font-mono selection:bg-emerald-500/30">
      {/* Top Navigation Bar */}
      <header className="h-14 border-b border-zinc-800/50 bg-[#0a0a0c]/80 backdrop-blur-md sticky top-0 z-50 flex items-center justify-between px-6">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-emerald-500/10 border border-emerald-500/20 rounded flex items-center justify-center">
            <Shield className="w-5 h-5 text-emerald-500" />
          </div>
          <h1 className="text-sm font-bold tracking-widest text-zinc-100 uppercase">
            Sentinel <span className="text-emerald-500">Threat Intel</span>
          </h1>
        </div>

        <div className="flex items-center gap-6 text-[10px] uppercase tracking-tighter text-zinc-500">
          <div className="flex items-center gap-2">
            <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
            <span>System Online</span>
          </div>
          <div className="hidden md:block">
            {currentTime.toLocaleTimeString()} UTC
          </div>
          <div className="flex items-center gap-4 pl-6 border-l border-zinc-800/50">
            <div className="text-right">
              <div className="text-[10px] font-bold text-zinc-100 uppercase tracking-widest">{currentUser.username}</div>
              <div className="text-[8px] text-zinc-500 uppercase tracking-widest font-bold">{currentUser.role}</div>
            </div>
            <button 
              onClick={() => setCurrentUser(null)}
              className="p-2 hover:bg-red-500/10 rounded-lg transition-colors text-zinc-500 hover:text-red-500"
              title="Logout"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </header>

      <div className="flex h-[calc(100-3.5rem)]">
        {/* Sidebar */}
        <nav className="w-64 border-r border-zinc-800/50 bg-[#0c0c0e] flex flex-col p-4 gap-2">
          <div className="text-[10px] text-zinc-600 uppercase mb-2 px-2">Navigation</div>
          <NavButton 
            active={activeTab === 'dashboard'} 
            onClick={() => setActiveTab('dashboard')}
            icon={<BarChart3 className="w-4 h-4" />}
            label="Dashboard"
          />
          <NavButton 
            active={activeTab === 'feed'} 
            onClick={() => setActiveTab('feed')}
            icon={<Activity className="w-4 h-4" />}
            label="Threat Feed"
          />
          <NavButton 
            active={activeTab === 'analysis'} 
            onClick={() => setActiveTab('analysis')}
            icon={<Terminal className="w-4 h-4" />}
            label="AI Analysis"
          />
          <NavButton 
            active={activeTab === 'log-analysis'} 
            onClick={() => setActiveTab('log-analysis')}
            icon={<FileText className="w-4 h-4" />}
            label="Log Analysis"
          />
          <NavButton 
            active={activeTab === 'collection'} 
            onClick={() => setActiveTab('collection')}
            icon={<Search className="w-4 h-4" />}
            label="Data Collection"
          />
          <NavButton 
            active={activeTab === 'ioc'} 
            onClick={() => setActiveTab('ioc')}
            icon={<Database className="w-4 h-4" />}
            label="IOC Management"
          />
          <NavButton 
            active={activeTab === 'alerts'} 
            onClick={() => setActiveTab('alerts')}
            icon={<Bell className="w-4 h-4" />}
            label="Detection Alerts"
            badge={alerts.length > 0 ? alerts.length : undefined}
          />
          <NavButton 
            active={activeTab === 'ttp'} 
            onClick={() => setActiveTab('ttp')}
            icon={<Target className="w-4 h-4" />}
            label="TTP Mapping"
          />
          <NavButton 
            active={activeTab === 'correlations'} 
            onClick={() => setActiveTab('correlations')}
            icon={<Network className="w-4 h-4" />}
            label="Threat Correlation"
            badge={correlations.length > 0 ? correlations.length : undefined}
          />
          <NavButton 
            active={activeTab === 'reports'} 
            onClick={() => setActiveTab('reports')}
            icon={<ClipboardList className="w-4 h-4" />}
            label="Reports"
          />
          
          <div className="mt-auto pt-4 border-t border-zinc-800/50">
            <div className="text-[10px] text-zinc-600 uppercase mb-4 px-2">Active Nodes</div>
            <div className="space-y-3 px-2">
              <NodeStatus label="US-EAST-1" status="online" />
              <NodeStatus label="EU-WEST-2" status="online" />
              <NodeStatus label="AP-SOUTH-1" status="warning" />
            </div>
          </div>
        </nav>

        {/* Main Content Area */}
        <main className="flex-1 overflow-y-auto bg-[#0a0a0c] p-6">
          <AnimatePresence mode="wait">
            {activeTab === 'dashboard' && (
              <motion.div 
                key="dashboard"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="space-y-6"
              >
                {/* Stats Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  <StatCard label="Total Threats" value={(1284 + iocs.length).toLocaleString()} trend="+12%" icon={<AlertTriangle className="text-orange-500" />} />
                  <StatCard label="Detection Alerts" value={alerts.length.toString()} trend={alerts.length > 0 ? "NEW" : "0"} icon={<Bell className="text-red-500" />} />
                  <StatCard label="Active IOCs" value={iocs.length.toString()} trend={iocs.length > MOCK_IOCS.length ? `+${iocs.length - MOCK_IOCS.length}` : "STABLE"} icon={<Database className="text-blue-500" />} />
                  <StatCard label="Avg Response" value="14ms" trend="-2ms" icon={<Cpu className="text-blue-500" />} />
                </div>

                {/* Charts Row */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  <div className="lg:col-span-2 bg-[#0c0c0e] border border-zinc-800/50 rounded-lg p-6">
                    <div className="flex items-center justify-between mb-6">
                      <h3 className="text-xs font-bold uppercase tracking-widest text-zinc-400">Threat Activity (24h)</h3>
                      <div className="flex gap-2">
                        <div className="w-2 h-2 rounded-full bg-emerald-500" />
                        <div className="w-2 h-2 rounded-full bg-zinc-800" />
                      </div>
                    </div>
                    <div className="h-[300px] w-full">
                      <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={MOCK_TIMELINE}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#1f1f23" vertical={false} />
                          <XAxis 
                            dataKey="time" 
                            stroke="#52525b" 
                            fontSize={10} 
                            tickLine={false} 
                            axisLine={false} 
                          />
                          <YAxis 
                            stroke="#52525b" 
                            fontSize={10} 
                            tickLine={false} 
                            axisLine={false} 
                          />
                          <Tooltip 
                            contentStyle={{ backgroundColor: '#0c0c0e', border: '1px solid #27272a', borderRadius: '4px' }}
                            itemStyle={{ color: '#10b981' }}
                          />
                          <Line 
                            type="monotone" 
                            dataKey="threats" 
                            stroke="#10b981" 
                            strokeWidth={2} 
                            dot={{ r: 4, fill: '#10b981' }} 
                            activeDot={{ r: 6, strokeWidth: 0 }} 
                          />
                        </LineChart>
                      </ResponsiveContainer>
                    </div>
                  </div>

                  <div className="bg-[#0c0c0e] border border-zinc-800/50 rounded-lg p-6">
                    <h3 className="text-xs font-bold uppercase tracking-widest text-zinc-400 mb-6">Threat Distribution</h3>
                    <div className="h-[300px] w-full">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={MOCK_METRICS}
                            cx="50%"
                            cy="50%"
                            innerRadius={60}
                            outerRadius={80}
                            paddingAngle={5}
                            dataKey="value"
                          >
                            {MOCK_METRICS.map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                            ))}
                          </Pie>
                          <Tooltip 
                            contentStyle={{ backgroundColor: '#0c0c0e', border: '1px solid #27272a', borderRadius: '4px' }}
                          />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                    <div className="mt-4 space-y-2">
                      {MOCK_METRICS.map((m, i) => (
                        <div key={m.name} className="flex items-center justify-between text-[10px]">
                          <div className="flex items-center gap-2">
                            <div className="w-2 h-2 rounded-full" style={{ backgroundColor: PIE_COLORS[i] }} />
                            <span className="text-zinc-500 uppercase">{m.name}</span>
                          </div>
                          <span className="text-zinc-300">{m.value}%</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* New Dashboard Row: Top Malicious IPs & Recent Alerts */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* Top Malicious IPs */}
                  <div className="bg-[#0c0c0e] border border-zinc-800/50 rounded-lg p-6">
                    <div className="flex items-center justify-between mb-6">
                      <h3 className="text-xs font-bold uppercase tracking-widest text-zinc-400">Top Malicious IPs</h3>
                      <div className="text-[10px] text-zinc-600 uppercase">High Risk Sources</div>
                    </div>
                    <div className="space-y-3">
                      {iocs.filter(ioc => ioc.type === 'IP')
                        .sort((a, b) => {
                          const severityMap = { Critical: 4, High: 3, Medium: 2, Low: 1 };
                          return severityMap[b.severity] - severityMap[a.severity];
                        })
                        .slice(0, 5).map((ioc, idx) => (
                        <div key={ioc.id} className="flex items-center justify-between p-3 bg-zinc-900/30 border border-zinc-800/50 rounded hover:border-red-500/30 transition-all group">
                          <div className="flex items-center gap-3">
                            <div className="text-zinc-600 text-[10px]">0{idx + 1}</div>
                            <div className="font-mono text-xs text-zinc-200">{ioc.value}</div>
                          </div>
                          <div className="flex items-center gap-3">
                            <span className={cn("px-1.5 py-0.5 rounded border text-[8px] uppercase font-bold", SEVERITY_COLORS[ioc.severity])}>
                              {ioc.severity}
                            </span>
                            <div className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />
                          </div>
                        </div>
                      ))}
                      {iocs.filter(ioc => ioc.type === 'IP').length === 0 && (
                        <div className="text-center py-8 text-zinc-600 text-[10px] uppercase tracking-widest">No malicious IPs tracked</div>
                      )}
                    </div>
                  </div>

                  {/* Recent Alerts */}
                  <div className="bg-[#0c0c0e] border border-zinc-800/50 rounded-lg p-6">
                    <div className="flex items-center justify-between mb-6">
                      <h3 className="text-xs font-bold uppercase tracking-widest text-zinc-400">Recent Alerts</h3>
                      <button 
                        onClick={() => setActiveTab('alerts')}
                        className="text-[10px] text-emerald-500 hover:underline flex items-center gap-1"
                      >
                        View All <ChevronRight className="w-3 h-3" />
                      </button>
                    </div>
                    <div className="space-y-3">
                      {alerts.slice(0, 5).map((alert) => (
                        <div key={alert.id} className="flex items-start gap-3 p-3 bg-zinc-900/30 border border-zinc-800/50 rounded hover:border-emerald-500/30 transition-all">
                          <div className={cn("mt-1 p-1 rounded", 
                            alert.severity === 'Critical' ? 'text-red-500' : 
                            alert.severity === 'High' ? 'text-orange-500' : 'text-yellow-500'
                          )}>
                            <AlertCircle className="w-3 h-3" />
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-[9px] text-zinc-500 uppercase">{new Date(alert.timestamp).toLocaleTimeString()}</span>
                              <span className={cn("text-[8px] font-bold uppercase", 
                                alert.severity === 'Critical' ? 'text-red-500' : 
                                alert.severity === 'High' ? 'text-orange-500' : 'text-yellow-500'
                              )}>{alert.severity}</span>
                            </div>
                            <p className="text-[11px] text-zinc-300 truncate">{alert.message}</p>
                          </div>
                        </div>
                      ))}
                      {alerts.length === 0 && (
                        <div className="text-center py-8 text-zinc-600 text-[10px] uppercase tracking-widest">No active alerts</div>
                      )}
                    </div>
                  </div>
                </div>

                {/* Top Correlated Indicators */}
                <div className="bg-[#0c0c0e] border border-zinc-800/50 rounded-lg p-6">
                  <div className="flex items-center justify-between mb-6">
                    <div className="flex items-center gap-2">
                      <Network className="w-4 h-4 text-emerald-500" />
                      <h3 className="text-xs font-bold uppercase tracking-widest text-zinc-400">Top Correlated Indicators</h3>
                    </div>
                    <button 
                      onClick={() => setActiveTab('correlations')}
                      className="text-[10px] text-emerald-500 hover:underline flex items-center gap-1"
                    >
                      View Analysis <ChevronRight className="w-3 h-3" />
                    </button>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {correlations.sort((a, b) => b.alerts.length - a.alerts.length).slice(0, 3).map((corr) => (
                      <div key={corr.id} className="p-4 bg-zinc-900/30 border border-zinc-800/50 rounded hover:border-emerald-500/30 transition-all group">
                        <div className="flex items-center justify-between mb-3">
                          <span className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest">{corr.id}</span>
                          <span className={cn("px-1.5 py-0.5 rounded border text-[8px] uppercase font-bold", SEVERITY_COLORS[corr.severity])}>
                            {corr.severity}
                          </span>
                        </div>
                        <div className="font-mono text-xs text-emerald-500 mb-2 truncate">{corr.indicator}</div>
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] text-zinc-600 uppercase tracking-widest">{corr.alerts.length} Linked Events</span>
                          <div className="flex -space-x-2">
                            {corr.alerts.slice(0, 3).map((id, i) => (
                              <div key={id} className="w-5 h-5 rounded-full bg-zinc-800 border border-zinc-700 flex items-center justify-center text-[8px] text-zinc-500 font-bold" style={{ zIndex: 3 - i }}>
                                {id.slice(-2)}
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    ))}
                    {correlations.length === 0 && (
                      <div className="col-span-full h-32 flex flex-col items-center justify-center border border-dashed border-zinc-800 rounded-lg">
                        <Share2 className="w-6 h-6 text-zinc-800 mb-2" />
                        <span className="text-zinc-600 text-[10px] uppercase tracking-widest">No correlations detected yet</span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Recent Threats Table */}
                <div className="bg-[#0c0c0e] border border-zinc-800/50 rounded-lg overflow-hidden">
                  <div className="p-4 border-b border-zinc-800/50 flex items-center justify-between">
                    <h3 className="text-xs font-bold uppercase tracking-widest text-zinc-400">Recent Indicators of Compromise</h3>
                    <button className="text-[10px] text-emerald-500 hover:underline flex items-center gap-1">
                      View All <ChevronRight className="w-3 h-3" />
                    </button>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                      <thead>
                        <tr className="text-[10px] uppercase text-zinc-600 border-b border-zinc-800/50">
                          <th className="p-4 font-medium">ID</th>
                          <th className="p-4 font-medium">Source IP</th>
                          <th className="p-4 font-medium">Type</th>
                          <th className="p-4 font-medium">Severity</th>
                          <th className="p-4 font-medium">Status</th>
                          <th className="p-4 font-medium">Action</th>
                        </tr>
                      </thead>
                      <tbody className="text-xs">
                        {threats.map((threat) => (
                          <tr key={threat.id} className="border-b border-zinc-800/30 hover:bg-zinc-800/10 transition-colors">
                            <td className="p-4 text-zinc-500">{threat.id}</td>
                            <td className="p-4 font-mono text-zinc-300">{threat.source}</td>
                            <td className="p-4">{threat.type}</td>
                            <td className="p-4">
                              <span className={cn("px-2 py-0.5 rounded border text-[10px] uppercase font-bold", SEVERITY_COLORS[threat.severity])}>
                                {threat.severity}
                              </span>
                            </td>
                            <td className="p-4">
                              <div className="flex items-center gap-2">
                                <div className={cn("w-1.5 h-1.5 rounded-full", 
                                  threat.status === 'Active' ? 'bg-red-500 animate-pulse' : 
                                  threat.status === 'Investigating' ? 'bg-yellow-500' : 'bg-emerald-500'
                                )} />
                                {threat.status}
                              </div>
                            </td>
                            <td className="p-4">
                              <button className="p-1.5 hover:bg-zinc-800 rounded transition-colors text-zinc-500 hover:text-zinc-100">
                                <Eye className="w-4 h-4" />
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </motion.div>
            )}

            {activeTab === 'log-analysis' && (
              <motion.div 
                key="log-analysis"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="space-y-6"
              >
                <div className="flex items-center justify-between">
                  <h2 className="text-lg font-bold text-zinc-100 uppercase tracking-widest">Log Analysis Module</h2>
                  <div className="flex items-center gap-3">
                    <button 
                      onClick={simulateLogs}
                      disabled={currentUser.role !== 'Admin'}
                      className="px-4 py-2 bg-zinc-800 hover:bg-zinc-700 disabled:opacity-30 disabled:cursor-not-allowed text-zinc-100 text-[10px] font-bold uppercase tracking-widest rounded-lg transition-all flex items-center gap-2"
                    >
                      <RefreshCw className="w-3 h-3" />
                      Simulate Logs
                    </button>
                    <button 
                      onClick={() => setLogAnalysisResults([])}
                      disabled={currentUser.role !== 'Admin'}
                      className="px-4 py-2 bg-red-500/10 hover:bg-red-500/20 disabled:opacity-30 disabled:cursor-not-allowed text-red-500 text-[10px] font-bold uppercase tracking-widest rounded-lg transition-all flex items-center gap-2"
                    >
                      <Trash2 className="w-3 h-3" />
                      Clear Results
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  <div className="lg:col-span-1 space-y-6">
                    <div className="bg-[#0c0c0e] border border-zinc-800/50 rounded-xl p-6 space-y-4">
                      <div className="flex items-center gap-3 mb-2">
                        <Upload className="w-5 h-5 text-emerald-500" />
                        <h3 className="text-sm font-bold text-zinc-100 uppercase tracking-widest">Ingest Logs</h3>
                      </div>
                      <p className="text-xs text-zinc-500">Paste raw log data below for automated parsing and anomaly detection.</p>
                      <textarea 
                        value={analysisInput}
                        onChange={(e) => setAnalysisInput(e.target.value)}
                        placeholder="Paste logs here (e.g., Apache, Nginx, Syslog)..."
                        className="w-full h-64 bg-[#0a0a0c] border border-zinc-800 rounded-lg p-4 text-xs font-mono focus:outline-none focus:border-emerald-500/50 transition-colors resize-none"
                      />
                      <button 
                        onClick={() => handleAnalyzeLogs(analysisInput)}
                        disabled={isAnalyzingLogs || !analysisInput.trim()}
                        className="w-full py-3 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-[10px] font-bold uppercase tracking-widest rounded-lg transition-all flex items-center justify-center gap-2"
                      >
                        {isAnalyzingLogs ? (
                          <>
                            <RefreshCw className="w-3 h-3 animate-spin" />
                            Analyzing...
                          </>
                        ) : (
                          <>
                            <Search className="w-3 h-3" />
                            Analyze Logs
                          </>
                        )}
                      </button>
                    </div>

                    <div className="bg-[#0c0c0e] border border-zinc-800/50 rounded-xl p-6 space-y-4">
                      <div className="flex items-center gap-3 mb-2">
                        <Activity className="w-5 h-5 text-emerald-500" />
                        <h3 className="text-sm font-bold text-zinc-100 uppercase tracking-widest">Detection Stats</h3>
                      </div>
                      <div className="grid grid-cols-2 gap-4">
                        <div className="p-4 bg-zinc-900/50 rounded-lg border border-zinc-800">
                          <div className="text-[10px] text-zinc-500 uppercase mb-1">Total Logs</div>
                          <div className="text-xl font-bold text-zinc-100">{logAnalysisResults.length}</div>
                        </div>
                        <div className="p-4 bg-zinc-900/50 rounded-lg border border-zinc-800">
                          <div className="text-[10px] text-zinc-500 uppercase mb-1">Anomalies</div>
                          <div className="text-xl font-bold text-red-500">
                            {logAnalysisResults.filter(r => r.anomalies.length > 0).length}
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="lg:col-span-2 space-y-6">
                    <div className="bg-[#0c0c0e] border border-zinc-800/50 rounded-xl overflow-hidden">
                      <div className="p-6 border-b border-zinc-800/50 flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <FileText className="w-5 h-5 text-emerald-500" />
                          <h3 className="text-sm font-bold text-zinc-100 uppercase tracking-widest">Analysis Results</h3>
                        </div>
                      </div>
                      <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse">
                          <thead>
                            <tr className="border-b border-zinc-800/50 bg-zinc-900/30">
                              <th className="p-4 text-[10px] uppercase font-bold text-zinc-500 tracking-widest">Timestamp</th>
                              <th className="p-4 text-[10px] uppercase font-bold text-zinc-500 tracking-widest">Source IP</th>
                              <th className="p-4 text-[10px] uppercase font-bold text-zinc-500 tracking-widest">Target URL</th>
                              <th className="p-4 text-[10px] uppercase font-bold text-zinc-500 tracking-widest">Anomalies</th>
                              <th className="p-4 text-[10px] uppercase font-bold text-zinc-500 tracking-widest">Severity</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-zinc-800/30">
                            {logAnalysisResults.length === 0 ? (
                              <tr>
                                <td colSpan={5} className="p-12 text-center text-zinc-600 text-xs uppercase tracking-widest">
                                  No analysis results to display. Ingest logs to begin.
                                </td>
                              </tr>
                            ) : (
                              logAnalysisResults.map((result, idx) => (
                                <tr key={idx} className="group hover:bg-zinc-800/30 transition-colors">
                                  <td className="p-4 text-[10px] font-mono text-zinc-400">{result.timestamp}</td>
                                  <td className="p-4 text-[10px] font-mono text-zinc-100">{result.ip}</td>
                                  <td className="p-4 text-[10px] font-mono text-zinc-400 truncate max-w-[150px]">{result.url}</td>
                                  <td className="p-4">
                                    <div className="flex flex-wrap gap-1">
                                      {result.anomalies.map((anomaly, aidx) => (
                                        <span key={aidx} className="px-2 py-0.5 bg-red-500/10 text-red-500 border border-red-500/20 rounded text-[9px] uppercase font-bold">
                                          {anomaly}
                                        </span>
                                      ))}
                                      {result.anomalies.length === 0 && (
                                        <span className="text-[10px] text-zinc-600 italic">None</span>
                                      )}
                                    </div>
                                  </td>
                                  <td className="p-4">
                                    <span className={cn(
                                      "px-2 py-0.5 rounded border text-[9px] font-bold uppercase",
                                      result.severity === 'Critical' ? 'bg-red-500/10 text-red-500 border-red-500/20' : 
                                      result.severity === 'High' ? 'bg-orange-500/10 text-orange-500 border-orange-500/20' : 
                                      result.severity === 'Medium' ? 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20' :
                                      'bg-emerald-500/10 text-emerald-500 border-emerald-500/20'
                                    )}>
                                      {result.severity}
                                    </span>
                                  </td>
                                </tr>
                              ))
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </div>
                </div>
              </motion.div>
            )}

            {activeTab === 'reports' && (
              <motion.div 
                key="reports"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="space-y-6"
              >
                <div className="flex items-center justify-between">
                  <h2 className="text-lg font-bold text-zinc-100 uppercase tracking-widest">Reporting System</h2>
                  <div className="flex items-center gap-3">
                    <button 
                      onClick={() => generateReport('Threat Summary')}
                      disabled={isGeneratingReport || currentUser.role !== 'Admin'}
                      className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-30 disabled:cursor-not-allowed text-white text-[10px] font-bold uppercase tracking-widest rounded-lg transition-all flex items-center gap-2"
                    >
                      <BarChart3 className="w-3 h-3" />
                      Generate Threat Summary
                    </button>
                    <button 
                      onClick={() => generateReport('Incident Report')}
                      disabled={isGeneratingReport || currentUser.role !== 'Admin'}
                      className="px-4 py-2 bg-zinc-800 hover:bg-zinc-700 disabled:opacity-30 disabled:cursor-not-allowed text-zinc-100 text-[10px] font-bold uppercase tracking-widest rounded-lg transition-all flex items-center gap-2"
                    >
                      <AlertTriangle className="w-3 h-3" />
                      Generate Incident Report
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-6">
                  {reports.length === 0 ? (
                    <div className="h-96 border border-dashed border-zinc-800 rounded-xl flex flex-col items-center justify-center text-zinc-600">
                      <ClipboardList className="w-12 h-12 mb-4 opacity-20" />
                      <p className="text-xs uppercase tracking-widest">No reports generated yet</p>
                    </div>
                  ) : (
                    reports.map((report) => (
                      <div key={report.id} className="bg-[#0c0c0e] border border-zinc-800/50 rounded-xl overflow-hidden">
                        <div className="p-6 border-b border-zinc-800/50 flex items-center justify-between bg-zinc-900/20">
                          <div className="flex items-center gap-4">
                            <div className="w-10 h-10 rounded-lg bg-zinc-800 flex items-center justify-center">
                              {report.type === 'Threat Summary' ? <BarChart3 className="w-5 h-5 text-emerald-500" /> : <AlertTriangle className="w-5 h-5 text-orange-500" />}
                            </div>
                            <div>
                              <h3 className="text-sm font-bold text-zinc-100 uppercase tracking-widest">{report.type}</h3>
                              <p className="text-[10px] text-zinc-500 font-mono uppercase mt-1">{report.id} • {new Date(report.timestamp).toLocaleString()}</p>
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            <button 
                              onClick={() => exportToCSV(report)}
                              className="p-2 hover:bg-zinc-800 rounded-lg transition-colors text-zinc-400 hover:text-zinc-100 flex items-center gap-2 text-[10px] uppercase font-bold"
                            >
                              <FileDown className="w-4 h-4" />
                              Export CSV
                            </button>
                            <button 
                              onClick={() => window.print()}
                              className="p-2 hover:bg-zinc-800 rounded-lg transition-colors text-zinc-400 hover:text-zinc-100 flex items-center gap-2 text-[10px] uppercase font-bold"
                            >
                              <Download className="w-4 h-4" />
                              Export PDF
                            </button>
                          </div>
                        </div>
                        <div className="p-6 space-y-6">
                          <div>
                            <h4 className="text-[10px] uppercase text-zinc-600 font-bold tracking-widest mb-2">Executive Summary</h4>
                            <p className="text-xs text-zinc-400 leading-relaxed">{report.summary}</p>
                          </div>

                          {report.type === 'Threat Summary' ? (
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                              <div className="p-4 bg-zinc-900/50 rounded-lg border border-zinc-800">
                                <div className="text-[10px] text-zinc-500 uppercase mb-1">Total Threats</div>
                                <div className="text-xl font-bold text-zinc-100">{report.details.threatCount}</div>
                              </div>
                              <div className="p-4 bg-zinc-900/50 rounded-lg border border-zinc-800">
                                <div className="text-[10px] text-zinc-500 uppercase mb-1">Total Alerts</div>
                                <div className="text-xl font-bold text-zinc-100">{report.details.alertCount}</div>
                              </div>
                              <div className="p-4 bg-zinc-900/50 rounded-lg border border-zinc-800">
                                <div className="text-[10px] text-zinc-500 uppercase mb-1">Correlations</div>
                                <div className="text-xl font-bold text-emerald-500">{report.details.correlationCount}</div>
                              </div>
                              <div className="p-4 bg-zinc-900/50 rounded-lg border border-zinc-800">
                                <div className="text-[10px] text-zinc-500 uppercase mb-1">Critical/High</div>
                                <div className="text-xl font-bold text-red-500">
                                  {report.details.severityBreakdown.Critical + report.details.severityBreakdown.High}
                                </div>
                              </div>
                            </div>
                          ) : (
                            <div className="space-y-3">
                              <h4 className="text-[10px] uppercase text-zinc-600 font-bold tracking-widest mb-2">Affected Assets & Events</h4>
                              {report.details.incidents.map((inc: any) => (
                                <div key={inc.id} className="flex items-center justify-between p-3 bg-zinc-900/30 border border-zinc-800/50 rounded-lg">
                                  <div className="flex items-center gap-3">
                                    <span className={cn("w-2 h-2 rounded-full", inc.severity === 'Critical' ? 'bg-red-500' : 'bg-orange-500')} />
                                    <span className="text-xs text-zinc-300">{inc.message}</span>
                                  </div>
                                  <span className="text-[10px] font-mono text-zinc-600">{inc.timestamp}</span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </motion.div>
            )}

            {activeTab === 'analysis' && (
              <motion.div 
                key="analysis"
                initial={{ opacity: 0, scale: 0.98 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.98 }}
                className="max-w-4xl mx-auto space-y-6"
              >
                <div className="bg-[#0c0c0e] border border-zinc-800/50 rounded-lg p-8">
                  <div className="flex items-center gap-4 mb-8">
                    <div className="w-12 h-12 bg-emerald-500/10 border border-emerald-500/20 rounded-lg flex items-center justify-center">
                      <Terminal className="w-6 h-6 text-emerald-500" />
                    </div>
                    <div>
                      <h2 className="text-xl font-bold text-zinc-100">AI Threat Analyst</h2>
                      <p className="text-xs text-zinc-500 uppercase tracking-widest mt-1">Powered by Gemini 3.1 Pro</p>
                    </div>
                  </div>

                  <div className="space-y-4">
                    <label className="text-[10px] uppercase text-zinc-500 font-bold tracking-widest">Input Logs, URLs, or Code Snippets</label>
                    <textarea 
                      value={analysisInput}
                      onChange={(e) => setAnalysisInput(e.target.value)}
                      placeholder="Paste suspicious data here for deep analysis..."
                      className="w-full h-48 bg-[#0a0a0c] border border-zinc-800 rounded-lg p-4 text-sm font-mono focus:outline-none focus:border-emerald-500/50 transition-colors resize-none"
                    />
                    <button 
                      onClick={handleAnalyze}
                      disabled={isAnalyzing || !analysisInput.trim()}
                      className="w-full h-12 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-bold uppercase tracking-widest rounded-lg transition-all flex items-center justify-center gap-2"
                    >
                      {isAnalyzing ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin" />
                          Processing Analysis...
                        </>
                      ) : (
                        <>
                          <Search className="w-4 h-4" />
                          Run Deep Analysis
                        </>
                      )}
                    </button>
                  </div>
                </div>

                {analysisResult && (
                  <motion.div 
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="bg-[#0c0c0e] border border-zinc-800/50 rounded-lg p-8 space-y-6"
                  >
                    <div className="flex items-center justify-between">
                      <h3 className="text-lg font-bold text-zinc-100 uppercase tracking-widest">Analysis Report</h3>
                      <div className={cn("px-4 py-1 rounded border text-xs font-bold uppercase", SEVERITY_COLORS[analysisResult.severity as keyof typeof SEVERITY_COLORS] || SEVERITY_COLORS.Medium)}>
                        {analysisResult.severity} Severity
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div className="space-y-4">
                        <div>
                          <div className="text-[10px] uppercase text-zinc-600 mb-1">Threat Type</div>
                          <div className="text-zinc-200">{analysisResult.threatType}</div>
                        </div>
                        <div>
                          <div className="text-[10px] uppercase text-zinc-600 mb-1">Confidence Score</div>
                          <div className="flex items-center gap-3">
                            <div className="flex-1 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
                              <div 
                                className="h-full bg-emerald-500" 
                                style={{ width: `${analysisResult.confidenceScore}%` }}
                              />
                            </div>
                            <span className="text-emerald-500 font-bold">{analysisResult.confidenceScore}%</span>
                          </div>
                        </div>
                      </div>
                      <div>
                        <div className="text-[10px] uppercase text-zinc-600 mb-1">Description</div>
                        <p className="text-sm leading-relaxed text-zinc-400">{analysisResult.description}</p>
                      </div>
                    </div>

                    <div className="pt-6 border-t border-zinc-800/50">
                      <div className="text-[10px] uppercase text-zinc-600 mb-4">Recommendations</div>
                      <ul className="space-y-3">
                        {analysisResult.recommendations?.map((rec: string, i: number) => (
                          <li key={i} className="flex items-start gap-3 text-sm text-zinc-400">
                            <div className="w-5 h-5 rounded bg-emerald-500/10 flex items-center justify-center flex-shrink-0 mt-0.5">
                              <ChevronRight className="w-3 h-3 text-emerald-500" />
                            </div>
                            {rec}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </motion.div>
                )}
              </motion.div>
            )}

            {activeTab === 'collection' && (
              <motion.div 
                key="collection"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                className="space-y-6"
              >
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  <CollectionSourceCard 
                    title="URLhaus" 
                    description="Malware URL feed"
                    onCollect={() => handleCollect('urlhaus')}
                    loading={isCollecting}
                    icon={<Globe className="text-blue-500" />}
                  />
                  <CollectionSourceCard 
                    title="Blocklist.de" 
                    description="Attack IP feed"
                    onCollect={() => handleCollect('blocklist')}
                    loading={isCollecting}
                    icon={<Activity className="text-red-500" />}
                  />
                  <CollectionSourceCard 
                    title="MalwareBazaar" 
                    description="Recent malware hashes"
                    onCollect={() => handleCollect('malwarebazaar')}
                    loading={isCollecting}
                    icon={<Zap className="text-yellow-500" />}
                  />
                  <CollectionSourceCard 
                    title="Log Parser" 
                    description="Extract IOCs from logs"
                    onCollect={() => setShowLogModal(true)}
                    loading={false}
                    icon={<Terminal className="text-emerald-500" />}
                  />
                </div>

                <div className="space-y-4">
                  <h3 className="text-xs font-bold uppercase tracking-widest text-zinc-500">Collection Results</h3>
                  {collectionResults.length === 0 ? (
                    <div className="h-64 border border-dashed border-zinc-800 rounded-lg flex flex-col items-center justify-center text-zinc-600">
                      <Search className="w-8 h-8 mb-2 opacity-20" />
                      <p className="text-xs uppercase tracking-widest">No data collected yet</p>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {collectionResults.map((result, idx) => (
                        <div key={idx} className="bg-[#0c0c0e] border border-zinc-800/50 rounded-lg overflow-hidden">
                          <div className="p-3 bg-zinc-900/50 border-b border-zinc-800/50 flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <span className="text-[10px] font-bold uppercase text-emerald-500">{result.source}</span>
                              <span className="text-[10px] text-zinc-600 tracking-widest">[{result.type}]</span>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className="text-[10px] text-zinc-600">{result.data.length} items found</span>
                              <button 
                                onClick={() => {
                                  const newIocs = result.data.map((val: string) => ({
                                    id: `IOC-${Math.random().toString(36).substr(2, 5).toUpperCase()}`,
                                    value: val,
                                    type: result.type.includes('IP') ? 'IP' : result.type.includes('URL') || result.type.includes('Domain') ? 'Domain' : 'Hash',
                                    tags: [result.source.toLowerCase()],
                                    addedAt: new Date().toISOString(),
                                    description: `Collected from ${result.source}`,
                                    severity: 'Medium'
                                  }));
                                  setIocs(prev => [...newIocs, ...prev]);
                                  setActiveTab('ioc');
                                }}
                                className="text-[10px] bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 px-2 py-0.5 rounded hover:bg-emerald-500/20 transition-colors"
                              >
                                Import to IOCs
                              </button>
                            </div>
                          </div>
                          <div className="p-4 max-h-64 overflow-y-auto font-mono text-[10px] text-zinc-400 space-y-1">
                            {result.data.map((item: string, i: number) => (
                              <div key={i} className="hover:text-emerald-400 transition-colors cursor-default truncate">
                                {item}
                              </div>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </motion.div>
            )}

            {activeTab === 'ioc' && (
              <motion.div 
                key="ioc"
                initial={{ opacity: 0, scale: 0.98 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.98 }}
                className="space-y-6"
              >
                {/* IOC Controls */}
                <div className="flex flex-col md:flex-row gap-4 items-center justify-between">
                  <div className="flex items-center gap-4 w-full md:w-auto">
                    <div className="relative flex-1 md:w-80">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-600" />
                      <input 
                        type="text"
                        value={iocSearch}
                        onChange={(e) => setIocSearch(e.target.value)}
                        placeholder="Search indicators..."
                        className="w-full bg-[#0c0c0e] border border-zinc-800 rounded-lg pl-10 pr-4 py-2 text-xs focus:outline-none focus:border-emerald-500/50 transition-colors"
                      />
                    </div>
                    <div className="flex items-center gap-2 bg-[#0c0c0e] border border-zinc-800 rounded-lg px-3 py-2">
                      <Filter className="w-3 h-3 text-zinc-600" />
                      <select 
                        value={iocFilter}
                        onChange={(e) => setIocFilter(e.target.value as any)}
                        className="bg-transparent text-[10px] uppercase font-bold text-zinc-400 focus:outline-none cursor-pointer"
                      >
                        <option value="All">All Types</option>
                        <option value="IP">IPs</option>
                        <option value="Domain">Domains</option>
                        <option value="Hash">Hashes</option>
                      </select>
                    </div>
                  </div>
                  <button 
                    onClick={() => setShowIocModal(true)}
                    className="w-full md:w-auto flex items-center justify-center gap-2 px-6 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold uppercase tracking-widest rounded-lg transition-all shadow-lg shadow-emerald-500/10"
                  >
                    <Plus className="w-4 h-4" />
                    Add Indicator
                  </button>
                </div>

                {/* IOC Table */}
                <div className="bg-[#0c0c0e] border border-zinc-800/50 rounded-lg overflow-hidden">
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                      <thead>
                        <tr className="text-[10px] uppercase text-zinc-600 border-b border-zinc-800/50">
                          <th className="p-4 font-medium">Indicator</th>
                          <th className="p-4 font-medium">Type</th>
                          <th className="p-4 font-medium">Tags</th>
                          <th className="p-4 font-medium">Severity</th>
                          <th className="p-4 font-medium">Added At</th>
                          <th className="p-4 font-medium">Action</th>
                        </tr>
                      </thead>
                      <tbody className="text-xs">
                        {iocs
                          .filter(ioc => {
                            const matchesSearch = ioc.value.toLowerCase().includes(iocSearch.toLowerCase()) || 
                                                ioc.tags.some(t => t.toLowerCase().includes(iocSearch.toLowerCase()));
                            const matchesFilter = iocFilter === 'All' || ioc.type === iocFilter;
                            return matchesSearch && matchesFilter;
                          })
                          .map((ioc) => (
                          <tr key={ioc.id} className="border-b border-zinc-800/30 hover:bg-zinc-800/10 transition-colors group">
                            <td className="p-4">
                              <div className="font-mono text-zinc-100">{ioc.value}</div>
                              <div className="text-[10px] text-zinc-600 mt-1">{ioc.description}</div>
                            </td>
                            <td className="p-4">
                              <span className="text-[10px] text-zinc-500 uppercase tracking-widest font-bold">
                                {ioc.type}
                              </span>
                            </td>
                            <td className="p-4">
                              <div className="flex flex-wrap gap-1">
                                {ioc.tags.map(tag => (
                                  <span key={tag} className="flex items-center gap-1 px-1.5 py-0.5 bg-zinc-900 border border-zinc-800 rounded text-[9px] text-zinc-500 uppercase">
                                    <Tag className="w-2 h-2" />
                                    {tag}
                                  </span>
                                ))}
                              </div>
                            </td>
                            <td className="p-4">
                              <span className={cn("px-2 py-0.5 rounded border text-[10px] uppercase font-bold", SEVERITY_COLORS[ioc.severity])}>
                                {ioc.severity}
                              </span>
                            </td>
                            <td className="p-4 text-zinc-500 text-[10px]">
                              {new Date(ioc.addedAt).toLocaleDateString()}
                            </td>
                            <td className="p-4">
                              <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                                <button className="p-1.5 hover:bg-zinc-800 rounded transition-colors text-zinc-500 hover:text-zinc-100">
                                  <Eye className="w-4 h-4" />
                                </button>
                                <button 
                                  onClick={() => setIocs(prev => prev.filter(i => i.id !== ioc.id))}
                                  className="p-1.5 hover:bg-red-500/10 rounded transition-colors text-zinc-500 hover:text-red-500"
                                >
                                  <Trash2 className="w-4 h-4" />
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </motion.div>
            )}

            {activeTab === 'alerts' && (
              <motion.div 
                key="alerts"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="space-y-6"
              >
                <div className="flex items-center justify-between">
                  <h2 className="text-lg font-bold text-zinc-100 uppercase tracking-widest">Detection Engine Alerts</h2>
                  <button 
                    onClick={() => setAlerts([])}
                    className="text-[10px] uppercase font-bold text-zinc-500 hover:text-red-500 transition-colors flex items-center gap-2"
                  >
                    <Trash2 className="w-3 h-3" />
                    Clear All Alerts
                  </button>
                </div>

                {alerts.length === 0 ? (
                  <div className="h-96 border border-dashed border-zinc-800 rounded-xl flex flex-col items-center justify-center text-zinc-600">
                    <CheckCircle2 className="w-12 h-12 mb-4 opacity-20 text-emerald-500" />
                    <p className="text-xs uppercase tracking-widest">No threats detected in current logs</p>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 gap-4">
                    {alerts.map((alert) => {
                      // Simple TTP mapping for alerts
                      const technique = MITRE_TECHNIQUES.find(t => 
                        alert.message.toLowerCase().includes(t.name.toLowerCase()) || 
                        alert.iocType === (t.id === 'T1566' ? 'Domain' : '')
                      );
                      const tactic = technique ? MITRE_TACTICS.find(tac => tac.id === technique.tacticId) : null;

                      return (
                        <motion.div 
                          key={alert.id}
                          initial={{ x: -20, opacity: 0 }}
                          animate={{ x: 0, opacity: 1 }}
                          className={cn(
                            "bg-[#0c0c0e] border rounded-lg p-5 flex items-start gap-6 group hover:border-zinc-700 transition-all",
                            alert.severity === 'Critical' ? 'border-red-500/20' : 
                            alert.severity === 'High' ? 'border-orange-500/20' : 
                            alert.severity === 'Medium' ? 'border-yellow-500/20' : 'border-zinc-800/50'
                          )}
                        >
                          <div className={cn("p-3 rounded-lg border", 
                            alert.severity === 'Critical' ? 'bg-red-500/10 border-red-500/20 text-red-500' : 
                            alert.severity === 'High' ? 'bg-orange-500/10 border-orange-500/20 text-orange-500' : 
                            alert.severity === 'Medium' ? 'bg-yellow-500/10 border-yellow-500/20 text-yellow-500' :
                            'bg-zinc-900 border-zinc-800 text-zinc-500'
                          )}>
                            <AlertTriangle className="w-6 h-6" />
                          </div>
                          <div className="flex-1 space-y-3">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-3">
                                <span className="text-[10px] font-bold uppercase tracking-widest text-zinc-500">
                                  {alert.id} • {alert.timestamp}
                                </span>
                                <span className="text-[10px] text-zinc-700 font-bold">•</span>
                                <span className="text-[10px] text-zinc-500 uppercase tracking-widest font-bold">{alert.type}</span>
                              </div>
                              <span className={cn(
                                "px-2 py-0.5 rounded border text-[9px] font-bold uppercase tracking-widest",
                                alert.severity === 'Critical' ? 'bg-red-500/10 text-red-500 border-red-500/20' : 
                                alert.severity === 'High' ? 'bg-orange-500/10 text-orange-500 border-orange-500/20' : 
                                alert.severity === 'Medium' ? 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20' :
                                'bg-zinc-800 text-zinc-400 border-zinc-700'
                              )}>
                                {alert.severity}
                              </span>
                            </div>
                            <h4 className="text-sm font-bold text-zinc-100 group-hover:text-white transition-colors">{alert.message}</h4>
                            
                            <div className="flex flex-wrap items-center gap-4 text-[10px]">
                              {alert.iocType && (
                                <div className="flex items-center gap-1.5 text-zinc-500 bg-zinc-900/50 px-2 py-1 rounded border border-zinc-800/50">
                                  <Database className="w-3 h-3 text-zinc-600" />
                                  Type: <span className="text-zinc-300 font-bold">{alert.iocType}</span>
                                </div>
                              )}
                              {alert.iocValue && (
                                <div className="flex items-center gap-1.5 text-zinc-500 bg-zinc-900/50 px-2 py-1 rounded border border-zinc-800/50">
                                  <Terminal className="w-3 h-3 text-zinc-600" />
                                  IOC: <span className="text-emerald-500 font-mono">{alert.iocValue}</span>
                                </div>
                              )}
                              {tactic && (
                                <div className="flex items-center gap-1.5 text-emerald-500 bg-emerald-500/5 px-2 py-1 rounded border border-emerald-500/20">
                                  <Target className="w-3 h-3" />
                                  Tactic: <span className="text-emerald-400 uppercase font-bold">{tactic.name}</span>
                                </div>
                              )}
                              {technique && (
                                <div className="flex items-center gap-1.5 text-blue-500 bg-blue-500/5 px-2 py-1 rounded border border-blue-500/20">
                                  <Crosshair className="w-3 h-3" />
                                  Technique: <span className="text-blue-400 uppercase font-bold">{technique.name} ({technique.id})</span>
                                </div>
                              )}
                            </div>

                            {alert.sourceLog && (
                              <div className="mt-3 p-3 bg-black/40 rounded border border-zinc-800/50 font-mono text-[9px] text-zinc-500 italic leading-relaxed">
                                <span className="text-zinc-700 uppercase font-bold tracking-widest mr-2 not-italic">Source Trace:</span>
                                {alert.sourceLog}
                              </div>
                            )}

                            {alert.relatedAlertIds && alert.relatedAlertIds.length > 0 && (
                              <div className="mt-4 pt-4 border-t border-zinc-800/50">
                                <div className="flex items-center gap-2 mb-2">
                                  <Share2 className="w-3 h-3 text-emerald-500" />
                                  <span className="text-[10px] font-bold uppercase tracking-widest text-emerald-500">Correlated Activity Detected</span>
                                  <div className="flex-1 h-[1px] bg-emerald-500/10"></div>
                                  <span className="text-[10px] font-bold text-emerald-500/50">{alert.correlationScore}% Confidence</span>
                                </div>
                                <div className="flex flex-wrap gap-2">
                                  {alert.relatedAlertIds.map(id => (
                                    <span key={id} className="px-2 py-1 rounded bg-emerald-500/5 border border-emerald-500/20 text-[9px] text-emerald-400 font-bold uppercase tracking-tighter">
                                      Linked: {id}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                          <button className="p-2 bg-zinc-900 border border-zinc-800 rounded hover:bg-zinc-800 transition-colors self-start mt-1 group-hover:border-emerald-500/30">
                            <ChevronRight className="w-4 h-4 text-zinc-500 group-hover:text-emerald-500 transition-colors" />
                          </button>
                        </motion.div>
                      );
                    })}
                  </div>
                )}
              </motion.div>
            )}

            {activeTab === 'ttp' && (
              <motion.div 
                key="ttp"
                initial={{ opacity: 0, scale: 0.98 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.98 }}
                className="space-y-6"
              >
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-lg font-bold text-zinc-100 uppercase tracking-widest">MITRE ATT&CK Mapping</h2>
                  <div className="text-[10px] text-zinc-500 uppercase tracking-widest">Observed Attacker Behaviors</div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                  {MITRE_TACTICS.map(tactic => {
                    const observedTechniques = MITRE_TECHNIQUES.filter(tech => tech.tacticId === tactic.id);
                    const isObserved = alerts.some(alert => 
                      observedTechniques.some(tech => alert.message.toLowerCase().includes(tech.name.toLowerCase()))
                    );

                    return (
                      <div key={tactic.id} className={cn(
                        "bg-[#0c0c0e] border p-4 rounded-lg flex flex-col gap-3 transition-all",
                        isObserved ? "border-emerald-500/50 shadow-lg shadow-emerald-500/5" : "border-zinc-800/50 opacity-60"
                      )}>
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] font-bold text-zinc-500 uppercase tracking-tighter">{tactic.id}</span>
                          {isObserved && <span className="px-1.5 py-0.5 bg-emerald-500/10 text-emerald-500 text-[8px] font-bold uppercase rounded border border-emerald-500/20">Observed</span>}
                        </div>
                        <h3 className="text-xs font-bold text-zinc-100 uppercase tracking-widest">{tactic.name}</h3>
                        <p className="text-[10px] text-zinc-500 leading-relaxed">{tactic.description}</p>
                        
                        <div className="mt-2 space-y-2">
                          {observedTechniques.map(tech => {
                            const techObserved = alerts.some(alert => alert.message.toLowerCase().includes(tech.name.toLowerCase()));
                            return (
                              <div key={tech.id} className={cn(
                                "p-2 rounded border text-[10px] flex items-center justify-between group cursor-help",
                                techObserved ? "bg-emerald-500/5 border-emerald-500/20 text-emerald-400" : "bg-zinc-900/50 border-zinc-800/50 text-zinc-600"
                              )} title={tech.description}>
                                <span className="font-bold">{tech.id}</span>
                                <span className="flex-1 ml-2 truncate">{tech.name}</span>
                                {techObserved && <Activity className="w-3 h-3 animate-pulse" />}
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </motion.div>
            )}

            {activeTab === 'correlations' && (
              <motion.div 
                key="correlations"
                initial={{ opacity: 0, scale: 0.98 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.98 }}
                className="space-y-6"
              >
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-emerald-500/10 rounded-lg border border-emerald-500/20">
                      <Network className="w-5 h-5 text-emerald-500" />
                    </div>
                    <div>
                      <h2 className="text-lg font-bold text-zinc-100 uppercase tracking-widest">Threat Correlation Engine</h2>
                      <p className="text-[10px] text-zinc-500 uppercase tracking-widest">Linking related indicators and attack patterns</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-4">
                    <div className="flex items-center gap-2 bg-zinc-900 border border-zinc-800 px-3 py-1.5 rounded-lg">
                      <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                      <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest">Engine Active</span>
                    </div>
                  </div>
                </div>

                {correlations.length === 0 ? (
                  <div className="h-96 flex flex-col items-center justify-center border border-dashed border-zinc-800 rounded-xl bg-zinc-900/20">
                    <Share2 className="w-12 h-12 text-zinc-700 mb-4" />
                    <h3 className="text-sm font-bold text-zinc-500 uppercase tracking-widest">No Correlations Detected</h3>
                    <p className="text-[10px] text-zinc-600 mt-2">The engine is monitoring for shared indicators across alerts.</p>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 gap-6">
                    {correlations.map(corr => (
                      <motion.div 
                        key={corr.id}
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="bg-[#0c0c0e] border border-zinc-800/50 rounded-xl overflow-hidden group hover:border-emerald-500/30 transition-all"
                      >
                        <div className="p-4 border-b border-zinc-800/50 bg-zinc-900/30 flex items-center justify-between">
                          <div className="flex items-center gap-4">
                            <div className={cn(
                              "px-2 py-0.5 rounded border text-[9px] font-bold uppercase tracking-widest",
                              corr.severity === 'Critical' ? 'bg-red-500/10 text-red-500 border-red-500/20' : 
                              corr.severity === 'High' ? 'bg-orange-500/10 text-orange-500 border-orange-500/20' : 
                              corr.severity === 'Medium' ? 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20' :
                              'bg-zinc-800 text-zinc-400 border-zinc-700'
                            )}>
                              {corr.severity} Severity
                            </div>
                            <h3 className="text-sm font-bold text-zinc-100 uppercase tracking-widest">{corr.id}</h3>
                            <span className="text-[10px] text-zinc-600 font-bold uppercase tracking-widest">Indicator: <span className="text-emerald-500 font-mono">{corr.indicator}</span></span>
                          </div>
                          <span className="text-[10px] text-zinc-500 font-bold uppercase tracking-widest">Last Seen: {corr.lastSeen}</span>
                        </div>
                        
                        <div className="p-6 grid grid-cols-1 lg:grid-cols-3 gap-8">
                          <div className="lg:col-span-1 space-y-4">
                            <div>
                              <label className="text-[10px] font-bold text-zinc-600 uppercase tracking-widest mb-2 block">Correlation Summary</label>
                              <p className="text-xs text-zinc-400 leading-relaxed">{corr.description}</p>
                            </div>
                            <div className="p-4 bg-zinc-900/50 border border-zinc-800/50 rounded-lg">
                              <div className="flex items-center justify-between mb-4">
                                <span className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest">Linked Alerts</span>
                                <span className="px-2 py-0.5 bg-emerald-500/10 text-emerald-500 text-[10px] font-bold rounded-full">{corr.alerts.length} Events</span>
                              </div>
                              <div className="space-y-2">
                                {corr.alerts.map(alertId => {
                                  const alert = alerts.find(a => a.id === alertId);
                                  return (
                                    <div key={alertId} className="flex items-center justify-between p-2 bg-black/40 rounded border border-zinc-800/30 text-[10px]">
                                      <span className="text-zinc-500 font-mono">{alertId}</span>
                                      <span className="text-zinc-300 truncate max-w-[150px] ml-2">{alert?.message}</span>
                                    </div>
                                  );
                                })}
                              </div>
                            </div>
                          </div>

                          <div className="lg:col-span-2">
                            <label className="text-[10px] font-bold text-zinc-600 uppercase tracking-widest mb-4 block">Relationship Visualization</label>
                            <div className="h-64 relative bg-black/40 rounded-xl border border-zinc-800/50 overflow-hidden flex items-center justify-center">
                              {/* Central Indicator Node */}
                              <div className="relative z-10 p-4 bg-emerald-500/10 border border-emerald-500/30 rounded-full shadow-2xl shadow-emerald-500/10">
                                <Database className="w-8 h-8 text-emerald-500" />
                                <div className="absolute -bottom-8 left-1/2 -translate-x-1/2 whitespace-nowrap text-[10px] font-bold text-emerald-500 uppercase tracking-widest">
                                  {corr.indicator}
                                </div>
                              </div>

                              {/* Alert Nodes */}
                              {corr.alerts.map((alertId, idx) => {
                                const angle = (idx / corr.alerts.length) * 2 * Math.PI;
                                const x = Math.cos(angle) * 100;
                                const y = Math.sin(angle) * 100;
                                
                                return (
                                  <React.Fragment key={alertId}>
                                    {/* Connection Line */}
                                    <div 
                                      className="absolute h-[1px] bg-gradient-to-r from-emerald-500/50 to-transparent origin-left"
                                      style={{
                                        width: '100px',
                                        left: '50%',
                                        top: '50%',
                                        transform: `rotate(${angle}rad)`
                                      }}
                                    />
                                    {/* Alert Node */}
                                    <motion.div 
                                      initial={{ scale: 0 }}
                                      animate={{ scale: 1 }}
                                      transition={{ delay: idx * 0.1 }}
                                      className="absolute p-2 bg-zinc-900 border border-zinc-800 rounded-lg shadow-xl"
                                      style={{
                                        left: `calc(50% + ${x}px - 16px)`,
                                        top: `calc(50% + ${y}px - 16px)`
                                      }}
                                    >
                                      <AlertTriangle className={cn(
                                        "w-4 h-4",
                                        alerts.find(a => a.id === alertId)?.severity === 'Critical' ? 'text-red-500' :
                                        alerts.find(a => a.id === alertId)?.severity === 'High' ? 'text-orange-500' :
                                        'text-yellow-500'
                                      )} />
                                      <div className="absolute -top-6 left-1/2 -translate-x-1/2 whitespace-nowrap text-[8px] font-bold text-zinc-500 uppercase tracking-tighter">
                                        {alertId}
                                      </div>
                                    </motion.div>
                                  </React.Fragment>
                                );
                              })}
                            </div>
                          </div>
                        </div>
                      </motion.div>
                    ))}
                  </div>
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </main>
      </div>

      {/* Footer Status Bar */}
      <footer className="h-8 border-t border-zinc-800/50 bg-[#0c0c0e] flex items-center justify-between px-6 text-[10px] text-zinc-600 uppercase tracking-widest">
        <div className="flex gap-6">
          <div className="flex items-center gap-2">
            <div className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            <span>DB Connection: Stable</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            <span>API Latency: 42ms</span>
          </div>
        </div>
        <div>Sentinel v2.4.0-build.892</div>
      </footer>

      {/* Log Parser Modal */}
      <AnimatePresence>
        {showLogModal && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-6">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setShowLogModal(false)}
              className="absolute inset-0 bg-black/80 backdrop-blur-sm"
            />
            <motion.div 
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="relative w-full max-w-2xl bg-[#0c0c0e] border border-zinc-800 rounded-xl overflow-hidden shadow-2xl"
            >
              <div className="p-4 border-b border-zinc-800 flex items-center justify-between bg-zinc-900/50">
                <h3 className="text-xs font-bold uppercase tracking-widest text-zinc-100">Manual Log Parser</h3>
                <button onClick={() => setShowLogModal(false)} className="text-zinc-500 hover:text-zinc-100 transition-colors">
                  <RefreshCw className="w-4 h-4 rotate-45" />
                </button>
              </div>
              <div className="p-6 space-y-4">
                <p className="text-[10px] text-zinc-500 uppercase tracking-widest">Paste network or system logs below to extract IPs, URLs, and SHA256 hashes.</p>
                <textarea 
                  value={logInput}
                  onChange={(e) => setLogInput(e.target.value)}
                  placeholder="e.g. 2026-03-19 14:22:01 Connection from 185.220.101.5... Downloaded file with hash 5e3504f4..."
                  className="w-full h-64 bg-[#0a0a0c] border border-zinc-800 rounded-lg p-4 text-xs font-mono focus:outline-none focus:border-emerald-500/50 transition-colors resize-none"
                />
                <div className="flex gap-3">
                  <button 
                    onClick={() => setShowLogModal(false)}
                    className="flex-1 py-3 bg-zinc-900 border border-zinc-800 text-[10px] font-bold uppercase tracking-widest text-zinc-400 hover:bg-zinc-800 transition-all"
                  >
                    Cancel
                  </button>
                  <button 
                    onClick={handleParseLogs}
                    className="flex-[2] py-3 bg-emerald-600 text-white text-[10px] font-bold uppercase tracking-widest hover:bg-emerald-500 transition-all shadow-lg shadow-emerald-500/20"
                  >
                    Extract Indicators
                  </button>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Add IOC Modal */}
      <AnimatePresence>
        {showIocModal && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-6">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setShowIocModal(false)}
              className="absolute inset-0 bg-black/80 backdrop-blur-sm"
            />
            <motion.div 
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="relative w-full max-w-md bg-[#0c0c0e] border border-zinc-800 rounded-xl overflow-hidden shadow-2xl"
            >
              <div className="p-4 border-b border-zinc-800 flex items-center justify-between bg-zinc-900/50">
                <h3 className="text-xs font-bold uppercase tracking-widest text-zinc-100">Add New Indicator</h3>
                <button onClick={() => setShowIocModal(false)} className="text-zinc-500 hover:text-zinc-100 transition-colors">
                  <RefreshCw className="w-4 h-4 rotate-45" />
                </button>
              </div>
              <div className="p-6 space-y-4">
                <div className="space-y-2">
                  <label className="text-[10px] text-zinc-500 uppercase font-bold tracking-widest">Indicator Value</label>
                  <input 
                    type="text"
                    value={newIoc.value}
                    onChange={(e) => setNewIoc(prev => ({ ...prev, value: e.target.value }))}
                    placeholder="e.g. 1.2.3.4 or malicious.com"
                    className="w-full bg-[#0a0a0c] border border-zinc-800 rounded-lg p-3 text-xs font-mono focus:outline-none focus:border-emerald-500/50 transition-colors"
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <label className="text-[10px] text-zinc-500 uppercase font-bold tracking-widest">Type</label>
                    <select 
                      value={newIoc.type}
                      onChange={(e) => setNewIoc(prev => ({ ...prev, type: e.target.value as any }))}
                      className="w-full bg-[#0a0a0c] border border-zinc-800 rounded-lg p-3 text-xs focus:outline-none focus:border-emerald-500/50 transition-colors"
                    >
                      <option value="IP">IP Address</option>
                      <option value="URL">URL</option>
                      <option value="Domain">Domain</option>
                      <option value="Hash">SHA256 Hash</option>
                    </select>
                  </div>
                  <div className="space-y-2">
                    <label className="text-[10px] text-zinc-500 uppercase font-bold tracking-widest">Severity</label>
                    <select 
                      value={newIoc.severity}
                      onChange={(e) => setNewIoc(prev => ({ ...prev, severity: e.target.value as any }))}
                      className="w-full bg-[#0a0a0c] border border-zinc-800 rounded-lg p-3 text-xs focus:outline-none focus:border-emerald-500/50 transition-colors"
                    >
                      <option value="Low">Low</option>
                      <option value="Medium">Medium</option>
                      <option value="High">High</option>
                      <option value="Critical">Critical</option>
                    </select>
                  </div>
                </div>
                <div className="space-y-2">
                  <label className="text-[10px] text-zinc-500 uppercase font-bold tracking-widest">Description</label>
                  <textarea 
                    value={newIoc.description}
                    onChange={(e) => setNewIoc(prev => ({ ...prev, description: e.target.value }))}
                    placeholder="Context about this threat..."
                    className="w-full h-20 bg-[#0a0a0c] border border-zinc-800 rounded-lg p-3 text-xs focus:outline-none focus:border-emerald-500/50 transition-colors resize-none"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-[10px] text-zinc-500 uppercase font-bold tracking-widest">Tags (comma separated)</label>
                  <input 
                    type="text"
                    value={newIoc.tags}
                    onChange={(e) => setNewIoc(prev => ({ ...prev, tags: e.target.value }))}
                    placeholder="e.g. botnet, phishing"
                    className="w-full bg-[#0a0a0c] border border-zinc-800 rounded-lg p-3 text-xs focus:outline-none focus:border-emerald-500/50 transition-colors"
                  />
                </div>
                <div className="flex gap-3 pt-2">
                  <button 
                    onClick={() => setShowIocModal(false)}
                    className="flex-1 py-3 bg-zinc-900 border border-zinc-800 text-[10px] font-bold uppercase tracking-widest text-zinc-400 hover:bg-zinc-800 transition-all"
                  >
                    Cancel
                  </button>
                  <button 
                    onClick={() => {
                      if (!newIoc.value) return;
                      const iocToAdd: IOC = {
                        id: `ioc-${Date.now()}`,
                        value: newIoc.value,
                        type: newIoc.type,
                        severity: newIoc.severity,
                        description: newIoc.description,
                        tags: newIoc.tags.split(',').map(t => t.trim()).filter(Boolean),
                        addedAt: new Date().toISOString()
                      };
                      setIocs(prev => [iocToAdd, ...prev]);
                      setShowIocModal(false);
                      setNewIoc({ value: '', type: 'IP', severity: 'Medium', description: '', tags: '' });
                      
                      setToast({
                        id: `toast-${Date.now()}`,
                        message: `New indicator ${newIoc.value} added to database.`,
                        severity: 'Low',
                        timestamp: new Date().toLocaleTimeString()
                      });
                    }}
                    className="flex-[2] py-3 bg-emerald-600 text-white text-[10px] font-bold uppercase tracking-widest hover:bg-emerald-500 transition-all shadow-lg shadow-emerald-500/20"
                  >
                    Add Indicator
                  </button>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Real-time Alert Toast */}
      <AnimatePresence>
        {toast && (
          <motion.div 
            initial={{ opacity: 0, x: 100, scale: 0.9 }}
            animate={{ opacity: 1, x: 0, scale: 1 }}
            exit={{ opacity: 0, x: 100, scale: 0.9 }}
            className={cn(
              "fixed bottom-12 right-6 z-[200] p-4 rounded-lg border shadow-2xl flex items-start gap-4 max-w-sm",
              toast.severity === 'Critical' ? 'bg-red-950/90 border-red-500/50 text-red-100' :
              toast.severity === 'High' ? 'bg-orange-950/90 border-orange-500/50 text-orange-100' :
              toast.severity === 'Medium' ? 'bg-yellow-950/90 border-yellow-500/50 text-yellow-100' :
              'bg-zinc-900/95 border-zinc-700/50 text-zinc-100'
            )}
          >
            <div className={cn("p-2 rounded-lg", 
              toast.severity === 'Critical' ? 'bg-red-500/20 text-red-500' : 
              toast.severity === 'High' ? 'bg-orange-500/20 text-orange-500' : 
              toast.severity === 'Medium' ? 'bg-yellow-500/20 text-yellow-500' :
              'bg-emerald-500/20 text-emerald-500'
            )}>
              <Bell className="w-5 h-5 animate-bounce" />
            </div>
            <div className="flex-1">
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] font-bold uppercase tracking-widest opacity-60">Security Alert</span>
                <span className={cn("text-[8px] font-bold uppercase px-1.5 py-0.5 rounded border", 
                  toast.severity === 'Critical' ? 'border-red-500/50 text-red-400' : 
                  toast.severity === 'High' ? 'border-orange-500/50 text-orange-400' : 
                  toast.severity === 'Medium' ? 'border-yellow-500/50 text-yellow-400' :
                  'border-zinc-500/50 text-zinc-400'
                )}>{toast.severity}</span>
              </div>
              <p className="text-xs font-medium leading-relaxed">{toast.message}</p>
            </div>
            <button onClick={() => setToast(null)} className="text-zinc-500 hover:text-zinc-100 transition-colors">
              <RefreshCw className="w-3 h-3 rotate-45" />
            </button>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function CollectionSourceCard({ title, description, onCollect, loading, icon, disabled }: { 
  title: string, 
  description: string, 
  onCollect: () => void, 
  loading: boolean, 
  icon: React.ReactNode,
  disabled?: boolean
}) {
  return (
    <div className={cn(
      "bg-[#0c0c0e] border border-zinc-800/50 p-5 rounded-lg flex flex-col gap-4",
      disabled && "opacity-50 grayscale"
    )}>
      <div className="flex items-center gap-3">
        <div className="p-2 bg-zinc-900 rounded border border-zinc-800">
          {icon}
        </div>
        <div>
          <h4 className="text-xs font-bold text-zinc-200">{title}</h4>
          <p className="text-[10px] text-zinc-500">{description}</p>
        </div>
      </div>
      <button 
        onClick={onCollect}
        disabled={loading || disabled}
        className="mt-auto w-full py-2 bg-zinc-900 border border-zinc-800 hover:border-emerald-500/50 hover:bg-zinc-800 text-[10px] font-bold uppercase tracking-widest text-zinc-400 hover:text-emerald-500 transition-all disabled:opacity-50"
      >
        {loading ? 'Collecting...' : 'Start Collection'}
      </button>
    </div>
  );
}

function NavButton({ active, onClick, icon, label, badge }: { active: boolean, onClick: () => void, icon: React.ReactNode, label: string, badge?: number }) {
  return (
    <button 
      onClick={onClick}
      className={cn(
        "flex items-center justify-between w-full px-3 py-2.5 rounded-lg text-xs font-medium transition-all group",
        active 
          ? "bg-emerald-500/10 text-emerald-500 border border-emerald-500/20" 
          : "text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800/50"
      )}
    >
      <div className="flex items-center gap-3">
        <span className={cn("transition-colors", active ? "text-emerald-500" : "text-zinc-600 group-hover:text-zinc-400")}>
          {icon}
        </span>
        {label}
      </div>
      {badge !== undefined && badge > 0 && (
        <span className="px-1.5 py-0.5 bg-red-500 text-white text-[9px] font-bold rounded-full animate-pulse">
          {badge}
        </span>
      )}
    </button>
  );
}

function NodeStatus({ label, status }: { label: string, status: 'online' | 'warning' | 'offline' }) {
  return (
    <div className="flex items-center justify-between group cursor-default">
      <span className="text-[10px] text-zinc-500 group-hover:text-zinc-400 transition-colors">{label}</span>
      <div className={cn(
        "w-1.5 h-1.5 rounded-full",
        status === 'online' ? 'bg-emerald-500' : status === 'warning' ? 'bg-yellow-500' : 'bg-red-500'
      )} />
    </div>
  );
}

function StatCard({ label, value, trend, icon }: { label: string, value: string, trend: string, icon: React.ReactNode }) {
  const isPositive = trend.startsWith('+');
  return (
    <div className="bg-[#0c0c0e] border border-zinc-800/50 p-5 rounded-lg hover:border-zinc-700/50 transition-colors group">
      <div className="flex items-center justify-between mb-3">
        <span className="text-[10px] uppercase font-bold tracking-widest text-zinc-600 group-hover:text-zinc-500 transition-colors">{label}</span>
        <div className="p-2 bg-zinc-900 rounded-lg border border-zinc-800 group-hover:border-zinc-700 transition-colors">
          {icon}
        </div>
      </div>
      <div className="flex items-end justify-between">
        <div className="text-2xl font-bold text-zinc-100">{value}</div>
        <div className={cn("text-[10px] font-bold", isPositive ? 'text-emerald-500' : 'text-red-500')}>
          {trend}
        </div>
      </div>
    </div>
  );
}
