import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { Shield, AlertTriangle, Activity, Globe, Download, Brain, Home, Clock, Target, BarChart3, CheckCircle, Lightbulb } from 'lucide-react';
import { ScanHistoryItem, useScan, VulnerabilityData } from '../contexts/ScanContext';
import { getAnalysisData, getPriorityColor, getRiskColor } from '../utils/analysis';
import { stripHtml } from '../utils/text';
import { useAuth } from '../contexts/AuthContext';
import { jsPDF } from 'jspdf';
import Footer from '../components/Footer';
import { API_BASE_URL } from '../utils/api';

interface AIAdviceItem {
  vulnId: string;
  title: string;
  summary: string;
  impact: string;
  steps: string[];
  analogy: string;
}

const TOKEN_STORAGE_KEY = 'auth_token';

const getPriorityFromSeverity = (severity?: VulnerabilityData['severity']): 'high' | 'medium' | 'low' => {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    default:
      return 'low';
  }
};

const getPriorityLabel = (priority: string) => {
  switch (priority) {
    case 'high':
      return '高';
    case 'medium':
      return '中';
    case 'low':
      return '低';
    default:
      return priority.toUpperCase();
  }
};

const getSeverityLabel = (severity: VulnerabilityData['severity'] | string) => {
  switch (severity) {
    case 'critical':
      return '重大';
    case 'high':
      return '高';
    case 'medium':
      return '中';
    case 'low':
      return '低';
    default:
      return String(severity).toUpperCase();
  }
};

const getFallbackAnalogy = (vulnType: string) => {
  switch (vulnType) {
    case 'SQL Injection':
      return '家の鍵穴に針金を刺されて不正に開けられるようなもの。正しい鍵（パラメータ化クエリ）を使えば安全です。';
    case 'XSS':
      return '手紙に毒を仕込まれ、読んだ人が被害を受けるようなもの。手紙の内容をチェック（サニタイズ）すれば防げます。';
    case 'Directory Traversal':
      return '建物の立入禁止区域に不正侵入されるようなもの。適切な案内（パス検証）があれば防げます。';
    case 'Open Port':
    case 'Weak SSL/TLS':
      return '家の窓や扉が開いたままになっているようなもの。不要な入口は閉めて、必要な入口には強い鍵をかけましょう。';
    default:
      return '';
  }
};

function Dashboard() {
  const { scanResults, loadScanById, loadScanHistory } = useScan();
  const { logout, user } = useAuth();
  const navigate = useNavigate();
  const [activeView, setActiveView] = useState<'dashboard' | 'ai'>('dashboard');
  const [historyScans, setHistoryScans] = useState<ScanHistoryItem[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [loadingScanId, setLoadingScanId] = useState<number | null>(null);
  const [aiAdvice, setAiAdvice] = useState<AIAdviceItem[] | null>(null);
  const [isLoadingAdvice, setIsLoadingAdvice] = useState(false);

  // Scroll to top when component mounts or view changes
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [activeView]);

  useEffect(() => {
    if (scanResults) {
      return;
    }
    let isActive = true;
    setHistoryLoading(true);
    setHistoryError(null);
    loadScanHistory()
      .then((scans) => {
        if (!isActive) {
          return;
        }
        setHistoryScans(scans);
      })
      .catch(() => {
        if (!isActive) {
          return;
        }
        setHistoryError('履歴を取得できませんでした');
      })
      .finally(() => {
        if (!isActive) {
          return;
        }
        setHistoryLoading(false);
      });

    return () => {
      isActive = false;
    };
  }, [scanResults, loadScanHistory]);

  useEffect(() => {
    if (!scanResults) {
      return;
    }

    const token = localStorage.getItem(TOKEN_STORAGE_KEY);
    if (!token) {
      setAiAdvice(null);
      return;
    }

    const vulnerabilities = scanResults.vulnerabilities ?? [];
    if (vulnerabilities.length === 0) {
      setAiAdvice([]);
      return;
    }

    let isActive = true;
    const controller = new AbortController();

    const fetchAdvice = async () => {
      setIsLoadingAdvice(true);
      setAiAdvice(null);
      try {
        const response = await fetch(`${API_BASE_URL}/advice`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({ vulnerabilities }),
          signal: controller.signal,
        });

        if (response.status === 401) {
          if (isActive) {
            logout();
          }
          return;
        }

        if (!response.ok) {
          throw new Error(`AI advice request failed: ${response.status}`);
        }

        const data = await response.json();
        const items = Array.isArray(data?.items) ? data.items : null;
        if (isActive && items) {
          setAiAdvice(items as AIAdviceItem[]);
        }
      } catch {
        if (isActive) {
          setAiAdvice(null);
        }
      } finally {
        if (isActive) {
          setIsLoadingAdvice(false);
        }
      }
    };

    fetchAdvice();

    return () => {
      isActive = false;
      controller.abort();
    };
  }, [scanResults, logout]);

  const handleLoadScan = async (scanId: number) => {
    setLoadingScanId(scanId);
    const ok = await loadScanById(scanId);
    setLoadingScanId(null);
    if (!ok) {
      alert('スキャン結果を取得できませんでした');
    }
  };

  if (!scanResults) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 flex flex-col">
        {/* Header */}
        <header className="bg-white/80 backdrop-blur-sm border-b border-slate-200 sticky top-0 z-10">
          <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
            <div className="flex items-center space-x-6">
              <div className="flex items-center space-x-3">
                <Shield className="w-8 h-8 text-blue-600" />
                <div>
                  <h1 className="text-xl font-bold text-gray-900">SecureGuard</h1>
                  <p className="text-sm text-gray-600">レポートダッシュボード</p>
                </div>
              </div>

              <nav className="flex items-center space-x-4">
                <button
                  onClick={() => navigate('/home')}
                  className="flex items-center space-x-2 px-3 py-2 text-sm text-gray-600 hover:text-blue-600 transition-colors"
                >
                  <Home className="w-4 h-4" />
                  <span>ホーム</span>
                </button>
              </nav>
            </div>

            <div className="flex items-center space-x-4">
              <span className="text-sm text-gray-600">{user?.email}</span>
              <button
                onClick={logout}
                className="text-sm text-gray-600 hover:text-red-600 transition-colors"
              >
                ログアウト
              </button>
            </div>
          </div>
        </header>

        <main className="flex-1 max-w-5xl mx-auto px-4 py-8">
          <div className="bg-white rounded-2xl shadow-lg p-6 border border-slate-200">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-bold text-gray-900">スキャン履歴</h2>
              <button
                onClick={() => navigate('/home')}
                className="text-sm text-blue-600 hover:text-blue-700"
              >
                新しいスキャンへ
              </button>
            </div>

            {historyLoading && (
              <p className="text-sm text-gray-600">履歴を読み込み中...</p>
            )}
            {historyError && (
              <p className="text-sm text-red-600">{historyError}</p>
            )}

            {!historyLoading && historyScans.length === 0 && !historyError && (
              <p className="text-sm text-gray-600">表示できる履歴がありません。</p>
            )}

            {historyScans.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-gray-500 border-b">
                      <th className="py-2 pr-4">対象URL</th>
                      <th className="py-2 pr-4">ステータス</th>
                      <th className="py-2 pr-4">日時</th>
                      <th className="py-2 pr-4">ID</th>
                      <th className="py-2 pr-4">操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    {historyScans.map((scan) => (
                      <tr key={scan.id} className="border-b last:border-b-0">
                        <td className="py-3 pr-4 text-gray-900">
                          {scan.target_url}
                        </td>
                        <td className="py-3 pr-4">
                          <span className="text-gray-700">{scan.status}</span>
                        </td>
                        <td className="py-3 pr-4 text-gray-600">
                          {scan.created_at ? new Date(scan.created_at).toLocaleString('ja-JP') : '-'}
                        </td>
                        <td className="py-3 pr-4 text-gray-600">{scan.id}</td>
                        <td className="py-3 pr-4">
                          <button
                            disabled={scan.status !== 'finished' || loadingScanId === scan.id}
                            onClick={() => handleLoadScan(scan.id)}
                            className={`px-3 py-1 rounded-md text-xs font-medium ${
                              scan.status === 'finished'
                                ? 'bg-blue-600 text-white hover:bg-blue-700'
                                : 'bg-gray-200 text-gray-500 cursor-not-allowed'
                            }`}
                          >
                            {loadingScanId === scan.id ? '読込中...' : '表示'}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </main>
        <Footer />
      </div>
    );
  }

  const severityColors = {
    low: '#10B981',
    medium: '#F59E0B',
    high: '#EF4444',
    critical: '#7C2D12'
  };

  const severityCounts = scanResults.vulnerabilities.reduce((acc, vuln) => {
    acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const chartData = Object.entries(severityCounts).map(([severity, count]) => ({
    severity: getSeverityLabel(severity),
    count,
    color: severityColors[severity as keyof typeof severityColors]
  }));

  const pieData = Object.entries(severityCounts).map(([severity, count]) => ({
    name: getSeverityLabel(severity),
    value: count,
    color: severityColors[severity as keyof typeof severityColors]
  }));

  const generatePDFReport = () => {
    const pdf = new jsPDF();
    const pageWidth = pdf.internal.pageSize.width;
    
    // Title
    pdf.setFontSize(20);
    pdf.text('SecureGuard 脆弱性レポート', pageWidth / 2, 20, { align: 'center' });
    
    // Scan info
    pdf.setFontSize(12);
    pdf.text(`対象URL: ${scanResults.targetUrl}`, 20, 40);
    pdf.text(`スキャン実行日時: ${new Date(scanResults.timestamp).toLocaleString('ja-JP')}`, 20, 50);
    pdf.text(`リスクスコア: ${scanResults.riskScore}/100`, 20, 60);
    
    // Summary
    pdf.setFontSize(14);
    pdf.text('サマリー', 20, 80);
    pdf.setFontSize(10);
    pdf.text(`検出された脆弱性: ${scanResults.vulnerabilities.length}件`, 20, 90);
    pdf.text(`開放ポート: ${scanResults.openPorts.join(', ')}`, 20, 100);
    
    // Vulnerabilities
    pdf.setFontSize(14);
    pdf.text('検出された脆弱性', 20, 120);
    
    let yPosition = 130;
    scanResults.vulnerabilities.forEach((vuln, index) => {
      if (yPosition > 250) {
        pdf.addPage();
        yPosition = 20;
      }
      
      pdf.setFontSize(12);
      pdf.text(`${index + 1}. ${vuln.type} [${vuln.severity.toUpperCase()}]`, 20, yPosition);
      pdf.setFontSize(10);
      pdf.text(`ポート: ${vuln.port}`, 25, yPosition + 10);
      
      const descLines = pdf.splitTextToSize(vuln.description, pageWidth - 50);
      pdf.text(descLines, 25, yPosition + 20);
      
      yPosition += 40 + (descLines.length * 4);
    });
    
    pdf.save(`secureguard-report-${new Date().toISOString().split('T')[0]}.pdf`);
  };

  const analysisData = getAnalysisData(scanResults);
  const hasAiAdvice = !isLoadingAdvice && (aiAdvice?.length ?? 0) > 0;
  const aiContentState = hasAiAdvice ? 'ready' : (isLoadingAdvice ? 'loading' : 'fallback');
  const aiPlaceholderText = aiContentState === 'loading'
    ? 'AI解析中です。しばらくお待ちください。'
    : 'AI解析結果を取得できませんでした。';
  const aiMissingSummaryText = 'AI解析の要約がありません。';
  const aiMissingImpactText = 'AI解析の影響情報がありません。';
  const aiMissingStepsText = 'AI解析の改善案がありません。';
  const overallRiskLabel = analysisData.overallRisk === 'high'
    ? '高'
    : analysisData.overallRisk === 'medium'
      ? '中'
      : '低';
  const vulnById = new Map(scanResults.vulnerabilities.map((vuln) => [vuln.id, vuln]));
  const adviceById = new Map(
    (aiAdvice ?? [])
      .filter((item) => item && typeof item.vulnId === 'string')
      .map((item) => [item.vulnId, item] as const),
  );
  const recommendations = hasAiAdvice
    ? aiAdvice!.map((item) => {
        const vuln = vulnById.get(item.vulnId);
        const description = item.summary
          ? stripHtml(item.summary)
          : aiMissingSummaryText;
        const impact = item.impact
          ? stripHtml(item.impact)
          : aiMissingImpactText;
        const title = item.title ? stripHtml(item.title) : '脆弱性の改善案';
        return {
          priority: getPriorityFromSeverity(vuln?.severity),
          title,
          description,
          impact,
        };
      })
    : analysisData.recommendations;
  const mostCritical = analysisData.mostCritical;
  const mostCriticalAdvice = mostCritical ? adviceById.get(mostCritical.id) : undefined;
  const mostCriticalTitle = mostCritical
    ? (mostCriticalAdvice?.title ? stripHtml(mostCriticalAdvice.title) : hasAiAdvice ? '脆弱性項目' : 'AI解析中')
    : '';
  const mostCriticalSummary = mostCritical
    ? (hasAiAdvice
        ? (mostCriticalAdvice?.summary ? stripHtml(mostCriticalAdvice.summary) : aiMissingSummaryText)
        : aiPlaceholderText)
    : '';
  const mostCriticalImpact = mostCritical
    ? (hasAiAdvice
        ? (mostCriticalAdvice?.impact ? stripHtml(mostCriticalAdvice.impact) : aiMissingImpactText)
        : '')
    : '';

  const authStatus = scanResults.authStatus;
  const authStatusLabel = authStatus?.success === true
    ? '認証: 成功'
    : authStatus?.success === false
      ? '認証: 失敗'
      : '認証: 未検証';
  const authStatusClass = authStatus?.success === true
    ? 'border-emerald-200 bg-emerald-50 text-emerald-900'
    : authStatus?.success === false
      ? 'border-amber-200 bg-amber-50 text-amber-900'
      : 'border-slate-200 bg-slate-50 text-slate-700';

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 flex flex-col">
      {/* Header */}
      <header className="bg-white/80 backdrop-blur-sm border-b border-slate-200 sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center space-x-6">
            <div className="flex items-center space-x-3">
              <Shield className="w-8 h-8 text-blue-600" />
              <div>
                <h1 className="text-xl font-bold text-gray-900">SecureGuard</h1>
                <p className="text-sm text-gray-600">レポートダッシュボード</p>
              </div>
            </div>
            
            <nav className="flex items-center space-x-4">
              <button
                onClick={() => navigate('/home')}
                className="flex items-center space-x-2 px-3 py-2 text-sm text-gray-600 hover:text-blue-600 transition-colors"
              >
                <Home className="w-4 h-4" />
                <span>ホーム</span>
              </button>
            </nav>
          </div>
          
          <div className="flex items-center space-x-4">
            <span className="text-sm text-gray-600">{user?.email}</span>
            <button
              onClick={logout}
              className="text-sm text-gray-600 hover:text-red-600 transition-colors"
            >
              ログアウト
            </button>
          </div>
        </div>
      </header>

      <main className="flex-1 max-w-7xl mx-auto px-4 py-8">
        {/* View Toggle */}
        <div className="flex items-center justify-center mb-8">
          <div className="bg-white rounded-xl shadow-lg p-2 border border-slate-200">
            <div className="flex space-x-2">
              <button
                onClick={() => setActiveView('dashboard')}
                className={`flex items-center space-x-2 px-6 py-3 rounded-lg font-medium transition-all ${
                  activeView === 'dashboard'
                    ? 'bg-blue-600 text-white shadow-md'
                    : 'text-gray-600 hover:text-blue-600 hover:bg-blue-50'
                }`}
              >
                <BarChart3 className="w-5 h-5" />
                <span>ダッシュボード</span>
              </button>
              <button
                onClick={() => setActiveView('ai')}
                className={`flex items-center space-x-2 px-6 py-3 rounded-lg font-medium transition-all ${
                  activeView === 'ai'
                    ? 'bg-purple-600 text-white shadow-md'
                    : 'text-gray-600 hover:text-purple-600 hover:bg-purple-50'
                }`}
              >
                <Brain className="w-5 h-5" />
                <span>AI解析</span>
              </button>
            </div>
          </div>
        </div>

        {activeView === 'dashboard' ? (
          <div key="dashboard-content">
            {authStatus?.used && (
              <div className={`mb-6 flex items-start space-x-3 rounded-xl border px-4 py-3 ${authStatusClass}`}>
                <AlertTriangle className="mt-0.5 h-5 w-5" />
                <div className="text-sm">
                  <p className="font-semibold">{authStatusLabel}</p>
                  <p className="opacity-80">
                    {authStatus.message || '認証結果の詳細はログイン成功判定の設定に依存します。'}
                  </p>
                </div>
              </div>
            )}
            {/* Scan Info */}
            <div className="bg-white rounded-2xl shadow-lg p-6 mb-8 border border-slate-200">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-2xl font-bold text-gray-900">スキャン結果</h2>
                <button
                  onClick={generatePDFReport}
                  className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                >
                  <Download className="w-4 h-4" />
                  <span>PDFダウンロード</span>
                </button>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <div className="flex items-center space-x-3">
                  <Target className="w-5 h-5 text-blue-600" />
                  <div>
                    <p className="text-sm text-gray-600">対象URL</p>
                    <p className="font-semibold text-gray-900">{scanResults.targetUrl}</p>
                  </div>
                </div>
                
                <div className="flex items-center space-x-3">
                  <Clock className="w-5 h-5 text-green-600" />
                  <div>
                    <p className="text-sm text-gray-600">スキャン実行日時</p>
                    <p className="font-semibold text-gray-900">
                      {new Date(scanResults.timestamp).toLocaleString('ja-JP')}
                    </p>
                  </div>
                </div>
                
                <div className="flex items-center space-x-3">
                  <Activity className="w-5 h-5 text-purple-600" />
                  <div>
                    <p className="text-sm text-gray-600">スキャンタイプ</p>
                    <p className="font-semibold text-gray-900">
                      {scanResults.scanType === 'bulk' ? '一括スキャン' : '詳細スキャン'}
                    </p>
                  </div>
                </div>
                
                <div className="flex items-center space-x-3">
                  <Shield className="w-5 h-5 text-orange-600" />
                  <div>
                    <p className="text-sm text-gray-600">リスクスコア</p>
                    <p className="font-semibold text-gray-900">{scanResults.riskScore}/100</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Key Metrics */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
              <div className="bg-gradient-to-r from-red-500 to-red-600 rounded-2xl p-6 text-white">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-red-100 text-sm">脆弱性検出数</p>
                    <p className="text-3xl font-bold">{scanResults.vulnerabilities.length}</p>
                  </div>
                  <AlertTriangle className="w-8 h-8 text-red-200" />
                </div>
              </div>
              
              <div className="bg-gradient-to-r from-orange-500 to-orange-600 rounded-2xl p-6 text-white">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-orange-100 text-sm">開放ポート数</p>
                    <p className="text-3xl font-bold">{scanResults.openPorts.length}</p>
                  </div>
                  <Globe className="w-8 h-8 text-orange-200" />
                </div>
              </div>
              
              <div className="bg-gradient-to-r from-purple-500 to-purple-600 rounded-2xl p-6 text-white">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-purple-100 text-sm">中以上のリスク</p>
                    <p className="text-3xl font-bold">
                      {scanResults.vulnerabilities.filter(v => ['medium', 'high', 'critical'].includes(v.severity)).length}
                    </p>
                  </div>
                  <Shield className="w-8 h-8 text-purple-200" />
                </div>
              </div>
            </div>

            {/* Charts */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
              <div className="bg-white rounded-2xl shadow-lg p-6 border border-slate-200">
                <h3 className="text-lg font-semibold text-gray-900 mb-4">脆弱性の重要度別分布</h3>
                <ResponsiveContainer width="100%" height={250}>
                  <BarChart data={chartData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="severity" />
                    <YAxis />
                    <Tooltip />
                    <Bar dataKey="count" fill="#3B82F6" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
              
              <div className="bg-white rounded-2xl shadow-lg p-6 border border-slate-200">
                <h3 className="text-lg font-semibold text-gray-900 mb-4">リスク分布</h3>
                <ResponsiveContainer width="100%" height={250}>
                  <PieChart>
                    <Pie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      outerRadius={80}
                      dataKey="value"
                      label={({ name, value }) => `${name}: ${value}`}
                    >
                      {pieData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Open Ports */}
            <div className="bg-white rounded-2xl shadow-lg p-6 mb-8 border border-slate-200">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">開放ポート</h3>
              <div className="flex flex-wrap gap-3">
                {scanResults.openPorts.map(port => (
                  <span
                    key={port}
                    className="px-3 py-1 bg-blue-100 text-blue-800 rounded-full text-sm font-medium"
                  >
                    ポート {port}
                  </span>
                ))}
              </div>
            </div>

            {/* Vulnerabilities List */}
            <div className="bg-white rounded-2xl shadow-lg p-6 border border-slate-200">
              <h3 className="text-lg font-semibold text-gray-900 mb-6">検出された脆弱性</h3>
              <div className="space-y-4">
                {scanResults.vulnerabilities.map((vuln) => {
                  const advice = adviceById.get(vuln.id);
                  const title = advice?.title
                    ? stripHtml(advice.title)
                    : hasAiAdvice
                      ? '脆弱性項目'
                      : 'AI解析中';
                  const description = hasAiAdvice
                    ? (advice?.summary ? stripHtml(advice.summary) : aiMissingSummaryText)
                    : aiPlaceholderText;
                  const impact = hasAiAdvice
                    ? (advice?.impact ? stripHtml(advice.impact) : aiMissingImpactText)
                    : aiPlaceholderText;
                  const steps = hasAiAdvice && Array.isArray(advice?.steps)
                    ? advice.steps.map((step) => stripHtml(step)).filter((step) => step.length > 0)
                    : [];
                  const solutionText = hasAiAdvice
                    ? (steps.length > 0 ? steps.join(' / ') : aiMissingStepsText)
                    : aiPlaceholderText;

                  return (
                    <div key={vuln.id} className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow">
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex items-center space-x-3">
                          <h4 className="text-lg font-semibold text-gray-900">{title}</h4>
                          <span
                            className="px-2 py-1 rounded-full text-xs font-medium text-white"
                            style={{ backgroundColor: severityColors[vuln.severity] }}
                          >
                            {getSeverityLabel(vuln.severity)}
                          </span>
                          {vuln.cveId && (
                            <span className="px-2 py-1 bg-gray-100 text-gray-800 rounded text-xs">
                              {vuln.cveId}
                            </span>
                          )}
                        </div>
                        <span className="text-sm text-gray-600">ポート {vuln.port}</span>
                      </div>

                      <p className="text-gray-700 mb-3">{description}</p>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                        <div>
                          <p className="font-medium text-gray-900 mb-1">影響:</p>
                          <p className="text-gray-600">{impact}</p>
                        </div>
                        <div>
                          <p className="font-medium text-gray-900 mb-1">対策:</p>
                          <p className="text-gray-600">{solutionText}</p>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        ) : (
          <div key="ai-content">
            {/* AI Analysis View */}
            <div className="bg-gradient-to-r from-purple-600 to-blue-600 rounded-2xl shadow-xl p-8 mb-8 text-white">
              <div className="flex items-center space-x-4 mb-6">
                <Brain className="w-12 h-12" />
                <div>
                  <h2 className="text-3xl font-bold">AI 分析結果</h2>
                  <p className="text-purple-100">高度なアルゴリズムによる脆弱性解析</p>
                </div>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="bg-white/10 backdrop-blur-sm rounded-lg p-4">
                  <div className="text-2xl font-bold">{scanResults.riskScore}/100</div>
                  <div className="text-purple-100">総合リスクスコア</div>
                </div>
                <div className="bg-white/10 backdrop-blur-sm rounded-lg p-4">
                  <div className="text-2xl font-bold">{analysisData.criticalIssues}</div>
                  <div className="text-purple-100">高リスク脆弱性</div>
                </div>
                <div className="bg-white/10 backdrop-blur-sm rounded-lg p-4">
                  <div className="text-2xl font-bold">{analysisData.mediumIssues}</div>
                  <div className="text-purple-100">中リスク脆弱性</div>
                </div>
              </div>
            </div>

            {/* Risk Assessment */}
            <div className="bg-white rounded-2xl shadow-lg p-8 mb-8 border border-slate-200">
              <h3 className="text-2xl font-bold text-gray-900 mb-6">リスク評価</h3>
              
              <div className={`p-6 rounded-lg border-2 ${getRiskColor(analysisData.overallRisk)} mb-6`}>
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-lg font-semibold mb-2">総合リスクレベル</h4>
                    <p className="text-sm">
                      {analysisData.overallRisk === 'high' && '緊急対応が必要です'}
                      {analysisData.overallRisk === 'medium' && '早期対応を推奨します'}
                      {analysisData.overallRisk === 'low' && '継続的な監視が必要です'}
                    </p>
                  </div>
                  <div className="text-2xl font-bold uppercase">
                    {overallRiskLabel}
                  </div>
                </div>
              </div>

              {analysisData.mostCritical && (
                <div className="border-l-4 border-red-500 bg-red-50 p-6 rounded-r-lg">
                  <h4 className="text-lg font-semibold text-red-900 mb-2">最優先対応項目</h4>
                  <div className="text-red-800">
                    <p className="font-medium">{mostCriticalTitle}</p>
                    <p className="text-sm mt-1">{mostCriticalSummary}</p>
                    {mostCriticalImpact && (
                      <p className="text-sm mt-2"><strong>影響:</strong> {mostCriticalImpact}</p>
                    )}
                    <div className="mt-3 flex items-center space-x-2">
                      <AlertTriangle className="w-4 h-4" />
                      <span className="text-sm font-medium">ポート {analysisData.mostCritical.port} で検出</span>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* AI Recommendations */}
            <div className="bg-white rounded-2xl shadow-lg p-8 mb-8 border border-slate-200">
              <div className="flex items-center space-x-3 mb-6">
                <Lightbulb className="w-6 h-6 text-yellow-600" />
                <h3 className="text-2xl font-bold text-gray-900">AI 推奨改善策</h3>
              </div>
              
              <div className="space-y-6">
                {recommendations.map((rec, index) => (
                  <div key={index} className="border border-gray-200 rounded-lg p-6 hover:shadow-md transition-shadow">
                    <div className="flex items-start space-x-4">
                      <div className={`w-3 h-3 rounded-full ${getPriorityColor(rec.priority)} mt-2`}></div>
                      <div className="flex-1">
                        <div className="flex items-start justify-between mb-3">
                          <h4 className="text-lg font-semibold text-gray-900">{rec.title}</h4>
                          <span className={`px-2 py-1 rounded-full text-xs font-medium text-white ${getPriorityColor(rec.priority)}`}>
                            {getPriorityLabel(rec.priority)}
                          </span>
                        </div>
                        <p className="text-gray-700 mb-3">{rec.description}</p>
                        <div className="flex items-center space-x-2 text-sm text-green-600">
                          <CheckCircle className="w-4 h-4" />
                          <span className="font-medium">期待効果:</span>
                          <span>{rec.impact}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Detailed Analysis */}
            <div className="bg-white rounded-2xl shadow-lg p-8 border border-slate-200">
              <h3 className="text-2xl font-bold text-gray-900 mb-6">詳細分析と解説</h3>
              
              <div className="space-y-8">
                {scanResults.vulnerabilities.slice(0, 3).map((vuln, index) => {
                  const advice = adviceById.get(vuln.id);
                  const title = advice?.title
                    ? stripHtml(advice.title)
                    : hasAiAdvice
                      ? '脆弱性項目'
                      : 'AI解析中';
                  const summary = hasAiAdvice
                    ? (advice?.summary ? stripHtml(advice.summary) : aiMissingSummaryText)
                    : aiPlaceholderText;
                  const impact = hasAiAdvice
                    ? (advice?.impact ? stripHtml(advice.impact) : aiMissingImpactText)
                    : aiPlaceholderText;
                  const steps = hasAiAdvice && Array.isArray(advice?.steps)
                    ? advice.steps.map((step) => stripHtml(step)).filter((step) => step.length > 0)
                    : [];
                  const analogyFromAi = hasAiAdvice && advice?.analogy ? stripHtml(advice.analogy) : '';
                  const analogy = hasAiAdvice ? (analogyFromAi || getFallbackAnalogy(vuln.type)) : '';

                  return (
                    <div key={vuln.id} className="border-b border-gray-200 pb-8 last:border-b-0 last:pb-0">
                    <div className="flex items-center space-x-3 mb-4">
                      <span className="flex items-center justify-center w-8 h-8 bg-blue-100 text-blue-600 rounded-full font-semibold text-sm">
                        {index + 1}
                      </span>
                      <h4 className="text-xl font-semibold text-gray-900">{title}</h4>
                    </div>
                    
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                      <div>
                        <h5 className="font-semibold text-gray-900 mb-3">技術的解説</h5>
                        <p className="text-gray-700 mb-4">{summary}</p>
                        <p className="text-gray-700"><strong>影響:</strong> {impact}</p>
                      </div>
                      
                      <div>
                        <h5 className="font-semibold text-gray-900 mb-3">改善案</h5>
                        {steps.length > 0 ? (
                          <ul className="text-gray-700 mb-4 list-disc list-inside space-y-1">
                            {steps.map((step, stepIndex) => (
                              <li key={stepIndex}>{step}</li>
                            ))}
                          </ul>
                        ) : (
                          <p className="text-gray-700 mb-4">
                            {hasAiAdvice ? aiMissingStepsText : aiPlaceholderText}
                          </p>
                        )}
                        
                        {scanResults.scanType === 'bulk' && analogy && (
                          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                            <h6 className="font-medium text-blue-900 mb-2">💡 わかりやすい例え</h6>
                            <p className="text-blue-800 text-sm">
                              {analogy}
                            </p>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}
      </main>

      <Footer />
    </div>
  );
}

export default Dashboard;
