import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { Shield, AlertTriangle, Activity, Globe, Download, Brain, Home, Clock, Target, BarChart3, CheckCircle, Lightbulb } from 'lucide-react';
import { useScan } from '../contexts/ScanContext';
import { useAuth } from '../contexts/AuthContext';
import { jsPDF } from 'jspdf';
import Footer from '../components/Footer';

function Dashboard() {
  const { scanResults } = useScan();
  const { logout, user } = useAuth();
  const navigate = useNavigate();
  const [activeView, setActiveView] = useState<'dashboard' | 'ai'>('dashboard');

  // Scroll to top when component mounts or view changes
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [activeView]);

  if (!scanResults) {
    navigate('/home');
    return null;
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
    severity: severity.toUpperCase(),
    count,
    color: severityColors[severity as keyof typeof severityColors]
  }));

  const pieData = Object.entries(severityCounts).map(([severity, count]) => ({
    name: severity.toUpperCase(),
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

  const getAnalysisData = () => {
    const highRiskVulns = scanResults.vulnerabilities.filter(v => 
      v.severity === 'critical' || v.severity === 'high'
    );
    
    const mediumRiskVulns = scanResults.vulnerabilities.filter(v => 
      v.severity === 'medium'
    );

    return {
      overallRisk: scanResults.riskScore > 70 ? 'high' : scanResults.riskScore > 40 ? 'medium' : 'low',
      criticalIssues: highRiskVulns.length,
      mediumIssues: mediumRiskVulns.length,
      mostCritical: highRiskVulns[0] || mediumRiskVulns[0],
      recommendations: [
        {
          priority: 'high',
          title: 'SQL インジェクション対策の実装',
          description: 'パラメータ化クエリの使用と入力値検証の徹底',
          impact: 'データベースへの不正アクセスを防止'
        },
        {
          priority: 'high',
          title: 'XSS 対策の強化',
          description: 'CSP ヘッダーの設定と出力値のエスケープ処理',
          impact: 'クロスサイトスクリプティング攻撃を防止'
        },
        {
          priority: 'medium',
          title: 'SSL/TLS 設定の最適化',
          description: '弱い暗号化スイートの無効化と最新プロトコルの採用',
          impact: '通信の暗号化強度を向上'
        }
      ]
    };
  };

  const analysisData = getAnalysisData();

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'high': return 'text-red-600 bg-red-50 border-red-200';
      case 'medium': return 'text-orange-600 bg-orange-50 border-orange-200';
      case 'low': return 'text-green-600 bg-green-50 border-green-200';
      default: return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'high': return 'bg-red-500';
      case 'medium': return 'bg-orange-500';
      case 'low': return 'bg-yellow-500';
      default: return 'bg-gray-500';
    }
  };

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
                    <p className="text-purple-100 text-sm">Medium以上のリスク</p>
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
                {scanResults.vulnerabilities.map(vuln => (
                  <div key={vuln.id} className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow">
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex items-center space-x-3">
                        <h4 className="text-lg font-semibold text-gray-900">{vuln.type}</h4>
                        <span
                          className={`px-2 py-1 rounded-full text-xs font-medium text-white`}
                          style={{ backgroundColor: severityColors[vuln.severity] }}
                        >
                          {vuln.severity.toUpperCase()}
                        </span>
                        {vuln.cveId && (
                          <span className="px-2 py-1 bg-gray-100 text-gray-800 rounded text-xs">
                            {vuln.cveId}
                          </span>
                        )}
                      </div>
                      <span className="text-sm text-gray-600">ポート {vuln.port}</span>
                    </div>
                    
                    <p className="text-gray-700 mb-3">{vuln.description}</p>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                      <div>
                        <p className="font-medium text-gray-900 mb-1">影響:</p>
                        <p className="text-gray-600">{vuln.impact}</p>
                      </div>
                      <div>
                        <p className="font-medium text-gray-900 mb-1">対策:</p>
                        <p className="text-gray-600">{vuln.solution}</p>
                      </div>
                    </div>
                  </div>
                ))}
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
                      {analysisData.overallRisk === 'high' && 'immediate attention required - 緊急対応が必要です'}
                      {analysisData.overallRisk === 'medium' && 'moderate risk - 早期対応を推奨します'}
                      {analysisData.overallRisk === 'low' && 'low risk - 継続的な監視が必要です'}
                    </p>
                  </div>
                  <div className="text-2xl font-bold uppercase">
                    {analysisData.overallRisk}
                  </div>
                </div>
              </div>

              {analysisData.mostCritical && (
                <div className="border-l-4 border-red-500 bg-red-50 p-6 rounded-r-lg">
                  <h4 className="text-lg font-semibold text-red-900 mb-2">最優先対応項目</h4>
                  <div className="text-red-800">
                    <p className="font-medium">{analysisData.mostCritical.type}</p>
                    <p className="text-sm mt-1">{analysisData.mostCritical.description}</p>
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
                {analysisData.recommendations.map((rec, index) => (
                  <div key={index} className="border border-gray-200 rounded-lg p-6 hover:shadow-md transition-shadow">
                    <div className="flex items-start space-x-4">
                      <div className={`w-3 h-3 rounded-full ${getPriorityColor(rec.priority)} mt-2`}></div>
                      <div className="flex-1">
                        <div className="flex items-start justify-between mb-3">
                          <h4 className="text-lg font-semibold text-gray-900">{rec.title}</h4>
                          <span className={`px-2 py-1 rounded-full text-xs font-medium text-white ${getPriorityColor(rec.priority)}`}>
                            {rec.priority.toUpperCase()}
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
                {scanResults.vulnerabilities.slice(0, 3).map((vuln, index) => (
                  <div key={vuln.id} className="border-b border-gray-200 pb-8 last:border-b-0 last:pb-0">
                    <div className="flex items-center space-x-3 mb-4">
                      <span className="flex items-center justify-center w-8 h-8 bg-blue-100 text-blue-600 rounded-full font-semibold text-sm">
                        {index + 1}
                      </span>
                      <h4 className="text-xl font-semibold text-gray-900">{vuln.type}</h4>
                    </div>
                    
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                      <div>
                        <h5 className="font-semibold text-gray-900 mb-3">技術的解説</h5>
                        <p className="text-gray-700 mb-4">{vuln.description}</p>
                        <p className="text-gray-700"><strong>影響:</strong> {vuln.impact}</p>
                      </div>
                      
                      <div>
                        <h5 className="font-semibold text-gray-900 mb-3">改善案</h5>
                        <p className="text-gray-700 mb-4">{vuln.solution}</p>
                        
                        {scanResults.scanType === 'bulk' && (
                          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                            <h6 className="font-medium text-blue-900 mb-2">💡 わかりやすい例え</h6>
                            <p className="text-blue-800 text-sm">
                              {vuln.type === 'SQL Injection' && 
                                '家の鍵穴に針金を刺されて不正に開けられるようなもの。正しい鍵（パラメータ化クエリ）を使えば安全です。'}
                              {vuln.type === 'XSS' && 
                                '手紙に毒を仕込まれ、読んだ人が被害を受けるようなもの。手紙の内容をチェック（サニタイズ）すれば防げます。'}
                              {vuln.type === 'Directory Traversal' && 
                                '建物の立入禁止区域に不正侵入されるようなもの。適切な案内（パス検証）があれば防げます。'}
                              {(vuln.type === 'Open Port' || vuln.type === 'Weak SSL/TLS') && 
                                '家の窓や扉が開いたままになっているようなもの。不要な入口は閉めて、必要な入口には強い鍵をかけましょう。'}
                            </p>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
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