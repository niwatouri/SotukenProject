import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Brain, Shield, Home, Lightbulb, AlertTriangle, CheckCircle, ArrowRight } from 'lucide-react';
import { useScan } from '../contexts/ScanContext';
import { useAuth } from '../contexts/AuthContext';
import Footer from '../components/Footer';

function AIAnalysis() {
  const { scanResults } = useScan();
  const { logout, user } = useAuth();
  const navigate = useNavigate();

  // Scroll to top when component mounts
  useEffect(() => {
    window.scrollTo(0, 0);
  }, []);

  if (!scanResults) {
    navigate('/home');
    return null;
  }

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
              <Brain className="w-8 h-8 text-purple-600" />
              <div>
                <h1 className="text-xl font-bold text-gray-900">AI セキュリティ分析</h1>
                <p className="text-sm text-gray-600">インテリジェント脆弱性解析</p>
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
              <button
                onClick={() => navigate('/dashboard')}
                className="flex items-center space-x-2 px-3 py-2 text-sm text-gray-600 hover:text-blue-600 transition-colors"
              >
                <Shield className="w-4 h-4" />
                <span>ダッシュボード</span>
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

      <main className="flex-1 max-w-6xl mx-auto px-4 py-8">
        {/* AI Summary */}
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
          
          {scanResults.vulnerabilities.length > 3 && (
            <div className="mt-8 text-center">
              <button
                onClick={() => navigate('/dashboard')}
                className="inline-flex items-center space-x-2 px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
              >
                <span>すべての脆弱性を表示</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>
      </main>

      <Footer />
    </div>
  );
}

export default AIAnalysis;