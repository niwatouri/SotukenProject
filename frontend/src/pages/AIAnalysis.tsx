import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Brain, Shield, Home, Lightbulb, AlertTriangle, CheckCircle, ArrowRight } from 'lucide-react';
import { useScan, VulnerabilityData } from '../contexts/ScanContext';
import { getAnalysisData, getPriorityColor, getRiskColor } from '../utils/analysis';
import { stripHtml } from '../utils/text';
import type { Recommendation } from '../utils/analysis';
import { useAuth } from '../contexts/AuthContext';
import Footer from '../components/Footer';
import { API_BASE_URL } from '../utils/api';

type AISummaryStatus = 'pending' | 'processing' | 'failed' | 'completed' | 'skipped';

interface AIAdviceItem {
  vulnId: string;
  alertKey?: string;
  status: AISummaryStatus;
  title?: string;
  summary?: string;
  impact?: string;
  steps?: string[];
  analogy?: string;
  error_reason?: string;
}

type AdviceRecommendation = Recommendation & {
  steps?: string[];
};

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
      return '小さな穴が空いたバケツのようなもの。放置すると被害が広がるため、早めに塞ぐのが効果的です。';
  }
};

const getAiStatusMessage = (status: AISummaryStatus) => {
  switch (status) {
    case 'processing':
      return 'AI解析中です。しばらくお待ちください。';
    case 'failed':
      return 'AI解析に失敗しました。';
    case 'skipped':
      return 'AI解析対象外です。';
    case 'pending':
    default:
      return 'AI解析の生成待ちです。';
  }
};

const normalizeAiStatus = (value: any): AISummaryStatus => {
  switch (value) {
    case 'completed':
    case 'processing':
    case 'failed':
    case 'skipped':
    case 'pending':
      return value;
    default:
      return 'pending';
  }
};

function AIAnalysis() {
  const { scanResults, scanId } = useScan();
  const { logout, user } = useAuth();
  const navigate = useNavigate();
  const [aiAdvice, setAiAdvice] = useState<AIAdviceItem[] | null>(null);
  const [isLoadingAdvice, setIsLoadingAdvice] = useState(false);

  // Scroll to top when component mounts
  useEffect(() => {
    window.scrollTo(0, 0);
  }, []);

  useEffect(() => {
    if (!scanResults) {
      return;
    }

    const token = localStorage.getItem(TOKEN_STORAGE_KEY);
    if (!token || !scanId) {
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
    let retryTimer: number | undefined;

    const fetchAdvice = async () => {
      setIsLoadingAdvice(true);
      try {
        const response = await fetch(`${API_BASE_URL}/advice`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({ scan_id: scanId }),
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
        const summaries = Array.isArray(data?.summaries) ? data.summaries : [];
        const items = Array.isArray(data?.items) ? data.items : [];
        const source = summaries.length > 0 ? summaries : items.map((item: any) => ({ ...item, status: 'completed' }));
        const normalized = source
          .filter((item: any) => item && (typeof item.vulnId === 'string' || typeof item.alertKey === 'string'))
          .map((item: any) => ({
            vulnId: String(item.vulnId ?? ''),
            alertKey: typeof item.alertKey === 'string' ? item.alertKey : undefined,
            status: normalizeAiStatus(item.status),
            title: item.title ?? undefined,
            summary: item.summary ?? undefined,
            impact: item.impact ?? undefined,
            steps: Array.isArray(item.steps) ? item.steps : undefined,
            analogy: item.analogy ?? undefined,
            error_reason: item.error_reason ?? undefined,
          } as AIAdviceItem));

        if (isActive) {
          setAiAdvice(normalized);
        }

        const shouldPoll = normalized.some((item) => item.status === 'pending' || item.status === 'processing');
        if (isActive && shouldPoll) {
          retryTimer = window.setTimeout(fetchAdvice, 4000);
        }
      } catch (error) {
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
      if (retryTimer) {
        window.clearTimeout(retryTimer);
      }
    };
  }, [scanResults, scanId, logout]);

  const analysisData = scanResults ? getAnalysisData(scanResults) : null;
  const vulnById = useMemo(() => {
    const entries = scanResults?.vulnerabilities?.map((vuln) => [vuln.id, vuln] as const) ?? [];
    return new Map(entries);
  }, [scanResults]);
  const aiAdviceList = Array.isArray(aiAdvice) ? aiAdvice : [];
  const adviceByKey = useMemo(() => {
    const entries = aiAdviceList
      .filter((item) => item && typeof item.alertKey === 'string')
      .map((item) => [item.alertKey as string, item] as const);
    return new Map(entries);
  }, [aiAdviceList]);
  const adviceById = useMemo(() => {
    const entries = aiAdviceList
      .filter((item) => item && typeof item.vulnId === 'string')
      .map((item) => [item.vulnId, item] as const);
    return new Map(entries);
  }, [aiAdviceList]);
  const completedAdvice = aiAdviceList.filter((item) => item.status === 'completed');
  const hasAiAdvice = !isLoadingAdvice && completedAdvice.length > 0;
  const recommendations: AdviceRecommendation[] = hasAiAdvice
    ? completedAdvice.map((item) => {
        const vuln = vulnById.get(item.vulnId);
        const safeSteps = Array.isArray(item.steps)
          ? item.steps.map((step) => stripHtml(step)).filter((step) => step.length > 0)
          : undefined;
        return {
          priority: getPriorityFromSeverity(vuln?.severity),
          title: item.title || vuln?.type || '脆弱性の改善案',
          description: stripHtml(item.summary || vuln?.description || ''),
          impact: stripHtml(item.impact || vuln?.impact || ''),
          steps: safeSteps,
        };
      })
    : analysisData?.recommendations ?? [];

  if (!scanResults || !analysisData) {
    navigate('/home');
    return null;
  }

  const totalVulnerabilities = scanResults?.vulnerabilities?.length ?? 0;

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
              <div className="text-2xl font-bold">{totalVulnerabilities}件</div>
              <div className="text-purple-100">検出された脆弱性（合計）</div>
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
            {recommendations.map((rec, index) => (
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
                    {rec.steps && rec.steps.length > 0 && (
                      <ul className="mb-3 list-disc list-inside text-sm text-gray-600 space-y-1">
                        {rec.steps.map((step, stepIndex) => (
                          <li key={stepIndex}>{step}</li>
                        ))}
                      </ul>
                    )}
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
              const alertKey = vuln.alertKey ?? vuln.id;
              const advice = adviceByKey.get(alertKey) || adviceById.get(vuln.id);
              const summary = stripHtml(advice?.summary || vuln.description);
              const impact = stripHtml(advice?.impact || vuln.impact);
              const steps = Array.isArray(advice?.steps)
                ? advice?.steps
                    .map((step) => stripHtml(step))
                    .filter((step) => step.length > 0)
                : [];
              const analogyFromAi = stripHtml(advice?.analogy || '');
              const analogy = analogyFromAi || getFallbackAnalogy(vuln.type);
              return (
              <div key={`${vuln.id}-${index}`} className="border-b border-gray-200 pb-8 last:border-b-0 last:pb-0">
                <div className="flex items-center space-x-3 mb-4">
                  <span className="flex items-center justify-center w-8 h-8 bg-blue-100 text-blue-600 rounded-full font-semibold text-sm">
                    {index + 1}
                  </span>
                  <h4 className="text-xl font-semibold text-gray-900">{vuln.type}</h4>
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
                      <p className="text-gray-700 mb-4">{stripHtml(vuln.solution)}</p>
                    )}
                    
                    {scanResults.scanType === 'bulk' && analogy && (
                      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                        <h6 className="font-medium text-blue-900 mb-2">💡 わかりやすい例え</h6>
                        <p className="text-blue-800 text-sm">{analogy}</p>
                      </div>
                    )}
                  </div>
                </div>
              </div>
              );
            })}
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
