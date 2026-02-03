import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { Shield, AlertTriangle, Activity, Globe, Download, Brain, Home, Clock, Target, BarChart3, CheckCircle, Lightbulb } from 'lucide-react';
import { ScanHistoryItem, useScan, VulnerabilityData } from '../contexts/ScanContext';
import { getAnalysisData, getPriorityColor, getRiskColor } from '../utils/analysis';
import { AI_GENERAL_LABEL, normalizeAiSteps, normalizeAiText, stripHtml } from '../utils/text';
import { useAuth } from '../contexts/AuthContext';
import { jsPDF } from 'jspdf';
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

const TOKEN_STORAGE_KEY = 'auth_token';
const PDF_FONT_URL = new URL('../assets/fonts/IPAexGothic.ttf', import.meta.url).toString();
const PDF_FONT_NAME = 'IPAexGothic';
const PDF_FONT_FILE = 'IPAexGothic.ttf';
let pdfFontBase64Promise: Promise<string> | null = null;

const loadPdfFontBase64 = async () => {
  if (!pdfFontBase64Promise) {
    pdfFontBase64Promise = fetch(PDF_FONT_URL)
      .then((res) => {
        if (!res.ok) {
          throw new Error('Failed to load PDF font');
        }
        return res.arrayBuffer();
      })
      .then((buffer) => {
        const bytes = new Uint8Array(buffer);
        const chunkSize = 0x8000;
        let binary = '';
        for (let i = 0; i < bytes.length; i += chunkSize) {
          binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
        }
        return btoa(binary);
      });
  }
  return pdfFontBase64Promise;
};

const ensurePdfFont = async (pdf: jsPDF) => {
  const fontList = pdf.getFontList();
  if (!fontList[PDF_FONT_NAME]) {
    const base64 = await loadPdfFontBase64();
    pdf.addFileToVFS(PDF_FONT_FILE, base64);
    pdf.addFont(PDF_FONT_FILE, PDF_FONT_NAME, 'normal');
  }
  pdf.setFont(PDF_FONT_NAME, 'normal');
};

const getPriorityFromSeverity = (severity?: VulnerabilityData['severity']): 'high' | 'medium' | 'low' => {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    case 'info':
    case 'low':
      return 'low';
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
    case 'info':
      return '情報';
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

const getConfidenceLabel = (confidence?: 'high' | 'medium' | 'low' | null) => {
  switch (confidence) {
    case 'high':
      return 'High';
    case 'medium':
      return 'Medium';
    case 'low':
      return 'Low';
    default:
      return '未取得';
  }
};

const getConfidenceTone = (confidence?: string | null) => {
  switch (confidence) {
    case 'high':
      return 'bg-red-100 text-red-700';
    case 'medium':
      return 'bg-yellow-100 text-yellow-700';
    case 'low':
      return 'bg-green-100 text-green-700';
    default:
      return 'bg-gray-100 text-gray-600';
  }
};

const getAiStatusLabel = (status: AISummaryStatus) => {
  switch (status) {
    case 'completed':
      return '解析完了';
    case 'processing':
      return 'AI解析中';
    case 'failed':
      return '生成失敗';
    case 'skipped':
      return '対象外';
    case 'pending':
    default:
      return '未生成';
  }
};

const getAiStatusTone = (status: AISummaryStatus) => {
  switch (status) {
    case 'completed':
      return 'bg-emerald-100 text-emerald-700';
    case 'processing':
      return 'bg-blue-100 text-blue-700';
    case 'failed':
      return 'bg-red-100 text-red-700';
    case 'skipped':
      return 'bg-gray-200 text-gray-600';
    case 'pending':
    default:
      return 'bg-slate-100 text-slate-600';
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

const trimSnippet = (snippet?: string[] | null) => {
  if (!Array.isArray(snippet)) {
    return [];
  }
  return snippet.slice(0, 10).map((line) => (line.length > 200 ? `${line.slice(0, 199)}…` : line));
};

function Dashboard() {
  const { scanResults, scanId, loadScanById, loadScanHistory } = useScan();
  const { logout, user } = useAuth();
  const navigate = useNavigate();
  const [activeView, setActiveView] = useState<'dashboard' | 'ai'>('dashboard');
  const [historyScans, setHistoryScans] = useState<ScanHistoryItem[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [loadingScanId, setLoadingScanId] = useState<number | null>(null);
  const [aiAdvice, setAiAdvice] = useState<AIAdviceItem[] | null>(null);
  const [isLoadingAdvice, setIsLoadingAdvice] = useState(false);
  const [aiRefreshToken, setAiRefreshToken] = useState(0);
  const [retryingKey, setRetryingKey] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<'all' | 'high_medium' | 'high'>('all');

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
      if (retryTimer) {
        window.clearTimeout(retryTimer);
      }
    };
  }, [scanResults, scanId, logout, aiRefreshToken]);

  const handleLoadScan = async (scanId: number) => {
    setLoadingScanId(scanId);
    const ok = await loadScanById(scanId);
    setLoadingScanId(null);
    if (!ok) {
      alert('スキャン結果を取得できませんでした');
    }
  };

  const handleRetryAdvice = async (alertKey: string) => {
    if (!scanId) {
      return;
    }
    const token = localStorage.getItem(TOKEN_STORAGE_KEY);
    if (!token) {
      return;
    }
    setRetryingKey(alertKey);
    try {
      const response = await fetch(`${API_BASE_URL}/advice/retry`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ scan_id: scanId, alert_key: alertKey }),
      });

      if (response.status === 401) {
        logout();
        return;
      }

      if (!response.ok) {
        throw new Error('AI解析の再試行に失敗しました');
      }

      setAiAdvice((prev) => {
        if (!prev) {
          return prev;
        }
        return prev.map((item) =>
          item.alertKey === alertKey
            ? { ...item, status: 'processing', error_reason: undefined }
            : item
        );
      });
      setAiRefreshToken((value) => value + 1);
    } catch (error) {
      console.error(error);
      alert('AI解析の再試行に失敗しました');
    } finally {
      setRetryingKey(null);
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
    info: '#3B82F6',
    low: '#10B981',
    medium: '#F59E0B',
    high: '#EF4444',
    critical: '#7C2D12'
  };

  const severityCounts = scanResults.vulnerabilities.reduce((acc, vuln) => {
    acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
  const totalVulnerabilities = scanResults.vulnerabilities.length;
  const stoppedByTimeout = scanResults.scanStatus === 'stopped' || scanResults.scanError === 'stopped_by_timeout';

  const filteredVulnerabilities = scanResults.vulnerabilities.filter((vuln) => {
    if (severityFilter === 'high') {
      return vuln.severity === 'high' || vuln.severity === 'critical';
    }
    if (severityFilter === 'high_medium') {
      return vuln.severity === 'high' || vuln.severity === 'critical' || vuln.severity === 'medium';
    }
    return true;
  });

  const pieData = Object.entries(severityCounts).map(([severity, count]) => ({
    name: getSeverityLabel(severity),
    value: count,
    color: severityColors[severity as keyof typeof severityColors]
  }));

  const aiAdviceList = Array.isArray(aiAdvice) ? aiAdvice : [];
  const hasCompletedAdvice = aiAdviceList.some((item) => item.status === 'completed');
  const canDownloadPdf = !isLoadingAdvice;

  const generatePDFReport = async () => {
    if (!canDownloadPdf) {
      alert('AI解析結果の取得中です。完了後にダウンロードしてください。');
      return;
    }

    const pdf = new jsPDF();
    await ensurePdfFont(pdf);
    const pageWidth = pdf.internal.pageSize.width;
    const pageHeight = pdf.internal.pageSize.height;
    const marginX = 18;
    const marginY = 18;
    const contentWidth = pageWidth - marginX * 2;
    let yPosition = marginY;

    const lineHeightFor = (fontSize: number) => Math.max(4, fontSize * 0.35 + 1);
    const ensureSpace = (height: number) => {
      if (yPosition + height > pageHeight - marginY) {
        pdf.addPage();
        yPosition = marginY;
      }
    };
    const addLines = (lines: string[], fontSize: number, indent = 0, gap = 0) => {
      const lineHeight = lineHeightFor(fontSize);
      ensureSpace(lines.length * lineHeight + gap);
      pdf.setFontSize(fontSize);
      pdf.text(lines, marginX + indent, yPosition);
      yPosition += lines.length * lineHeight + gap;
    };
    const addParagraph = (text: string, fontSize = 10, indent = 0, gap = 0) => {
      const lines = pdf.splitTextToSize(text, contentWidth - indent);
      addLines(lines, fontSize, indent, gap);
    };
    const addCenteredTitle = (text: string) => {
      const fontSize = 18;
      const lineHeight = lineHeightFor(fontSize);
      ensureSpace(lineHeight + 4);
      pdf.setFontSize(fontSize);
      pdf.text(text, pageWidth / 2, yPosition, { align: 'center' });
      yPosition += lineHeight + 4;
    };
    const addSectionTitle = (text: string) => {
      addParagraph(text, 13, 0, 3);
    };
    const addSubTitle = (text: string) => {
      addParagraph(text, 11, 0, 2);
    };
    const addDivider = () => {
      ensureSpace(3);
      pdf.setDrawColor(220);
      pdf.line(marginX, yPosition, pageWidth - marginX, yPosition);
      yPosition += 4;
    };
    const maskSensitiveLine = (line: string) => {
      let masked = line;
      masked = masked.replace(/(authorization|cookie)\s*:\s*[^\n]*/gi, '$1: ***');
      masked = masked.replace(/(token|apikey|api_key|access_token|session|jwt)\s*=?\s*[^\s&]+/gi, '$1=***');
      return masked;
    };
    const maskSnippet = (lines: string[]) => lines.map((line) => maskSensitiveLine(line));

    const criticalCount = Number(severityCounts.critical || 0);
    const highCount = Number(severityCounts.high || 0);
    const mediumCount = Number(severityCounts.medium || 0);
    const lowCount = Number(severityCounts.low || 0);
    const infoCount = Number(severityCounts.info || 0);
    const highRiskCount = criticalCount + highCount;
    const midPlusCount = highRiskCount + mediumCount;
    const openPortsCount = scanResults.openPorts.length;
    const openPortsText = openPortsCount > 0 ? scanResults.openPorts.join(', ') : 'なし';
    const scanTypeLabel = scanResults.scanType === 'bulk' ? '一括スキャン' : '詳細スキャン';

    const adviceByKey = new Map(
      aiAdviceList
        .filter((item) => item && typeof item.alertKey === 'string')
        .map((item) => [item.alertKey as string, item] as const),
    );
    const adviceById = new Map(
      aiAdviceList
        .filter((item) => item && typeof item.vulnId === 'string')
        .map((item) => [item.vulnId, item] as const),
    );

    const getFallbackMitigations = (vulnType: string) => {
      const lower = (vulnType || '').toLowerCase();
      if (lower.includes('sql')) {
        return [
          'プレースホルダ/バインド変数を使用する',
          'ORMの安全APIを使用する',
          '入力値の型チェック/バリデーションを実施する',
          'DB最小権限を適用する',
          'エラーメッセージを抑制する',
          'WAFは補助として利用する',
        ];
      }
      if (lower.includes('xss') || lower.includes('cross site')) {
        return [
          '出力エスケープを徹底する',
          'テンプレートエンジンの自動エスケープを有効化する',
          'CSPを導入する',
          'HttpOnly/SameSiteを適用する',
          '入力検証は補助として実施する',
        ];
      }
      return [
        '入力値の型チェック/バリデーションを実施する',
        '権限の最小化を徹底する',
        'エラーメッセージを抑制する',
        'WAFは補助として利用する',
      ];
    };

    addCenteredTitle('SecureGuard 脆弱性レポート');
    addParagraph(`対象URL: ${scanResults.targetUrl}`);
    addParagraph(`スキャン実行日時: ${new Date(scanResults.timestamp).toLocaleString('ja-JP')}`);
    addParagraph(`スキャンタイプ: ${scanTypeLabel}`);
    addParagraph(`検出された脆弱性（合計）: ${totalVulnerabilities}件`);
    addParagraph(`開放ポート（合計）: ${openPortsCount}件`);
    addParagraph(`開放ポート一覧: ${openPortsText}`);
    if (stoppedByTimeout) {
      addParagraph('※時間上限で停止: タイムボックスに達したためスキャンを停止しました。');
    }
    addDivider();

    addSectionTitle('サマリー');
    addParagraph(`脆弱性検出数: ${totalVulnerabilities}件`);
    addParagraph(`開放ポート数: ${openPortsCount}件`);
    addParagraph(`中以上のリスク件数: ${midPlusCount}件（High+Medium、CriticalはHighに含む）`);
    addParagraph(
      `重要度分布: Critical=${criticalCount}, High=${highCount}, Medium=${mediumCount}, Low=${lowCount}, Info=${infoCount}（合計${totalVulnerabilities}）`,
    );
    if (totalVulnerabilities === 0) {
      addParagraph('検出された脆弱性はありません。');
    }
    addDivider();

    addSectionTitle('検出された脆弱性（証拠付き）');
    if (scanResults.vulnerabilities.length === 0) {
      addParagraph('検出結果がありません。');
    }
    scanResults.vulnerabilities.forEach((vuln, index) => {
      const alertKey = vuln.alertKey ?? vuln.id;
      const advice = adviceByKey.get(alertKey) || adviceById.get(vuln.id);
      const status = normalizeAiStatus(advice?.status);
      const statusLabel = getAiStatusLabel(status);
      const title = advice?.title ? normalizeAiText(advice.title) : (vuln.type || '脆弱性項目');
      const summaryFallback = normalizeAiText(vuln.description || '');
      const impactFallback = normalizeAiText(vuln.impact || '');
      const summary = status === 'completed'
        ? normalizeAiText(advice?.summary || summaryFallback)
        : summaryFallback;
      const impact = status === 'completed'
        ? normalizeAiText(advice?.impact || impactFallback)
        : impactFallback;
      const aiSteps = status === 'completed' && Array.isArray(advice?.steps)
        ? normalizeAiSteps(advice.steps)
        : [];
      let mitigationSteps = aiSteps.length > 0 ? aiSteps : getFallbackMitigations(vuln.type || '');
      if (mitigationSteps.length < 4) {
        const padding = getFallbackMitigations('');
        mitigationSteps = [...mitigationSteps, ...padding].slice(0, 6);
      }
      const evidence = vuln.evidence;
      const requestSnippet = maskSnippet(trimSnippet(evidence?.request_snippet));
      const responseSnippet = maskSnippet(trimSnippet(evidence?.response_snippet));

      addSubTitle(`${index + 1}. ${title}`);
      addParagraph(`重要度: ${getSeverityLabel(vuln.severity)} / ポート: ${vuln.port}`);
      addParagraph(`AI解析: ${statusLabel}`);
      if (status === 'failed' && advice?.error_reason) {
        addParagraph(`失敗理由: ${normalizeAiText(advice.error_reason)}`, 9);
      }
      if (status === 'completed') {
        addParagraph(AI_GENERAL_LABEL, 8, 0, 2);
      }
      addParagraph(`概要: ${summary || '未取得'}`);
      addParagraph(`影響: ${impact || '未取得'}`);

      addParagraph('対策:');
      mitigationSteps.forEach((step) => {
        addParagraph(`・${step}`, 10, 2);
      });

      addParagraph('証拠:');
      addParagraph(`該当URL: ${evidence?.affected_url || '未取得'}`, 10, 2);
      addParagraph(`パス: ${evidence?.path || '未取得'}`, 10, 2);
      addParagraph(`メソッド: ${evidence?.method || '未取得'}`, 10, 2);
      addParagraph(`パラメータ: ${evidence?.parameter || '未取得'}`, 10, 2);
      addParagraph(`検出根拠: ${evidence?.rationale || '未取得'}`, 10, 2);
      addParagraph(`確度: ${getConfidenceLabel(evidence?.confidence ?? null)}`, 10, 2);
      addParagraph(`再現手順: ${evidence?.reproduction || '未取得'}`, 10, 2);

      addParagraph('抜粋（最大10行）:');
      if (requestSnippet.length > 0) {
        addParagraph('リクエスト:', 9, 2);
        requestSnippet.forEach((line) => addParagraph(line, 9, 6));
      } else {
        addParagraph('リクエスト: 未取得', 9, 2);
      }
      if (responseSnippet.length > 0) {
        addParagraph('レスポンス:', 9, 2);
        responseSnippet.forEach((line) => addParagraph(line, 9, 6));
      } else {
        addParagraph('レスポンス: 未取得', 9, 2);
      }

      addDivider();
    });

    addSectionTitle('AI解析サマリー');
    addParagraph(`高リスク脆弱性数: ${analysisData.criticalIssues}件`);
    addParagraph(`中リスク脆弱性数: ${analysisData.mediumIssues}件`);
    addParagraph(`低リスク脆弱性数: ${lowCount}件`);
    addParagraph(`情報レベル脆弱性数: ${infoCount}件`);

    const riskComment = analysisData.overallRisk === 'high'
      ? '緊急対応が必要です'
      : analysisData.overallRisk === 'medium'
        ? '早期対応を推奨します'
        : '継続的な監視が必要です';
    addSectionTitle('リスク評価');
    addParagraph(`総合リスクレベル: ${overallRiskLabel}`);
    addParagraph(`コメント: ${riskComment}`);

    addSectionTitle('最優先対応項目');
    if (mostCritical) {
      const priorityReason = mostCriticalImpact
        ? normalizeAiText(mostCriticalImpact)
        : (mostCriticalSummary || '影響が大きいと判断されるため');
      addParagraph(`${mostCriticalTitle}（ポート ${mostCritical.port}）`);
      addParagraph(`理由: ${priorityReason}`);
    } else {
      addParagraph('該当なし');
    }

    addSectionTitle('AI推奨改善策');
    addParagraph(AI_GENERAL_LABEL, 8, 0, 2);
    if (recommendations.length === 0) {
      addParagraph('推奨改善策は未取得です。');
    }
    recommendations.forEach((rec, index) => {
      addParagraph(`${index + 1}. ${normalizeAiText(rec.title)}`);
      addParagraph(`概要: ${normalizeAiText(rec.description)}`, 10, 2);
      addParagraph(`期待効果: ${normalizeAiText(rec.impact)}`, 10, 2);
    });

    addSectionTitle('詳細分析と解説');
    const detailTargets = scanResults.vulnerabilities.slice(0, 3);
    detailTargets.forEach((vuln, index) => {
      const alertKey = vuln.alertKey ?? vuln.id;
      const advice = adviceByKey.get(alertKey) || adviceById.get(vuln.id);
      const status = normalizeAiStatus(advice?.status);
      const statusLabel = getAiStatusLabel(status);
      const title = advice?.title ? normalizeAiText(advice.title) : (vuln.type || '脆弱性項目');
      const summary = status === 'completed'
        ? normalizeAiText(advice?.summary || vuln.description)
        : normalizeAiText(vuln.description || '');
      const impact = status === 'completed'
        ? normalizeAiText(advice?.impact || vuln.impact)
        : normalizeAiText(vuln.impact || '');
      const steps = status === 'completed' && Array.isArray(advice?.steps)
        ? normalizeAiSteps(advice.steps)
        : [];
      const analogy = status === 'completed'
        ? normalizeAiText(advice?.analogy || getFallbackAnalogy(vuln.type))
        : '';

      addSubTitle(`${index + 1}. ${title}`);
      addParagraph(`AI解析: ${statusLabel}`);
      if (status === 'completed') {
        addParagraph(AI_GENERAL_LABEL, 8, 0, 2);
      }
      addParagraph(`技術的解説: ${summary || '未取得'}`);
      addParagraph(`影響: ${impact || '未取得'}`);
      if (steps.length > 0) {
        addParagraph('改善案:');
        steps.forEach((step) => addParagraph(`・${step}`, 10, 2));
      } else {
        addParagraph('改善案: 未取得');
      }
      if (analogy) {
        addParagraph(`わかりやすい例え: ${analogy}`);
      }
      addDivider();
    });
    if (scanResults.vulnerabilities.length > detailTargets.length) {
      addParagraph('※詳細分析は上位3件を掲載しています。');
    }

    pdf.save(`secureguard-report-${new Date().toISOString().split('T')[0]}.pdf`);
  };

  const analysisData = getAnalysisData(scanResults);
  const aiMissingSummaryText = 'AI解析の要約がありません。';
  const aiMissingImpactText = 'AI解析の影響情報がありません。';
  const aiMissingStepsText = 'AI解析の改善案がありません。';
  const overallRiskLabel = analysisData.overallRisk === 'high'
    ? '高'
    : analysisData.overallRisk === 'medium'
      ? '中'
      : '低';
  const vulnById = new Map(scanResults.vulnerabilities.map((vuln) => [vuln.id, vuln]));
  const adviceByKey = new Map(
    aiAdviceList
      .filter((item) => item && typeof item.alertKey === 'string')
      .map((item) => [item.alertKey as string, item] as const),
  );
  const adviceById = new Map(
    aiAdviceList
      .filter((item) => item && typeof item.vulnId === 'string')
      .map((item) => [item.vulnId, item] as const),
  );
  const completedAdvice = aiAdviceList.filter((item) => item.status === 'completed');
  const recommendations = hasCompletedAdvice
    ? completedAdvice.map((item) => {
        const vuln = vulnById.get(item.vulnId);
        const description = item.summary
          ? normalizeAiText(item.summary)
          : aiMissingSummaryText;
        const impact = item.impact
          ? normalizeAiText(item.impact)
          : aiMissingImpactText;
        const title = item.title ? normalizeAiText(item.title) : '脆弱性の改善案';
        return {
          priority: getPriorityFromSeverity(vuln?.severity),
          title,
          description,
          impact,
        };
      })
    : analysisData.recommendations;
  const mostCritical = analysisData.mostCritical;
  const mostCriticalKey = mostCritical?.alertKey ?? mostCritical?.id;
  const mostCriticalAdvice = mostCriticalKey
    ? (adviceByKey.get(mostCriticalKey) || adviceById.get(mostCritical.id))
    : undefined;
  const mostCriticalStatus: AISummaryStatus = mostCriticalAdvice?.status ?? (isLoadingAdvice ? 'processing' : 'pending');
  const mostCriticalTitle = mostCritical
    ? (mostCriticalAdvice?.title
        ? normalizeAiText(mostCriticalAdvice.title)
        : (mostCritical.type || getAiStatusLabel(mostCriticalStatus)))
    : '';
  const mostCriticalSummary = mostCritical
    ? (mostCriticalStatus === 'completed'
        ? (mostCriticalAdvice?.summary ? normalizeAiText(mostCriticalAdvice.summary) : aiMissingSummaryText)
        : getAiStatusMessage(mostCriticalStatus))
    : '';
  const mostCriticalImpact = mostCritical
    ? (mostCriticalStatus === 'completed'
        ? (mostCriticalAdvice?.impact ? normalizeAiText(mostCriticalAdvice.impact) : aiMissingImpactText)
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
            {stoppedByTimeout && (
              <div className="mb-6 flex items-start space-x-3 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3">
                <AlertTriangle className="mt-0.5 h-5 w-5 text-amber-600" />
                <div className="text-sm text-amber-900">
                  <p className="font-semibold">時間上限で停止</p>
                  <p className="opacity-80">タイムボックスに達したためスキャンを停止しました。</p>
                </div>
              </div>
            )}
            {/* Scan Info */}
            <div className="bg-white rounded-2xl shadow-lg p-6 mb-8 border border-slate-200">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-2xl font-bold text-gray-900">スキャン結果</h2>
                <button
                  onClick={generatePDFReport}
                  disabled={!canDownloadPdf}
                  className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-colors ${
                    canDownloadPdf
                      ? 'bg-blue-600 text-white hover:bg-blue-700'
                      : 'bg-gray-200 text-gray-500 cursor-not-allowed'
                  }`}
                >
                  <Download className="w-4 h-4" />
                  <span>
                    {canDownloadPdf ? 'PDFダウンロード' : (isLoadingAdvice ? 'AI解析中...' : 'AI解析待ち')}
                  </span>
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
                    <p className="text-sm text-gray-600">検出された脆弱性</p>
                    <p className="font-semibold text-gray-900">{totalVulnerabilities}件</p>
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
            <div className="grid grid-cols-1 gap-8 mb-8">
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
                <div className="mt-4 grid grid-cols-2 sm:grid-cols-4 gap-2 text-sm text-gray-600">
                  <span>High: {severityCounts.high || 0}</span>
                  <span>Medium: {severityCounts.medium || 0}</span>
                  <span>Low: {severityCounts.low || 0}</span>
                  <span>Info: {severityCounts.info || 0}</span>
                </div>
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
              <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 mb-6">
                <h3 className="text-lg font-semibold text-gray-900">検出された脆弱性</h3>
                <div className="flex items-center space-x-2 text-sm text-gray-600">
                  <span>表示:</span>
                  <select
                    value={severityFilter}
                    onChange={(e) => setSeverityFilter(e.target.value as 'all' | 'high_medium' | 'high')}
                    className="border border-gray-300 rounded-md px-2 py-1 text-sm"
                  >
                    <option value="all">All</option>
                    <option value="high_medium">High+Medium</option>
                    <option value="high">High</option>
                  </select>
                </div>
              </div>
              <div className="space-y-4">
                {filteredVulnerabilities.map((vuln, index) => {
                  const alertKey = vuln.alertKey ?? vuln.id;
                  const advice = adviceByKey.get(alertKey) || adviceById.get(vuln.id);
                  const status = advice?.status ?? (isLoadingAdvice ? 'processing' : 'pending');
                  const statusMessage = getAiStatusMessage(status);
                  const title = advice?.title
                    ? normalizeAiText(advice.title)
                    : (vuln.type || '脆弱性項目');
                  const description = status === 'completed'
                    ? (advice?.summary ? normalizeAiText(advice.summary) : aiMissingSummaryText)
                    : statusMessage;
                  const impact = status === 'completed'
                    ? (advice?.impact ? normalizeAiText(advice.impact) : aiMissingImpactText)
                    : statusMessage;
                  const steps = status === 'completed' && Array.isArray(advice?.steps)
                    ? normalizeAiSteps(advice.steps)
                    : [];
                  const solutionText = status === 'completed'
                    ? (steps.length > 0 ? steps.join(' / ') : aiMissingStepsText)
                    : statusMessage;
                  const evidence = vuln.evidence;
                  const hasEvidence = !!(evidence && (
                    evidence.affected_url ||
                    evidence.path ||
                    evidence.parameter ||
                    evidence.confidence ||
                    evidence.rationale ||
                    evidence.reproduction ||
                    (evidence.request_snippet && evidence.request_snippet.length > 0) ||
                    (evidence.response_snippet && evidence.response_snippet.length > 0)
                  ));
                  const requestSnippet = trimSnippet(evidence?.request_snippet);
                  const responseSnippet = trimSnippet(evidence?.response_snippet);
                  const showSnippet = requestSnippet.length > 0 || responseSnippet.length > 0;

                  return (
                    <div key={`${vuln.id}-${index}`} className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow">
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex items-center space-x-3">
                          <h4 className="text-lg font-semibold text-gray-900">{title}</h4>
                          <span
                            className="px-2 py-1 rounded-full text-xs font-medium text-white"
                            style={{ backgroundColor: severityColors[vuln.severity] }}
                          >
                            {getSeverityLabel(vuln.severity)}
                          </span>
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${getAiStatusTone(status)}`}>
                            {getAiStatusLabel(status)}
                          </span>
                          {vuln.cveId && (
                            <span className="px-2 py-1 bg-gray-100 text-gray-800 rounded text-xs">
                              {vuln.cveId}
                            </span>
                          )}
                        </div>
                        <span className="text-sm text-gray-600">ポート {vuln.port}</span>
                      </div>

                      {status === 'completed' && (
                        <p className="text-xs text-gray-500 mb-2">{AI_GENERAL_LABEL}</p>
                      )}
                      <p className="text-gray-700 mb-3">{description}</p>
                      {status === 'failed' && advice?.error_reason && (
                        <p className="text-xs text-red-600 mb-2">失敗理由: {stripHtml(advice.error_reason)}</p>
                      )}

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

                      {status === 'failed' && (
                        <div className="mt-3">
                          <button
                            onClick={() => handleRetryAdvice(alertKey)}
                            disabled={retryingKey === alertKey}
                            className={`px-3 py-1 rounded-md text-xs font-medium ${
                              retryingKey === alertKey
                                ? 'bg-gray-200 text-gray-500 cursor-not-allowed'
                                : 'bg-red-600 text-white hover:bg-red-700'
                            }`}
                          >
                            {retryingKey === alertKey ? '再試行中...' : '再試行'}
                          </button>
                        </div>
                      )}

                      <div className="mt-4 border-t border-gray-100 pt-4">
                        <div className="flex items-center justify-between mb-3">
                          <p className="font-medium text-gray-900">証拠</p>
                          <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${getConfidenceTone(evidence?.confidence ?? null)}`}>
                            確度: {getConfidenceLabel(evidence?.confidence ?? null)}
                          </span>
                        </div>
                        {!hasEvidence && (
                          <p className="text-sm text-gray-500">証拠情報：未取得（次回スキャンで取得予定）</p>
                        )}
                        {hasEvidence && (
                          <div className="space-y-3 text-sm text-gray-700">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                              <div>
                                <p className="text-xs text-gray-500 mb-1">該当URL</p>
                                <p className="font-medium text-gray-900">{evidence?.affected_url || '未取得'}</p>
                              </div>
                              <div>
                                <p className="text-xs text-gray-500 mb-1">パス</p>
                                <p className="font-medium text-gray-900">{evidence?.path || '未取得'}</p>
                              </div>
                              <div>
                                <p className="text-xs text-gray-500 mb-1">パラメータ</p>
                                <p className="font-medium text-gray-900">{evidence?.parameter || '未取得'}</p>
                              </div>
                              <div>
                                <p className="text-xs text-gray-500 mb-1">メソッド</p>
                                <p className="font-medium text-gray-900">{evidence?.method || '未取得'}</p>
                              </div>
                            </div>
                            <div>
                              <p className="text-xs text-gray-500 mb-1">根拠</p>
                              <p className="text-gray-700">{evidence?.rationale || '未取得'}</p>
                            </div>
                            <div>
                              <p className="text-xs text-gray-500 mb-1">再現手順</p>
                              <p className="text-gray-700">{evidence?.reproduction || '未取得'}</p>
                            </div>
                            {showSnippet && (
                              <details className="rounded-md border border-gray-200 bg-gray-50 px-3 py-2">
                                <summary className="cursor-pointer text-sm font-medium text-gray-700">詳細（リクエスト/レスポンス抜粋）</summary>
                                <div className="mt-2 space-y-3 text-xs text-gray-700">
                                  {requestSnippet.length > 0 && (
                                    <div>
                                      <p className="font-medium text-gray-600 mb-1">Request</p>
                                      <pre className="whitespace-pre-wrap break-words">{requestSnippet.join('\n')}</pre>
                                    </div>
                                  )}
                                  {responseSnippet.length > 0 && (
                                    <div>
                                      <p className="font-medium text-gray-600 mb-1">Response</p>
                                      <pre className="whitespace-pre-wrap break-words">{responseSnippet.join('\n')}</pre>
                                    </div>
                                  )}
                                </div>
                              </details>
                            )}
                          </div>
                        )}
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
                  const alertKey = vuln.alertKey ?? vuln.id;
                  const advice = adviceByKey.get(alertKey) || adviceById.get(vuln.id);
                  const status = advice?.status ?? (isLoadingAdvice ? 'processing' : 'pending');
                  const statusMessage = getAiStatusMessage(status);
                  const title = advice?.title
                    ? normalizeAiText(advice.title)
                    : (vuln.type || '脆弱性項目');
                  const summary = status === 'completed'
                    ? (advice?.summary ? normalizeAiText(advice.summary) : aiMissingSummaryText)
                    : statusMessage;
                  const impact = status === 'completed'
                    ? (advice?.impact ? normalizeAiText(advice.impact) : aiMissingImpactText)
                    : statusMessage;
                  const steps = status === 'completed' && Array.isArray(advice?.steps)
                    ? normalizeAiSteps(advice.steps)
                    : [];
                  const analogyFromAi = status === 'completed' && advice?.analogy ? normalizeAiText(advice.analogy) : '';
                  const analogy = status === 'completed' ? (analogyFromAi || getFallbackAnalogy(vuln.type)) : '';

                  return (
                    <div key={`${vuln.id}-${index}`} className="border-b border-gray-200 pb-8 last:border-b-0 last:pb-0">
                    <div className="flex items-center space-x-3 mb-4">
                      <span className="flex items-center justify-center w-8 h-8 bg-blue-100 text-blue-600 rounded-full font-semibold text-sm">
                        {index + 1}
                      </span>
                      <h4 className="text-xl font-semibold text-gray-900">{title}</h4>
                    </div>
                    
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                      <div>
                        <h5 className="font-semibold text-gray-900 mb-3">技術的解説</h5>
                        {status === 'completed' && (
                          <p className="text-xs text-gray-500 mb-2">{AI_GENERAL_LABEL}</p>
                        )}
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
                            {status === 'completed' ? aiMissingStepsText : statusMessage}
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
