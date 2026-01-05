import type { ScanResults, VulnerabilityData } from '../contexts/ScanContext';

export type RiskLevel = 'high' | 'medium' | 'low';
export type PriorityLevel = 'high' | 'medium' | 'low';

export interface Recommendation {
  priority: PriorityLevel;
  title: string;
  description: string;
  impact: string;
}

export interface AnalysisData {
  overallRisk: RiskLevel;
  criticalIssues: number;
  mediumIssues: number;
  mostCritical?: VulnerabilityData;
  recommendations: Recommendation[];
}

const RECOMMENDATIONS: Recommendation[] = [
  {
    priority: 'high',
    title: 'SQL インジェクション対策の実装',
    description: 'パラメータ化クエリの使用と入力値検証の徹底',
    impact: 'データベースへの不正アクセスを防止',
  },
  {
    priority: 'high',
    title: 'XSS 対策の強化',
    description: 'CSP ヘッダーの設定と出力値のエスケープ処理',
    impact: 'クロスサイトスクリプティング攻撃を防止',
  },
  {
    priority: 'medium',
    title: 'SSL/TLS 設定の最適化',
    description: '弱い暗号化スイートの無効化と最新プロトコルの採用',
    impact: '通信の暗号化強度を向上',
  },
];

export const getAnalysisData = (scanResults: ScanResults): AnalysisData => {
  const highRiskVulns = scanResults.vulnerabilities.filter(
    (v) => v.severity === 'critical' || v.severity === 'high',
  );

  const mediumRiskVulns = scanResults.vulnerabilities.filter(
    (v) => v.severity === 'medium',
  );

  return {
    overallRisk: scanResults.riskScore > 70 ? 'high' : scanResults.riskScore > 40 ? 'medium' : 'low',
    criticalIssues: highRiskVulns.length,
    mediumIssues: mediumRiskVulns.length,
    mostCritical: highRiskVulns[0] || mediumRiskVulns[0],
    recommendations: RECOMMENDATIONS,
  };
};

export const getRiskColor = (risk: string) => {
  switch (risk) {
    case 'high':
      return 'text-red-600 bg-red-50 border-red-200';
    case 'medium':
      return 'text-orange-600 bg-orange-50 border-orange-200';
    case 'low':
      return 'text-green-600 bg-green-50 border-green-200';
    default:
      return 'text-gray-600 bg-gray-50 border-gray-200';
  }
};

export const getPriorityColor = (priority: string) => {
  switch (priority) {
    case 'high':
      return 'bg-red-500';
    case 'medium':
      return 'bg-orange-500';
    case 'low':
      return 'bg-yellow-500';
    default:
      return 'bg-gray-500';
  }
};
