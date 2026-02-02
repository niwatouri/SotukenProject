import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { stripHtml } from '../utils/text';
import { useAuth } from './AuthContext';
import { API_BASE_URL } from '../utils/api';

export interface VulnerabilityData {
  id: string;
  alertKey?: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  port: number;
  description: string;
  impact: string;
  solution: string;
  cveId?: string;
  evidence?: {
    affected_url?: string | null;
    path?: string | null;
    parameter?: string | null;
    method?: string | null;
    confidence?: 'high' | 'medium' | 'low' | null;
    rationale?: string | null;
    reproduction?: string | null;
    request_snippet?: string[] | null;
    response_snippet?: string[] | null;
  };
}

export interface ScanResults {
  timestamp: string;
  targetUrl: string;
  scanType: 'bulk' | 'detailed';
  openPorts: number[];
  vulnerabilities: VulnerabilityData[];
  riskScore: number;
  authStatus?: {
    used: boolean;
    method?: string;
    success?: boolean;
    message?: string;
  };
}

export interface ScanHistoryItem {
  id: number;
  target_url: string;
  status: string;
  created_at: string;
  scan_types?: string[];
  job_id?: string;
  started_at?: string | null;
  completed_at?: string | null;
  error?: string | null;
}

export type ScanAuthConfig =
  | {
      method: 'form';
      login_url: string;
      username: string;
      password: string;
      login_indicator?: string;
      username_field?: string;
      password_field?: string;
      extra_params?: string;
      login_request_data?: string;
    }
  | {
      method: 'cookie';
      cookie: string;
    }
  | {
      method: 'header';
      header: string;
    }
  | null;

interface ScanContextType {
  scanResults: ScanResults | null;
  scanId: number | null;
  isScanning: boolean;
  scanProgress: number;
  restoreLatestScan: () => Promise<boolean>;
  loadScanHistory: () => Promise<ScanHistoryItem[]>;
  loadScanById: (scanId: number) => Promise<boolean>;
  startScan: (
    url: string,
    scanTypes?: string[],
    auth?: ScanAuthConfig
  ) => Promise<boolean>;
  clearResults: () => void;
}

const ScanContext = createContext<ScanContextType | undefined>(undefined);
const TOKEN_STORAGE_KEY = 'auth_token';

const isValidScanResults = (data: any): data is ScanResults => {
  return !!data &&
    typeof data.timestamp === 'string' &&
    typeof data.targetUrl === 'string' &&
    typeof data.scanType === 'string' &&
    Array.isArray(data.openPorts) &&
    Array.isArray(data.vulnerabilities) &&
    typeof data.riskScore === 'number';
};

const sanitizeEvidence = (evidence?: VulnerabilityData['evidence']): VulnerabilityData['evidence'] => {
  if (!evidence) {
    return evidence;
  }
  return {
    ...evidence,
    affected_url: evidence.affected_url ? stripHtml(evidence.affected_url) : evidence.affected_url,
    path: evidence.path ? stripHtml(evidence.path) : evidence.path,
    parameter: evidence.parameter ? stripHtml(evidence.parameter) : evidence.parameter,
    method: evidence.method ? stripHtml(evidence.method) : evidence.method,
    rationale: evidence.rationale ? stripHtml(evidence.rationale) : evidence.rationale,
    reproduction: evidence.reproduction ? stripHtml(evidence.reproduction) : evidence.reproduction,
    request_snippet: Array.isArray(evidence.request_snippet)
      ? evidence.request_snippet.map((line) => stripHtml(line))
      : evidence.request_snippet,
    response_snippet: Array.isArray(evidence.response_snippet)
      ? evidence.response_snippet.map((line) => stripHtml(line))
      : evidence.response_snippet,
  };
};

const sanitizeVulnerability = (vulnerability: VulnerabilityData): VulnerabilityData => ({
  ...vulnerability,
  description: stripHtml(vulnerability.description || ''),
  impact: stripHtml(vulnerability.impact || ''),
  solution: stripHtml(vulnerability.solution || ''),
  evidence: sanitizeEvidence(vulnerability.evidence),
});

const sanitizeScanResults = (results: ScanResults): ScanResults => ({
  ...results,
  vulnerabilities: results.vulnerabilities.map(sanitizeVulnerability),
});

export function ScanProvider({ children }: { children: React.ReactNode }) {
  const [scanResults, setScanResults] = useState<ScanResults | null>(null);
  const [scanId, setScanId] = useState<number | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const { logout } = useAuth();

  const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
  const getAuthHeaders = useCallback(() => {
    const token = localStorage.getItem(TOKEN_STORAGE_KEY);
    return token ? { Authorization: `Bearer ${token}` } : {};
  }, []);
  const handleUnauthorized = useCallback((message?: string) => {
    logout();
    if (message) {
      alert(message);
    }
  }, [logout]);

  const restoreLatestScan = useCallback(async (): Promise<boolean> => {
    const token = localStorage.getItem(TOKEN_STORAGE_KEY);
    if (!token) {
      return false;
    }
    try {
      const response = await fetch(`${API_BASE_URL}/scans/latest`, {
        headers: {
          ...getAuthHeaders(),
        },
      });
      if (response.status === 401) {
        handleUnauthorized();
        return false;
      }
      if (response.status === 404) {
        return false;
      }
      if (!response.ok) {
        return false;
      }
      const data = await response.json();
      const parsed = data?.scan?.parsed_report;
      const latestId = data?.scan?.id;
      if (!isValidScanResults(parsed)) {
        return false;
      }
      setScanResults(sanitizeScanResults(parsed));
      if (typeof latestId === 'number') {
        setScanId(latestId);
      }
      return true;
    } catch {
      return false;
    }
  }, [getAuthHeaders, handleUnauthorized]);

  const loadScanHistory = useCallback(async (): Promise<ScanHistoryItem[]> => {
    const token = localStorage.getItem(TOKEN_STORAGE_KEY);
    if (!token) {
      return [];
    }
    try {
      const response = await fetch(`${API_BASE_URL}/scans`, {
        headers: {
          ...getAuthHeaders(),
        },
      });
      if (response.status === 401) {
        handleUnauthorized();
        return [];
      }
      if (!response.ok) {
        return [];
      }
      const data = await response.json();
      if (!Array.isArray(data?.scans)) {
        return [];
      }
      return data.scans as ScanHistoryItem[];
    } catch {
      return [];
    }
  }, [getAuthHeaders, handleUnauthorized]);

  const loadScanById = useCallback(async (scanId: number): Promise<boolean> => {
    const token = localStorage.getItem(TOKEN_STORAGE_KEY);
    if (!token) {
      return false;
    }
    try {
      const response = await fetch(`${API_BASE_URL}/scans/${scanId}`, {
        headers: {
          ...getAuthHeaders(),
        },
      });
      if (response.status === 401) {
        handleUnauthorized();
        return false;
      }
      if (!response.ok) {
        return false;
      }
      const data = await response.json();
      const parsed = data?.scan?.parsed_report;
      if (!isValidScanResults(parsed)) {
        return false;
      }
      setScanResults(sanitizeScanResults(parsed));
      setScanId(scanId);
      return true;
    } catch {
      return false;
    }
  }, [getAuthHeaders, handleUnauthorized]);

  const startScan = async (
    url: string,
    scanTypes?: string[],
    auth?: ScanAuthConfig
  ): Promise<boolean> => {
    setIsScanning(true);
    setScanResults(null);
    setScanId(null);
    setScanProgress(0);

    try {
      const payloadScanTypes = scanTypes && scanTypes.length > 0 ? scanTypes : ['all'];
      const startTime = Date.now();

      const response = await fetch(`${API_BASE_URL}/start-scan/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...getAuthHeaders(),
        },
        body: JSON.stringify({
          url,
          scan_types: payloadScanTypes,
          auth: auth ?? null,
        }),
      });

      if (response.status === 401) {
        handleUnauthorized('セッションが期限切れました。再ログインしてください。');
        return false;
      }
      if (!response.ok) {
        throw new Error(`ジョブ投入に失敗しました: ${response.statusText}`);
      }

      const { job_id: jobId, scan_id: responseScanId } = await response.json();
      if (!jobId) {
        throw new Error('ジョブIDの取得に失敗しました');
      }
      if (typeof responseScanId === 'number') {
        setScanId(responseScanId);
      }

      const maxWaitMs = 60 * 60 * 1000; // 60分まで待機
      const pollIntervalMs = 5000;
      const bumpProgress = (value: number) => {
        setScanProgress(prev => Math.max(prev, Math.min(100, value)));
      };

      while (true) {
        if (Date.now() - startTime > maxWaitMs) {
          throw new Error('スキャンがタイムアウトしました');
        }

        const resultRes = await fetch(`${API_BASE_URL}/scan-result/${jobId}`, {
          headers: {
            ...getAuthHeaders(),
          },
        });
        if (resultRes.status === 401) {
          handleUnauthorized('セッションが期限切れました。再ログインしてください。');
          return false;
        }
        if (!resultRes.ok) {
          throw new Error(`結果取得失敗: ${resultRes.statusText}`);
        }

        const resultData = await resultRes.json();
        const { status, result, error, progress } = resultData;
        if (typeof progress === 'number' && Number.isFinite(progress)) {
          bumpProgress(progress);
        }
        if (typeof progress !== 'number' || !Number.isFinite(progress)) {
          if (status === 'queued') {
            bumpProgress(2);
          } else {
            const elapsed = Date.now() - startTime;
            const estimated = Math.floor((elapsed / maxWaitMs) * 100);
            bumpProgress(Math.min(95, Math.max(5, estimated)));
          }
        }

        if (status === 'finished') {
          if (error) {
            throw new Error(typeof error === 'string' ? error : 'スキャン結果の取得中にエラーが発生しました');
          }
          if (!isValidScanResults(result)) {
            throw new Error('スキャン結果の形式が想定と異なります');
          }
          bumpProgress(100);
          setScanResults(sanitizeScanResults(result));
          return true;
        }

        if (status === 'failed') {
          throw new Error(error || 'スキャンが失敗しました');
        }

        // queued / started などは再ポーリング
        await sleep(pollIntervalMs);
      }
    } catch (error) {
      console.error('❌ スキャン中エラー:', error);
      const message = error instanceof Error ? error.message : 'スキャンに失敗しました。もう一度お試しください。';
      alert(message);
      return false;
    } finally {
      setIsScanning(false);
      setScanProgress(0);
    }

    return false;
  };

  const clearResults = () => {
    setScanResults(null);
    setScanId(null);
  };

  useEffect(() => {
    void restoreLatestScan();
  }, [restoreLatestScan]);

  return (
    <ScanContext.Provider value={{
      scanResults,
      scanId,
      isScanning,
      scanProgress,
      restoreLatestScan,
      loadScanHistory,
      loadScanById,
      startScan,
      clearResults,
    }}>
      {children}
    </ScanContext.Provider>
  );
}

export function useScan() {
  const context = useContext(ScanContext);
  if (context === undefined) {
    throw new Error('useScan must be used within a ScanProvider');
  }
  return context;
}
