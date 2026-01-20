import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { resolveBaseUrl } from '../utils/url';
import { stripHtml } from '../utils/text';

export interface VulnerabilityData {
  id: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  port: number;
  description: string;
  impact: string;
  solution: string;
  cveId?: string;
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
const API_BASE_URL = resolveBaseUrl(import.meta.env.VITE_API_URL, '/api');

const isValidScanResults = (data: any): data is ScanResults => {
  return !!data &&
    typeof data.timestamp === 'string' &&
    typeof data.targetUrl === 'string' &&
    typeof data.scanType === 'string' &&
    Array.isArray(data.openPorts) &&
    Array.isArray(data.vulnerabilities) &&
    typeof data.riskScore === 'number';
};

const sanitizeVulnerability = (vulnerability: VulnerabilityData): VulnerabilityData => ({
  ...vulnerability,
  description: stripHtml(vulnerability.description || ''),
  impact: stripHtml(vulnerability.impact || ''),
  solution: stripHtml(vulnerability.solution || ''),
});

const sanitizeScanResults = (results: ScanResults): ScanResults => ({
  ...results,
  vulnerabilities: results.vulnerabilities.map(sanitizeVulnerability),
});

export function ScanProvider({ children }: { children: React.ReactNode }) {
  const [scanResults, setScanResults] = useState<ScanResults | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);

  const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
  const getAuthHeaders = useCallback(() => {
    const token = localStorage.getItem(TOKEN_STORAGE_KEY);
    return token ? { Authorization: `Bearer ${token}` } : {};
  }, []);

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
      if (response.status === 404) {
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
      return true;
    } catch {
      return false;
    }
  }, [getAuthHeaders]);

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
  }, [getAuthHeaders]);

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
      if (!response.ok) {
        return false;
      }
      const data = await response.json();
      const parsed = data?.scan?.parsed_report;
      if (!isValidScanResults(parsed)) {
        return false;
      }
      setScanResults(sanitizeScanResults(parsed));
      return true;
    } catch {
      return false;
    }
  }, [getAuthHeaders]);

  const startScan = async (
    url: string,
    scanTypes?: string[],
    auth?: ScanAuthConfig
  ): Promise<boolean> => {
    setIsScanning(true);
    setScanResults(null);
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

      if (!response.ok) {
        throw new Error(`ジョブ投入に失敗しました: ${response.statusText}`);
      }

      const { job_id: jobId } = await response.json();
      if (!jobId) {
        throw new Error('ジョブIDの取得に失敗しました');
      }

      console.log('✅ スキャンジョブ投入:', jobId);

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
  };

  useEffect(() => {
    void restoreLatestScan();
  }, [restoreLatestScan]);

  return (
    <ScanContext.Provider value={{
      scanResults,
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
