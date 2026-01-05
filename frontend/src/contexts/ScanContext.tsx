import React, { createContext, useContext, useState } from 'react';

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
  startScan: (
    url: string,
    scanType: 'bulk' | 'detailed',
    scanTypes?: string[],
    auth?: ScanAuthConfig
  ) => Promise<boolean>;
  clearResults: () => void;
}

const ScanContext = createContext<ScanContextType | undefined>(undefined);
const TOKEN_STORAGE_KEY = 'auth_token';
const resolveBaseUrl = (envValue: string | undefined, fallbackPort: number) => {
  const defaultUrl = envValue || `http://localhost:${fallbackPort}`;

  if (typeof window === 'undefined') {
    return defaultUrl.replace(/\/$/, '');
  }

  try {
    const parsed = new URL(defaultUrl);
    const currentHost = window.location.hostname;
    const isLocalHost = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';

    if (isLocalHost && currentHost && currentHost !== parsed.hostname) {
      parsed.hostname = currentHost;
    }

    return parsed.origin;
  } catch {
    return defaultUrl.replace(/\/$/, '');
  }
};

const API_BASE_URL = resolveBaseUrl(import.meta.env.VITE_API_URL, 8000);

export function ScanProvider({ children }: { children: React.ReactNode }) {
  const [scanResults, setScanResults] = useState<ScanResults | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);

  const isValidScanResults = (data: any): data is ScanResults => {
    return !!data &&
      typeof data.timestamp === 'string' &&
      typeof data.targetUrl === 'string' &&
      typeof data.scanType === 'string' &&
      Array.isArray(data.openPorts) &&
      Array.isArray(data.vulnerabilities) &&
      typeof data.riskScore === 'number';
  };

  const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
  const getAuthHeaders = () => {
    const token = localStorage.getItem(TOKEN_STORAGE_KEY);
    return token ? { Authorization: `Bearer ${token}` } : {};
  };

  const startScan = async (
    url: string,
    scanType: 'bulk' | 'detailed',
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
          scan_type: scanType,
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
        const { status, result, error } = resultData;
        if (status === 'queued') {
          bumpProgress(2);
        } else if (status === 'started') {
          bumpProgress(5);
        } else {
          const elapsed = Date.now() - startTime;
          const estimated = Math.floor((elapsed / maxWaitMs) * 100);
          bumpProgress(Math.min(95, estimated));
        }

        if (status === 'finished') {
          if (error) {
            throw new Error(typeof error === 'string' ? error : 'スキャン結果の取得中にエラーが発生しました');
          }
          if (!isValidScanResults(result)) {
            throw new Error('スキャン結果の形式が想定と異なります');
          }
          bumpProgress(100);
          setScanResults(result);
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

  return (
    <ScanContext.Provider value={{ scanResults, isScanning, scanProgress, startScan, clearResults }}>
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
