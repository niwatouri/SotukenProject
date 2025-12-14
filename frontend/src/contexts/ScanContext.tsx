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
}

interface ScanContextType {
  scanResults: ScanResults | null;
  isScanning: boolean;
  startScan: (url: string, scanType: 'bulk' | 'detailed', scanTypes?: string[]) => Promise<boolean>;
  clearResults: () => void;
}

const ScanContext = createContext<ScanContextType | undefined>(undefined);

export function ScanProvider({ children }: { children: React.ReactNode }) {
  const [scanResults, setScanResults] = useState<ScanResults | null>(null);
  const [isScanning, setIsScanning] = useState(false);

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

  const startScan = async (
    url: string,
    scanType: 'bulk' | 'detailed',
    scanTypes?: string[]
  ): Promise<boolean> => {
    setIsScanning(true);
    setScanResults(null);

    try {
      const payloadScanTypes = scanTypes && scanTypes.length > 0 ? scanTypes : ['all'];

      const response = await fetch(`${import.meta.env.VITE_API_URL}/start-scan/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url,
          scan_type: scanType,
          scan_types: payloadScanTypes,
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

      const maxWaitMs = 20 * 60 * 1000; // 20分まで待機
      const pollIntervalMs = 5000;
      const startTime = Date.now();

      while (true) {
        if (Date.now() - startTime > maxWaitMs) {
          throw new Error('スキャンがタイムアウトしました');
        }

        const resultRes = await fetch(`${import.meta.env.VITE_API_URL}/scan-result/${jobId}`);
        if (!resultRes.ok) {
          throw new Error(`結果取得失敗: ${resultRes.statusText}`);
        }

        const resultData = await resultRes.json();
        const { status, result, error } = resultData;

        if (status === 'finished') {
          if (error) {
            throw new Error(typeof error === 'string' ? error : 'スキャン結果の取得中にエラーが発生しました');
          }
          if (!isValidScanResults(result)) {
            throw new Error('スキャン結果の形式が想定と異なります');
          }
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
    }

    return false;
  };

  const clearResults = () => {
    setScanResults(null);
  };

  return (
    <ScanContext.Provider value={{ scanResults, isScanning, startScan, clearResults }}>
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
