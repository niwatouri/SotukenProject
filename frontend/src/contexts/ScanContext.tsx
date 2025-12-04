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
  startScan: (
    url: string,
    scanType: 'bulk' | 'detailed',
    options?: string[]
  ) => Promise<void>;
  clearResults: () => void;
}

const ScanContext = createContext<ScanContextType | undefined>(undefined);

export function ScanProvider({ children }: { children: React.ReactNode }) {
  const [scanResults, setScanResults] = useState<ScanResults | null>(null);
  const [isScanning, setIsScanning] = useState(false);

  // -------------------------------------------------------------
  // 🔁 追加：ジョブ結果ポーリング
  // -------------------------------------------------------------
  const pollJobResult = async (jobId: string) => {
    while (true) {
      const res = await fetch(
        `${import.meta.env.VITE_API_URL}/scan-result/${jobId}`
      );
      const data = await res.json();

      console.log("⏳ ジョブ状態:", data);

      if (data.status === "finished") {
        return data.result;
      }

      // 2秒待つ
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
  };

  // -------------------------------------------------------------
  // 🟦 startScan を非同期ジョブ版に変更
  // -------------------------------------------------------------
  const startScan = async (
    url: string,
    scanType: 'bulk' | 'detailed',
    options?: string[]
  ): Promise<void> => {
    setIsScanning(true);

    try {
      // ① ジョブ開始 API（同期スキャンから置き換え）
      const response = await fetch(`${import.meta.env.VITE_API_URL}/start-scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
      });

      if (!response.ok) {
        throw new Error(`ジョブ開始失敗: ${response.statusText}`);
      }

      const { job_id } = await response.json();
      console.log('🎉 ジョブ開始:', job_id);

      // ② ポーリングして完了を待つ
      const zapResult = await pollJobResult(job_id);
      console.log('📄 ZAP スキャン結果:', zapResult);

      // --- ↓ ここは必要に応じて ZAP レポートに合わせて編集 ---
      const parsedResult: ScanResults = {
        timestamp: new Date().toISOString(),
        targetUrl: url,
        scanType,
        openPorts: [],
        vulnerabilities: [],
        riskScore: 75,
      };
      // -------------------------------------------------------------

      setScanResults(parsedResult);
    } catch (error) {
      console.error('❌ スキャン中エラー:', error);
      alert('スキャンに失敗しました。');
    } finally {
      setIsScanning(false);
    }
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
