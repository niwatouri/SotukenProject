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
  startScan: (url: string, scanType: 'bulk' | 'detailed', options?: string[]) => Promise<void>;
  clearResults: () => void;
}

const ScanContext = createContext<ScanContextType | undefined>(undefined);

export function ScanProvider({ children }: { children: React.ReactNode }) {
  const [scanResults, setScanResults] = useState<ScanResults | null>(null);
  const [isScanning, setIsScanning] = useState(false);

  const startScan = async (
    url: string,
    scanType: 'bulk' | 'detailed',
    options?: string[]
  ): Promise<void> => {
    setIsScanning(true);

    try {
      const response = await fetch(`${import.meta.env.VITE_API_URL}/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url,
          scanType,
          options,
        }),
      });

      if (!response.ok) {
        throw new Error(`スキャン失敗: ${response.statusText}`);
      }

      const result = await response.json();
      console.log('✅ スキャン開始成功:', result);

      // レポート取得（オプション：必要であれば）
      const reportRes = await fetch(`${import.meta.env.VITE_API_URL}/report`);
      if (!reportRes.ok) {
        throw new Error(`レポート取得失敗: ${reportRes.statusText}`);
      }

      const reportData = await reportRes.json();
      console.log('📄 レポート取得:', reportData);

      // 必要な形式に変換（ZAPレポート形式に応じて調整すること）
      const parsedResult: ScanResults = {
        timestamp: new Date().toISOString(),
        targetUrl: url,
        scanType,
        openPorts: [], // ← ポート情報があるならパースして入れて
        vulnerabilities: [], // ← レポートの内容に合わせてマッピング
        riskScore: 75, // 仮の値
      };

      setScanResults(parsedResult);
    } catch (error) {
      console.error('❌ スキャン中エラー:', error);
      alert('スキャンに失敗しました。もう一度お試しください。');
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
