import { useState, useEffect } from 'react';

interface Vulnerability {
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  solution: string;
}

interface ScanResults {
  timestamp: string;
  targetUrl: string;
  vulnerabilities: Vulnerability[];
  openPorts: number[];
  riskScore: number;
}

export function useScan() {
  const [scanResults, setScanResults] = useState<ScanResults | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const useRealScanner = import.meta.env.VITE_USE_REAL_SCANNER === 'true';
    const apiUrl = import.meta.env.VITE_SCANNER_API_URL || 'http://localhost:8000/api';

    async function fetchScanResults() {
      try {
        setIsLoading(true);
        if (useRealScanner) {
          // ✅ 実際のスキャナ API から結果を取得
          const res = await fetch(`${apiUrl}/scan/latest`);
          if (!res.ok) throw new Error('Failed to fetch scan results');
          const data = await res.json();
          setScanResults(data);
        } else {
          // 🧪 モックデータ
          setScanResults({
            timestamp: new Date().toISOString(),
            targetUrl: 'https://example.com',
            openPorts: [22, 80, 443],
            riskScore: 74,
            vulnerabilities: [
              {
                type: 'SQL Injection',
                severity: 'critical',
                description: 'ユーザー入力がSQLクエリに直接埋め込まれています。',
                solution: 'プリペアドステートメントを使用してください。'
              },
              {
                type: 'XSS (Reflected)',
                severity: 'high',
                description: 'ユーザー入力がHTMLとして反映される可能性があります。',
                solution: 'HTMLエスケープ処理を追加してください。'
              },
              {
                type: 'Open Redirect',
                severity: 'medium',
                description: 'URLパラメータによって任意のサイトへリダイレクト可能です。',
                solution: '安全なリダイレクト先のホワイトリストを導入してください。'
              }
            ]
          });
        }
      } catch (err: any) {
        setError(err.message);
      } finally {
        setIsLoading(false);
      }
    }

    fetchScanResults();
  }, []);

  return { scanResults, isLoading, error };
}
