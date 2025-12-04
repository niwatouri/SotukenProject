import { useEffect, useState } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, Legend } from "recharts";

interface Vulnerability {
  risk: string;
  name: string;
  url: string;
}

export default function Dashboard() {
  const [data, setData] = useState<Vulnerability[]>([]);
  const useRealScanner = import.meta.env.VITE_USE_REAL_SCANNER === "true";
  const apiUrl = import.meta.env.VITE_SCANNER_API_URL;

  useEffect(() => {
    const fetchData = async () => {
      const endpoint = useRealScanner
        ? `${apiUrl}/scan-results`
        : "/mock/scan-results.json"; // モックデータ用
      const res = await fetch(endpoint);
      const json = await res.json();
      setData(json.alerts || []);
    };
    fetchData();
  }, [useRealScanner, apiUrl]);

  // リスク別の件数集計
  const riskCount = data.reduce((acc, v) => {
    acc[v.risk] = (acc[v.risk] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const chartData = Object.entries(riskCount).map(([risk, count]) => ({
    risk,
    count,
  }));

  return (
    <div className="p-4">
      <h1 className="text-2xl font-bold mb-4">ZAP スキャン結果ダッシュボード</h1>
      <BarChart width={500} height={300} data={chartData}>
        <XAxis dataKey="risk" />
        <YAxis />
        <Tooltip />
        <Legend />
        <Bar dataKey="count" fill="#8884d8" />
      </BarChart>
    </div>
  );
}
