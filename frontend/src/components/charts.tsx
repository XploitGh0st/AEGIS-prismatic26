import { Bar, BarChart, CartesianGrid, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis, Cell } from "recharts";
import type { SeverityDistribution, SourceDistribution } from "../types";

const severityPalette: Record<string, string> = {
  critical: "#ff4d6d",
  high: "#ffb020",
  medium: "#27f5ff",
  low: "#8bff3a",
};

export function SeverityChart({ data }: { data: SeverityDistribution }) {
  const chartData = [
    { name: "critical", value: data.critical },
    { name: "high", value: data.high },
    { name: "medium", value: data.medium },
    { name: "low", value: data.low },
  ];

  return (
    <div className="surface-card h-72 rounded-2xl border border-white/10 bg-white/[0.04] p-4">
      <h3 className="panel-title">Severity Distribution</h3>
      <ResponsiveContainer width="100%" height="85%">
        <PieChart>
          <Pie data={chartData} innerRadius={48} outerRadius={78} dataKey="value" nameKey="name" label>
            {chartData.map((entry) => (
              <Cell key={entry.name} fill={severityPalette[entry.name]} />
            ))}
          </Pie>
          <Tooltip />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

export function SourceChart({ data }: { data: SourceDistribution[] }) {
  return (
    <div className="surface-card h-72 rounded-2xl border border-white/10 bg-white/[0.04] p-4">
      <h3 className="panel-title">Alerts by Source</h3>
      <ResponsiveContainer width="100%" height="85%">
        <BarChart data={data}>
          <CartesianGrid strokeDasharray="4 4" stroke="rgba(39,245,255,0.15)" />
          <XAxis dataKey="source" stroke="#9ca3af" />
          <YAxis stroke="#9ca3af" />
          <Tooltip />
          <Bar dataKey="count" radius={[6, 6, 0, 0]} fill="#27f5ff" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}