'use client';
import { useEffect, useState } from 'react';
import { securityAPI } from '@/lib/api';
import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from 'recharts';

const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  INFO: '#6b7280',
};

export default function SecurityDashboard() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      try {
        const res = await securityAPI.getDashboard();
        setData(res.data);
      } catch (err) {
        console.error('Failed to load dashboard');
      } finally {
        setLoading(false);
      }
    };
    load();
    const iv = setInterval(load, 30000);
    return () => clearInterval(iv);
  }, []);

  if (loading) return (
    <div className="h-screen bg-gray-950 flex items-center justify-center text-blue-400">
      Loading Security Dashboard...
    </div>
  );

  if (!data) return (
    <div className="h-screen bg-gray-950 flex items-center justify-center text-red-400">
      Failed to load. Make sure you are logged in as admin.
    </div>
  );

  return (
    <div className="min-h-screen bg-gray-950 text-white p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">Security Operations Dashboard</h1>
          <p className="text-gray-400 text-sm">Real-time monitoring · Auto-refresh 30s</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"/>
          <span className="text-green-400 text-sm">LIVE</span>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        {[
          { label: 'Open Alerts', val: data.summary?.open_alerts ?? 0 },
          { label: 'Critical Events 24h', val: data.summary?.critical_events_24h ?? 0 },
          { label: 'Failed Logins 24h', val: data.summary?.failed_logins_24h ?? 0 },
          { label: 'Blocked IPs', val: data.summary?.blocked_ips ?? 0 },
        ].map((c) => (
          <div key={c.label} className="bg-gray-900 border border-gray-800 rounded-lg p-4">
            <div className="text-3xl font-bold text-white">{c.val}</div>
            <div className="text-sm text-gray-500 mt-1">{c.label}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <h3 className="text-sm text-gray-400 mb-3">Event Timeline (24h)</h3>
          <ResponsiveContainer width="100%" height={180}>
            <LineChart data={data.event_timeline || []}>
              <XAxis dataKey="hour" tick={{fill:'#6b7280', fontSize:10}} />
              <YAxis tick={{fill:'#6b7280', fontSize:10}} />
              <Tooltip contentStyle={{background:'#1f2937', border:'1px solid #374151'}} />
              <Line type="monotone" dataKey="count" stroke="#3b82f6" dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <h3 className="text-sm text-gray-400 mb-3">Severity Distribution (7d)</h3>
          <ResponsiveContainer width="100%" height={180}>
            <PieChart>
              <Pie data={data.severity_distribution || []}
                dataKey="count" nameKey="severity"
                cx="50%" cy="50%" outerRadius={70}>
                {(data.severity_distribution || []).map((e: any) => (
                  <Cell key={e.severity} fill={SEV_COLORS[e.severity] || '#6b7280'} />
                ))}
              </Pie>
              <Tooltip />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 mb-6">
        <h3 className="text-sm text-gray-400 mb-3">Top Event Types (24h)</h3>
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={data.events_by_type || []} layout="vertical">
            <XAxis type="number" tick={{fill:'#6b7280', fontSize:10}} />
            <YAxis type="category" dataKey="event_type"
              tick={{fill:'#6b7280', fontSize:10}} width={180} />
            <Tooltip contentStyle={{background:'#1f2937', border:'1px solid #374151'}} />
            <Bar dataKey="count" fill="#3b82f6" />
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
        <h3 className="text-sm text-gray-400 mb-3">Top Suspicious IPs (24h)</h3>
        <div className="space-y-2">
          {(data.top_suspicious_ips || []).length === 0 && (
            <p className="text-gray-600 text-sm">No suspicious IPs detected</p>
          )}
          {(data.top_suspicious_ips || []).map((item: any, idx: number) => (
            <div key={idx} className="flex items-center justify-between bg-gray-800 p-2 rounded">
              <span className="font-mono text-sm text-red-300">{item.ip_address}</span>
              <span className="text-sm text-gray-400">{item.count} events</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
