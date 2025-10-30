import React, { useState, useEffect } from 'react';
import { api } from '../../utils/api';

export default function LiveTraffic() {
  const [flows, setFlows] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isRunning, setIsRunning] = useState(false);

  // Fetch network status and flows
  const fetchData = async () => {
    try {
      const [statusRes, flowsRes] = await Promise.all([
        api.get('/network/status'),
        api.get('/network/flows?limit=20')
      ]);
      
      setStats(statusRes.data);
      setFlows(flowsRes.data.flows || []);
      setIsRunning(statusRes.data.is_running);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching network data:', error);
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 2000); // Update every 2 seconds
    return () => clearInterval(interval);
  }, []);

  const handleStart = async () => {
    try {
      await api.post('/network/start');
      fetchData();
    } catch (error) {
      console.error('Error starting inspection:', error);
    }
  };

  const handleStop = async () => {
    try {
      await api.post('/network/stop');
      fetchData();
    } catch (error) {
      console.error('Error stopping inspection:', error);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header with controls */}
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold text-gray-800">Live Network Traffic</h2>
        <div className="flex gap-2">
          {isRunning ? (
            <button
              onClick={handleStop}
              className="px-4 py-2 bg-red-500 text-white rounded hover:bg-red-600 transition"
            >
              Stop Inspection
            </button>
          ) : (
            <button
              onClick={handleStart}
              className="px-4 py-2 bg-green-500 text-white rounded hover:bg-green-600 transition"
            >
              Start Inspection
            </button>
          )}
        </div>
      </div>

      {/* Statistics Cards */}
      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-white rounded-lg shadow p-4">
            <div className="text-sm text-gray-600">Interface</div>
            <div className="text-2xl font-bold text-blue-600">{stats.interface}</div>
          </div>
          <div className="bg-white rounded-lg shadow p-4">
            <div className="text-sm text-gray-600">Active Flows</div>
            <div className="text-2xl font-bold text-green-600">
              {stats.flows?.active_flows || 0}
            </div>
          </div>
          <div className="bg-white rounded-lg shadow p-4">
            <div className="text-sm text-gray-600">Total Packets</div>
            <div className="text-2xl font-bold text-purple-600">
              {stats.flows?.total_packets || 0}
            </div>
          </div>
          <div className="bg-white rounded-lg shadow p-4">
            <div className="text-sm text-gray-600">Packets/sec</div>
            <div className="text-2xl font-bold text-orange-600">
              {stats.packets_per_second || 0}
            </div>
          </div>
        </div>
      )}

      {/* Flows Table */}
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <div className="px-4 py-3 border-b border-gray-200">
          <h3 className="text-lg font-semibold text-gray-800">Recent Flows</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Source IP
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Destination IP
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Ports
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Protocol
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Packets
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Bytes
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Duration
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {flows.length === 0 ? (
                <tr>
                  <td colSpan="7" className="px-6 py-4 text-center text-gray-500">
                    {isRunning ? 'Waiting for traffic...' : 'Start inspection to see traffic'}
                  </td>
                </tr>
              ) : (
                flows.map((flow, index) => (
                  <tr key={index} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900">
                      {flow.src_ip}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900">
                      {flow.dst_ip}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600">
                      {flow.src_port} → {flow.dst_port}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                        flow.protocol === 'TCP' ? 'bg-blue-100 text-blue-800' :
                        flow.protocol === 'UDP' ? 'bg-green-100 text-green-800' :
                        'bg-gray-100 text-gray-800'
                      }`}>
                        {flow.protocol}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600">
                      {flow.packet_count}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600">
                      {(flow.byte_count / 1024).toFixed(2)} KB
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600">
                      {flow.duration?.toFixed(2)}s
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
