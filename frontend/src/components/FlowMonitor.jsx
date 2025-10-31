// FlowMonitor.jsx - Real-time Bidirectional Flow Tracking
import { useState } from 'react';
import { useMLFlows, useFormatBytes, useFormatDuration } from '../utils/mlHooks';

// Flow Direction Indicator
const FlowDirection = ({ forward, backward }) => {
  return (
    <div className="flex items-center gap-2">
      <div className="flex flex-col items-end text-xs">
        <span className="text-neon-green font-semibold">{forward}</span>
        <span className="text-gray-500">forward</span>
      </div>
      <div className="relative">
        <div className="flex flex-col gap-1">
          <div className="flex items-center">
            <div className="w-6 h-0.5 bg-gradient-to-r from-neon-green to-transparent"></div>
            <div className="text-neon-green">▶</div>
          </div>
          <div className="flex items-center">
            <div className="text-neon-blue">◀</div>
            <div className="w-6 h-0.5 bg-gradient-to-l from-neon-blue to-transparent"></div>
          </div>
        </div>
      </div>
      <div className="flex flex-col items-start text-xs">
        <span className="text-neon-blue font-semibold">{backward}</span>
        <span className="text-gray-500">backward</span>
      </div>
    </div>
  );
};

// Individual Flow Card
const FlowCard = ({ flow, index }) => {
  const [expanded, setExpanded] = useState(false);
  
  const totalPackets = (flow.forward_packets || 0) + (flow.backward_packets || 0);
  const totalBytes = (flow.forward_bytes || 0) + (flow.backward_bytes || 0);
  const formattedBytes = useFormatBytes(totalBytes);
  const duration = useFormatDuration(flow.duration || 0);

  const getProtocolColor = (protocol) => {
    const colors = {
      'TCP': 'text-neon-blue',
      'UDP': 'text-neon-purple',
      'ICMP': 'text-neon-yellow',
    };
    return colors[protocol?.toUpperCase()] || 'text-gray-400';
  };

  return (
    <div 
      className="bg-cyber-darker border border-cyber-border rounded-lg p-4 hover:border-cyber-borderLight 
                 transition-all duration-300 animate-slide-up cursor-pointer"
      style={{ animationDelay: `${index * 50}ms` }}
      onClick={() => setExpanded(!expanded)}
    >
      {/* Flow Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <div className="w-2 h-2 rounded-full bg-neon-green animate-pulse shadow-neon-green"></div>
          <div>
            <p className="text-white font-semibold font-mono text-sm">
              {flow.src_ip}:{flow.src_port}
            </p>
            <p className="text-gray-400 text-xs">→ {flow.dst_ip}:{flow.dst_port}</p>
          </div>
        </div>
        <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase ${getProtocolColor(flow.protocol)} 
                         bg-cyber-card`}>
          {flow.protocol || 'UNKNOWN'}
        </span>
      </div>

      {/* Flow Metrics */}
      <div className="grid grid-cols-2 gap-4 mb-3">
        <div className="text-center p-3 bg-cyber-card rounded-lg">
          <div className="text-2xl font-bold text-neon-cyan">{totalPackets}</div>
          <div className="text-xs text-gray-500">Total Packets</div>
        </div>
        <div className="text-center p-3 bg-cyber-card rounded-lg">
          <div className="text-2xl font-bold text-neon-purple">{formattedBytes}</div>
          <div className="text-xs text-gray-500">Total Data</div>
        </div>
      </div>

      {/* Direction Indicator */}
      <div className="flex justify-center mb-3">
        <FlowDirection 
          forward={flow.forward_packets || 0} 
          backward={flow.backward_packets || 0}
        />
      </div>

      {/* Duration */}
      <div className="text-center">
        <span className="text-xs text-gray-500">Duration: </span>
        <span className="text-sm text-neon-green font-semibold">{duration}</span>
      </div>

      {/* Expanded Details */}
      {expanded && (
        <div className="mt-4 pt-4 border-t border-cyber-border space-y-2 animate-slide-down">
          <div className="grid grid-cols-2 gap-2 text-sm">
            <div className="bg-cyber-card p-2 rounded">
              <span className="text-gray-400">Forward Bytes:</span>
              <span className="text-neon-green ml-2 font-semibold">
                {useFormatBytes(flow.forward_bytes || 0)}
              </span>
            </div>
            <div className="bg-cyber-card p-2 rounded">
              <span className="text-gray-400">Backward Bytes:</span>
              <span className="text-neon-blue ml-2 font-semibold">
                {useFormatBytes(flow.backward_bytes || 0)}
              </span>
            </div>
          </div>
          <div className="text-xs text-gray-500 text-center">
            Click to collapse
          </div>
        </div>
      )}
    </div>
  );
};

// Flow Statistics Summary
const FlowSummary = ({ stats }) => {
  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
      <div className="bg-cyber-darker rounded-lg p-4 border border-cyber-border">
        <div className="flex items-center gap-3">
          <div className="text-3xl">🌊</div>
          <div>
            <div className="text-2xl font-bold text-neon-blue">
              {stats.active_flows || 0}
            </div>
            <div className="text-xs text-gray-400">Active Flows</div>
          </div>
        </div>
      </div>
      <div className="bg-cyber-darker rounded-lg p-4 border border-cyber-border">
        <div className="flex items-center gap-3">
          <div className="text-3xl">📊</div>
          <div>
            <div className="text-2xl font-bold text-neon-purple">
              {stats.total_flows || 0}
            </div>
            <div className="text-xs text-gray-400">Total Tracked</div>
          </div>
        </div>
      </div>
      <div className="bg-cyber-darker rounded-lg p-4 border border-cyber-border">
        <div className="flex items-center gap-3">
          <div className="text-3xl">⏱️</div>
          <div>
            <div className="text-2xl font-bold text-neon-green">
              {((stats.avg_duration || 0) / 60).toFixed(1)}m
            </div>
            <div className="text-xs text-gray-400">Avg Duration</div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default function FlowMonitor() {
  const { data: flowsData, loading, error, lastUpdate } = useMLFlows(3000);
  const [filter, setFilter] = useState('all'); // 'all', 'tcp', 'udp'
  const [sortBy, setSortBy] = useState('packets'); // 'packets', 'bytes', 'duration'

  if (loading) {
    return (
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-6">
        <div className="animate-pulse space-y-4">
          <div className="h-6 bg-cyber-darker rounded w-1/4"></div>
          <div className="grid grid-cols-3 gap-4">
            <div className="h-20 bg-cyber-darker rounded"></div>
            <div className="h-20 bg-cyber-darker rounded"></div>
            <div className="h-20 bg-cyber-darker rounded"></div>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-6">
        <p className="text-gray-400">Failed to load flow data</p>
      </div>
    );
  }

  const flows = flowsData?.flows || [];
  const stats = flowsData?.statistics || {};

  // Filter flows
  let filteredFlows = flows;
  if (filter !== 'all') {
    filteredFlows = flows.filter(f => f.protocol?.toLowerCase() === filter);
  }

  // Sort flows
  filteredFlows = [...filteredFlows].sort((a, b) => {
    if (sortBy === 'packets') {
      const aPackets = (a.forward_packets || 0) + (a.backward_packets || 0);
      const bPackets = (b.forward_packets || 0) + (b.backward_packets || 0);
      return bPackets - aPackets;
    } else if (sortBy === 'bytes') {
      const aBytes = (a.forward_bytes || 0) + (a.backward_bytes || 0);
      const bBytes = (b.forward_bytes || 0) + (b.backward_bytes || 0);
      return bBytes - aBytes;
    } else {
      return (b.duration || 0) - (a.duration || 0);
    }
  });

  return (
    <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h3 className="text-2xl font-bold text-white flex items-center gap-2">
            <span className="text-neon-cyan">🌊</span>
            Flow Monitor
          </h3>
          <p className="text-gray-400 text-sm mt-1">
            Bidirectional network flow tracking
          </p>
        </div>
        {lastUpdate && (
          <div className="text-right">
            <p className="text-xs text-gray-500">Last Updated</p>
            <p className="text-sm text-neon-cyan font-mono">
              {lastUpdate.toLocaleTimeString()}
            </p>
          </div>
        )}
      </div>

      {/* Summary Stats */}
      <FlowSummary stats={stats} />

      {/* Controls */}
      <div className="flex flex-wrap gap-4 mb-6">
        {/* Filter */}
        <div className="flex gap-2 bg-cyber-darker rounded-lg p-1">
          {['all', 'tcp', 'udp'].map((filterType) => (
            <button
              key={filterType}
              onClick={() => setFilter(filterType)}
              className={`px-4 py-2 rounded-md text-sm font-medium uppercase transition-all duration-300 ${
                filter === filterType
                  ? 'bg-gradient-neon text-white shadow-neon'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              {filterType}
            </button>
          ))}
        </div>

        {/* Sort */}
        <div className="flex gap-2 bg-cyber-darker rounded-lg p-1">
          {[
            { value: 'packets', label: '📦 Packets' },
            { value: 'bytes', label: '💾 Bytes' },
            { value: 'duration', label: '⏱️ Duration' },
          ].map((sort) => (
            <button
              key={sort.value}
              onClick={() => setSortBy(sort.value)}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-all duration-300 ${
                sortBy === sort.value
                  ? 'bg-gradient-cyber text-white'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              {sort.label}
            </button>
          ))}
        </div>
      </div>

      {/* Flow List */}
      {filteredFlows.length === 0 ? (
        <div className="text-center py-16">
          <div className="text-6xl mb-4">🔍</div>
          <p className="text-gray-400 text-lg">No active flows</p>
          <p className="text-gray-500 text-sm mt-2">
            {filter !== 'all' ? `No ${filter.toUpperCase()} flows detected` : 'Waiting for network activity'}
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 max-h-[600px] overflow-y-auto custom-scrollbar">
          {filteredFlows.map((flow, index) => (
            <FlowCard key={index} flow={flow} index={index} />
          ))}
        </div>
      )}

      {/* Footer */}
      {filteredFlows.length > 0 && (
        <div className="mt-6 pt-4 border-t border-cyber-border text-center">
          <p className="text-sm text-gray-500">
            Showing {filteredFlows.length} of {flows.length} flows
          </p>
        </div>
      )}
    </div>
  );
}
