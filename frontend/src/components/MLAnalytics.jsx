// MLAnalytics.jsx - Main ML Analytics Dashboard
import { useState, useEffect } from 'react';
import { useMLStats, useMLStatus, useCountUp } from '../utils/mlHooks';
import ThreatChart from './ThreatChart';
import FlowMonitor from './FlowMonitor';
import MLStatus from './MLStatus';

// Stat Card Component with animated counter
const StatCard = ({ title, value, icon, color, subtitle, trend }) => {
  const animatedValue = useCountUp(value);

  return (
    <div className="bg-cyber-card hover:bg-cyber-cardHover border border-cyber-border rounded-xl p-6 
                    transform hover:scale-105 transition-all duration-300 shadow-card hover:shadow-card-hover
                    animate-fade-in">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-gray-400 text-sm font-medium uppercase tracking-wider mb-2">
            {title}
          </p>
          <div className="flex items-baseline gap-2">
            <h3 className={`text-4xl font-bold ${color} animate-counter`}>
              {animatedValue.toLocaleString()}
            </h3>
            {trend && (
              <span className={`text-sm font-semibold ${trend > 0 ? 'text-neon-green' : 'text-neon-red'}`}>
                {trend > 0 ? '↑' : '↓'} {Math.abs(trend)}%
              </span>
            )}
          </div>
          {subtitle && (
            <p className="text-gray-500 text-xs mt-2">{subtitle}</p>
          )}
        </div>
        <div className={`text-4xl ${color} opacity-20`}>
          {icon}
        </div>
      </div>
    </div>
  );
};

// Performance Metric Component
const PerformanceMetric = ({ label, value, max, color }) => {
  const percentage = max > 0 ? Math.min((value / max) * 100, 100) : 0;
  
  return (
    <div className="mb-4">
      <div className="flex justify-between items-center mb-2">
        <span className="text-sm text-gray-400 font-medium">{label}</span>
        <span className={`text-sm font-bold ${color}`}>
          {value.toLocaleString()} / {max.toLocaleString()}
        </span>
      </div>
      <div className="w-full bg-cyber-darker rounded-full h-2.5 overflow-hidden">
        <div 
          className={`h-full rounded-full transition-all duration-700 ease-out ${
            percentage > 80 ? 'bg-gradient-threat' : 
            percentage > 50 ? 'bg-gradient-cyber' : 
            'bg-gradient-success'
          }`}
          style={{ width: `${percentage}%` }}
        />
      </div>
    </div>
  );
};

// Cache Performance Component
const CachePerformance = ({ stats }) => {
  if (!stats) return null;
  
  const hitRate = stats.total > 0 
    ? ((stats.hits / stats.total) * 100).toFixed(1) 
    : 0;

  return (
    <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 animate-slide-up">
      <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
        <span className="text-neon-purple">⚡</span>
        Cache Performance
      </h3>
      
      <div className="grid grid-cols-2 gap-4 mb-4">
        <div className="text-center p-4 bg-cyber-darker rounded-lg">
          <div className="text-3xl font-bold text-neon-green">
            {hitRate}%
          </div>
          <div className="text-xs text-gray-400 mt-1">Hit Rate</div>
        </div>
        <div className="text-center p-4 bg-cyber-darker rounded-lg">
          <div className="text-3xl font-bold text-neon-blue">
            {stats.size || 0}
          </div>
          <div className="text-xs text-gray-400 mt-1">Cache Size</div>
        </div>
      </div>

      <div className="space-y-2">
        <div className="flex justify-between text-sm">
          <span className="text-gray-400">Total Queries</span>
          <span className="text-white font-semibold">{stats.total || 0}</span>
        </div>
        <div className="flex justify-between text-sm">
          <span className="text-gray-400">Cache Hits</span>
          <span className="text-neon-green font-semibold">{stats.hits || 0}</span>
        </div>
        <div className="flex justify-between text-sm">
          <span className="text-gray-400">Cache Misses</span>
          <span className="text-neon-red font-semibold">{stats.misses || 0}</span>
        </div>
      </div>
    </div>
  );
};

// Main MLAnalytics Component
export default function MLAnalytics() {
  const { data: statsData, loading: statsLoading, error: statsError, lastUpdate } = useMLStats(5000);
  const { data: statusData, loading: statusLoading, error: statusError } = useMLStatus(10000);
  
  const [previousStats, setPreviousStats] = useState(null);
  const [trends, setTrends] = useState({});

  useEffect(() => {
    if (statsData && previousStats) {
      const newTrends = {
        analyzed: calculateTrend(statsData.total_analyzed, previousStats.total_analyzed),
        threats: calculateTrend(statsData.threats_detected, previousStats.threats_detected),
      };
      setTrends(newTrends);
    }
    if (statsData) {
      setPreviousStats(statsData);
    }
  }, [statsData]);

  const calculateTrend = (current, previous) => {
    if (!previous || previous === 0) return 0;
    return (((current - previous) / previous) * 100).toFixed(1);
  };

  // Error state - ML not available
  if (statsError?.type === 'unavailable' || statusError?.type === 'unavailable') {
    return (
      <div className="min-h-screen bg-cyber-dark p-6">
        <div className="max-w-4xl mx-auto">
          <div className="bg-cyber-card border border-cyber-border rounded-2xl p-12 text-center animate-scale-in">
            <div className="text-6xl mb-6">🤖</div>
            <h2 className="text-3xl font-bold text-white mb-4">
              ML Analytics Not Available
            </h2>
            <p className="text-gray-400 text-lg mb-6">
              Machine Learning packages are not installed. Install them to enable advanced threat detection.
            </p>
            <div className="bg-cyber-darker rounded-lg p-6 text-left">
              <p className="text-sm text-gray-400 mb-2">Installation command:</p>
              <code className="text-neon-cyan font-mono">
                pip install -r backend/requirements-ml.txt
              </code>
            </div>
            <div className="mt-8">
              <a 
                href="https://github.com/Jaiyantan/Phantom-shroud#ml-based-dpi-optional---phase-4"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-block px-8 py-3 bg-gradient-neon rounded-lg text-white font-semibold
                         hover:shadow-neon transition-all duration-300"
              >
                View Documentation
              </a>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Loading state
  if (statsLoading || statusLoading) {
    return (
      <div className="min-h-screen bg-cyber-dark flex items-center justify-center">
        <div className="text-center">
          <div className="inline-block animate-spin text-6xl text-neon-blue mb-4">⚙️</div>
          <p className="text-gray-400 text-lg">Loading ML Analytics...</p>
        </div>
      </div>
    );
  }

  const stats = statsData || {};
  const status = statusData || {};

  return (
    <div className="min-h-screen bg-cyber-dark p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-8 animate-slide-down">
          <div>
            <h1 className="text-4xl font-bold text-white mb-2 flex items-center gap-3">
              <span className="text-neon-blue">🧠</span>
              ML Analytics Dashboard
            </h1>
            <p className="text-gray-400">
              Real-time machine learning threat detection powered by BERT
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

        {/* ML Status Widget */}
        <MLStatus status={status} />

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <StatCard
            title="Packets Analyzed"
            value={stats.total_analyzed || 0}
            icon="📦"
            color="text-neon-blue"
            subtitle="Total packets processed"
            trend={trends.analyzed}
          />
          <StatCard
            title="Threats Detected"
            value={stats.threats_detected || 0}
            icon="🚨"
            color="text-neon-red"
            subtitle="Malicious packets found"
            trend={trends.threats}
          />
          <StatCard
            title="Active Flows"
            value={stats.active_flows || 0}
            icon="🌊"
            color="text-neon-purple"
            subtitle="Bidirectional connections"
          />
          <StatCard
            title="Queue Size"
            value={stats.queue_size || 0}
            icon="📊"
            color="text-neon-green"
            subtitle="Pending analysis"
          />
        </div>

        {/* Performance Metrics */}
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 animate-fade-in">
          <h3 className="text-xl font-bold text-white mb-6 flex items-center gap-2">
            <span className="text-neon-green">📈</span>
            System Performance
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <PerformanceMetric
                label="Queue Utilization"
                value={stats.queue_size || 0}
                max={1000}
                color="text-neon-cyan"
              />
              <PerformanceMetric
                label="Packets Dropped"
                value={stats.packets_dropped || 0}
                max={stats.total_analyzed || 1}
                color="text-neon-red"
              />
            </div>
            <CachePerformance stats={stats.cache_stats} />
          </div>
        </div>

        {/* Threat Visualization */}
        <ThreatChart />

        {/* Flow Monitor */}
        <FlowMonitor />
      </div>
    </div>
  );
}
