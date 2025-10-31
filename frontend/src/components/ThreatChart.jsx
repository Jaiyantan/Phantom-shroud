// ThreatChart.jsx - Interactive Threat Visualization
import { useEffect, useRef, useState } from 'react';
import { Chart as ChartJS, ArcElement, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend } from 'chart.js';
import { Doughnut, Bar } from 'react-chartjs-2';
import { useMLThreats } from '../utils/mlHooks';

ChartJS.register(ArcElement, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

// Threat category colors
const THREAT_COLORS = {
  'Backdoor': '#ff0040',
  'Bot': '#ff6b00',
  'DDoS': '#ff006e',
  'DoS': '#ffee00',
  'Exploits': '#b24bf3',
  'Shellcode': '#00d4ff',
  'SQL Injection': '#39ff14',
  'XSS': '#00ffff',
};

// Threat severity mapping
const THREAT_SEVERITY = {
  'Backdoor': 'critical',
  'Bot': 'high',
  'DDoS': 'critical',
  'DoS': 'high',
  'Exploits': 'critical',
  'Shellcode': 'critical',
  'SQL Injection': 'high',
  'XSS': 'medium',
};

// Threat List Item
const ThreatItem = ({ threat, index }) => {
  const color = THREAT_COLORS[threat.category] || '#00d4ff';
  const severity = THREAT_SEVERITY[threat.category] || 'medium';
  
  return (
    <div 
      className="flex items-center justify-between p-4 bg-cyber-darker rounded-lg hover:bg-cyber-cardHover 
                 transition-all duration-300 animate-slide-up border border-cyber-border hover:border-cyber-borderLight"
      style={{ animationDelay: `${index * 50}ms` }}
    >
      <div className="flex items-center gap-4 flex-1">
        <div 
          className="w-3 h-3 rounded-full animate-pulse"
          style={{ backgroundColor: color, boxShadow: `0 0 10px ${color}` }}
        />
        <div className="flex-1">
          <h4 className="text-white font-semibold">{threat.category}</h4>
          <p className="text-gray-400 text-sm">{threat.ip || 'Unknown IP'}</p>
        </div>
      </div>
      <div className="flex items-center gap-4">
        <div className="text-center">
          <div className="text-2xl font-bold" style={{ color }}>
            {threat.count}
          </div>
          <div className="text-xs text-gray-500">detections</div>
        </div>
        <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase ${
          severity === 'critical' ? 'bg-threat-critical/20 text-threat-critical' :
          severity === 'high' ? 'bg-threat-high/20 text-threat-high' :
          severity === 'medium' ? 'bg-threat-medium/20 text-threat-medium' :
          'bg-threat-low/20 text-threat-low'
        }`}>
          {severity}
        </span>
      </div>
    </div>
  );
};

export default function ThreatChart() {
  const { data: threatsData, loading, error } = useMLThreats(4000);
  const [chartType, setChartType] = useState('doughnut'); // 'doughnut' or 'bar'
  const [timeSeriesData, setTimeSeriesData] = useState([]);

  useEffect(() => {
    if (threatsData?.threats) {
      // Simulate time series data (in real app, backend would provide this)
      setTimeSeriesData(prev => {
        const newEntry = {
          timestamp: new Date().toLocaleTimeString(),
          count: threatsData.total_threats || 0,
        };
        return [...prev.slice(-19), newEntry]; // Keep last 20 entries
      });
    }
  }, [threatsData]);

  if (loading) {
    return (
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-6">
        <div className="animate-pulse space-y-4">
          <div className="h-6 bg-cyber-darker rounded w-1/4"></div>
          <div className="h-64 bg-cyber-darker rounded"></div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-6">
        <p className="text-gray-400">Failed to load threat data</p>
      </div>
    );
  }

  const threats = threatsData?.threats || [];
  const totalThreats = threatsData?.total_threats || 0;
  const categories = threatsData?.categories || {};

  // Prepare chart data
  const categoryNames = Object.keys(categories);
  const categoryCounts = Object.values(categories);

  const doughnutData = {
    labels: categoryNames,
    datasets: [{
      data: categoryCounts,
      backgroundColor: categoryNames.map(cat => THREAT_COLORS[cat] || '#00d4ff'),
      borderColor: categoryNames.map(cat => THREAT_COLORS[cat] || '#00d4ff'),
      borderWidth: 2,
      hoverBorderWidth: 3,
      hoverOffset: 10,
    }],
  };

  const barData = {
    labels: categoryNames,
    datasets: [{
      label: 'Detections',
      data: categoryCounts,
      backgroundColor: categoryNames.map(cat => `${THREAT_COLORS[cat] || '#00d4ff'}80`),
      borderColor: categoryNames.map(cat => THREAT_COLORS[cat] || '#00d4ff'),
      borderWidth: 2,
    }],
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom',
        labels: {
          color: '#9ca3af',
          padding: 15,
          font: {
            size: 12,
            family: "'Inter', sans-serif",
          },
        },
      },
      tooltip: {
        backgroundColor: '#0f1535',
        titleColor: '#ffffff',
        bodyColor: '#00d4ff',
        borderColor: '#1a2351',
        borderWidth: 1,
        padding: 12,
        displayColors: true,
      },
    },
    animation: {
      animateRotate: true,
      animateScale: true,
      duration: 1000,
      easing: 'easeInOutQuart',
    },
  };

  const barOptions = {
    ...chartOptions,
    scales: {
      y: {
        beginAtZero: true,
        grid: {
          color: '#1a2351',
        },
        ticks: {
          color: '#9ca3af',
        },
      },
      x: {
        grid: {
          display: false,
        },
        ticks: {
          color: '#9ca3af',
        },
      },
    },
  };

  return (
    <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h3 className="text-2xl font-bold text-white flex items-center gap-2">
            <span className="text-neon-red">🎯</span>
            Threat Detection
          </h3>
          <p className="text-gray-400 text-sm mt-1">
            {totalThreats} threats detected across {categoryNames.length} categories
          </p>
        </div>
        
        {/* Chart Type Toggle */}
        <div className="flex gap-2 bg-cyber-darker rounded-lg p-1">
          <button
            onClick={() => setChartType('doughnut')}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-all duration-300 ${
              chartType === 'doughnut'
                ? 'bg-gradient-neon text-white shadow-neon'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            🍩 Doughnut
          </button>
          <button
            onClick={() => setChartType('bar')}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-all duration-300 ${
              chartType === 'bar'
                ? 'bg-gradient-neon text-white shadow-neon'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            📊 Bar
          </button>
        </div>
      </div>

      {totalThreats === 0 ? (
        <div className="text-center py-16">
          <div className="text-6xl mb-4">✨</div>
          <p className="text-gray-400 text-lg">No threats detected yet</p>
          <p className="text-gray-500 text-sm mt-2">Your network is secure</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Chart */}
          <div className="bg-cyber-darker rounded-lg p-6">
            <div className="h-80">
              {chartType === 'doughnut' ? (
                <Doughnut data={doughnutData} options={chartOptions} />
              ) : (
                <Bar data={barData} options={barOptions} />
              )}
            </div>
          </div>

          {/* Threat List */}
          <div className="space-y-3 max-h-96 overflow-y-auto custom-scrollbar">
            {threats.slice(0, 10).map((threat, index) => (
              <ThreatItem key={index} threat={threat} index={index} />
            ))}
            {threats.length > 10 && (
              <div className="text-center py-4 text-gray-500 text-sm">
                +{threats.length - 10} more threats
              </div>
            )}
          </div>
        </div>
      )}

      {/* Category Legend */}
      {categoryNames.length > 0 && (
        <div className="mt-6 pt-6 border-t border-cyber-border">
          <h4 className="text-sm font-semibold text-gray-400 mb-3 uppercase tracking-wider">
            Category Breakdown
          </h4>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {categoryNames.map((category, index) => (
              <div 
                key={category}
                className="flex items-center gap-2 p-3 bg-cyber-darker rounded-lg hover:bg-cyber-cardHover transition-all duration-300"
                style={{ animationDelay: `${index * 100}ms` }}
              >
                <div 
                  className="w-4 h-4 rounded-full"
                  style={{ 
                    backgroundColor: THREAT_COLORS[category],
                    boxShadow: `0 0 8px ${THREAT_COLORS[category]}`
                  }}
                />
                <div className="flex-1 min-w-0">
                  <p className="text-white text-sm font-medium truncate">{category}</p>
                  <p className="text-gray-500 text-xs">{categories[category]} detected</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
