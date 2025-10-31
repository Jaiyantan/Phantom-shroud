// MLStatus.jsx - ML Model Status Widget
import { useState } from 'react';

export default function MLStatus({ status }) {
  const [expanded, setExpanded] = useState(false);

  if (!status || Object.keys(status).length === 0) {
    return null;
  }

  const isAvailable = status.ml_available || false;
  const modelName = status.model_name || 'Unknown';
  const device = status.device || 'CPU';
  const batchSize = status.batch_size || 16;
  const isGPU = device.toLowerCase().includes('cuda') || device.toLowerCase().includes('gpu');

  return (
    <div 
      className="bg-gradient-dark border border-cyber-border rounded-xl p-6 animate-slide-down 
                 cursor-pointer hover:shadow-card-hover transition-all duration-300"
      onClick={() => setExpanded(!expanded)}
    >
      <div className="flex items-center justify-between">
        {/* Left: Status */}
        <div className="flex items-center gap-4">
          <div className="relative">
            <div className={`w-16 h-16 rounded-full flex items-center justify-center text-3xl
                          ${isAvailable ? 'bg-neon-green/20' : 'bg-neon-red/20'}`}>
              {isAvailable ? '🧠' : '⚠️'}
            </div>
            {isAvailable && (
              <div className="absolute -top-1 -right-1 w-5 h-5 bg-neon-green rounded-full 
                            animate-pulse shadow-neon-green flex items-center justify-center">
                <span className="text-xs">✓</span>
              </div>
            )}
          </div>
          
          <div>
            <h3 className="text-xl font-bold text-white mb-1">
              ML Engine Status
            </h3>
            <div className="flex items-center gap-2">
              <span className={`w-2 h-2 rounded-full ${isAvailable ? 'bg-neon-green' : 'bg-neon-red'} 
                              animate-pulse`}></span>
              <span className={`text-sm font-semibold ${isAvailable ? 'text-neon-green' : 'text-neon-red'}`}>
                {isAvailable ? 'ACTIVE' : 'UNAVAILABLE'}
              </span>
            </div>
          </div>
        </div>

        {/* Right: Quick Stats */}
        {isAvailable && (
          <div className="flex items-center gap-6">
            {/* Device Badge */}
            <div className="text-center">
              <div className={`px-4 py-2 rounded-lg font-bold text-lg ${
                isGPU ? 'bg-neon-purple/20 text-neon-purple' : 'bg-neon-blue/20 text-neon-blue'
              }`}>
                {isGPU ? '⚡ GPU' : '💻 CPU'}
              </div>
              <div className="text-xs text-gray-400 mt-1">{device}</div>
            </div>

            {/* Batch Size */}
            <div className="text-center">
              <div className="text-2xl font-bold text-neon-cyan">{batchSize}</div>
              <div className="text-xs text-gray-400">Batch Size</div>
            </div>

            {/* Expand Indicator */}
            <div className={`text-2xl text-gray-400 transition-transform duration-300 ${
              expanded ? 'rotate-180' : ''
            }`}>
              ▼
            </div>
          </div>
        )}
      </div>

      {/* Expanded Details */}
      {expanded && isAvailable && (
        <div className="mt-6 pt-6 border-t border-cyber-border animate-slide-down">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* Model Information */}
            <div className="bg-cyber-card rounded-lg p-4 border border-cyber-border">
              <h4 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
                Model Info
              </h4>
              <div className="space-y-2">
                <div>
                  <span className="text-xs text-gray-500">Model:</span>
                  <p className="text-white font-mono text-sm mt-1 break-all">{modelName}</p>
                </div>
                <div>
                  <span className="text-xs text-gray-500">Type:</span>
                  <p className="text-neon-purple text-sm mt-1">BERT Transformer</p>
                </div>
              </div>
            </div>

            {/* Configuration */}
            <div className="bg-cyber-card rounded-lg p-4 border border-cyber-border">
              <h4 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
                Configuration
              </h4>
              <div className="space-y-2">
                <div className="flex justify-between items-center">
                  <span className="text-gray-400 text-sm">Device:</span>
                  <span className={`font-semibold ${isGPU ? 'text-neon-purple' : 'text-neon-blue'}`}>
                    {device}
                  </span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-400 text-sm">Batch Size:</span>
                  <span className="text-neon-cyan font-semibold">{batchSize}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-400 text-sm">Cache TTL:</span>
                  <span className="text-neon-green font-semibold">60s</span>
                </div>
              </div>
            </div>

            {/* Capabilities */}
            <div className="bg-cyber-card rounded-lg p-4 border border-cyber-border">
              <h4 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
                Capabilities
              </h4>
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <span className="text-neon-green">✓</span>
                  <span className="text-sm text-gray-300">8 Threat Categories</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-neon-green">✓</span>
                  <span className="text-sm text-gray-300">Flow Tracking</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-neon-green">✓</span>
                  <span className="text-sm text-gray-300">Batch Inference</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-neon-green">✓</span>
                  <span className="text-sm text-gray-300">Result Caching</span>
                </div>
              </div>
            </div>
          </div>

          {/* Threat Categories */}
          <div className="mt-6 bg-cyber-card rounded-lg p-4 border border-cyber-border">
            <h4 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
              Detection Categories
            </h4>
            <div className="flex flex-wrap gap-2">
              {['Backdoor', 'Bot', 'DDoS', 'DoS', 'Exploits', 'Shellcode', 'SQL Injection', 'XSS'].map((category, index) => (
                <span 
                  key={category}
                  className="px-3 py-1.5 bg-cyber-darker border border-cyber-border rounded-full 
                           text-xs font-semibold text-neon-cyan hover:border-neon-cyan 
                           transition-all duration-300 cursor-default animate-fade-in"
                  style={{ animationDelay: `${index * 50}ms` }}
                >
                  {category}
                </span>
              ))}
            </div>
          </div>

          {/* Performance Tips */}
          {!isGPU && (
            <div className="mt-4 bg-neon-yellow/10 border border-neon-yellow/30 rounded-lg p-4">
              <div className="flex items-start gap-3">
                <span className="text-2xl">💡</span>
                <div>
                  <h5 className="text-neon-yellow font-semibold mb-1">Performance Tip</h5>
                  <p className="text-sm text-gray-300">
                    Running on CPU. For faster inference, install PyTorch with CUDA support:
                  </p>
                  <code className="block mt-2 text-xs bg-cyber-darker p-2 rounded text-neon-cyan">
                    pip install torch --index-url https://download.pytorch.org/whl/cu118
                  </code>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Unavailable State */}
      {expanded && !isAvailable && (
        <div className="mt-6 pt-6 border-t border-cyber-border animate-slide-down">
          <div className="bg-neon-red/10 border border-neon-red/30 rounded-lg p-6">
            <div className="flex items-start gap-4">
              <span className="text-4xl">⚠️</span>
              <div className="flex-1">
                <h4 className="text-xl font-bold text-neon-red mb-2">ML Engine Not Available</h4>
                <p className="text-gray-300 mb-4">
                  Machine learning packages are not installed. The system is running in rule-based detection mode only.
                </p>
                <div className="bg-cyber-darker rounded-lg p-4 mb-4">
                  <p className="text-sm text-gray-400 mb-2">To enable ML-based threat detection, install:</p>
                  <code className="block text-neon-cyan font-mono text-sm">
                    pip install -r backend/requirements-ml.txt
                  </code>
                </div>
                <a 
                  href="https://github.com/Jaiyantan/Phantom-shroud#ml-based-dpi-optional---phase-4"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-block px-6 py-2 bg-gradient-neon rounded-lg text-white font-semibold
                           hover:shadow-neon transition-all duration-300"
                >
                  📖 View Setup Guide
                </a>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Click hint */}
      <div className="text-center mt-4">
        <p className="text-xs text-gray-500">
          {expanded ? '▲ Click to collapse' : '▼ Click to expand details'}
        </p>
      </div>
    </div>
  );
}
