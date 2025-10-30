/**
 * Stats Component
 * Hours 20-22 Implementation
 * 
 * Display charts and statistics
 */

export default function Stats() {
  // TODO: Integrate Chart.js for visualizations
  
  return (
    <div className="bg-gray-800 rounded-lg shadow-lg p-6">
      <h2 className="text-xl font-bold text-white mb-4">
        📈 Statistics
      </h2>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Placeholder for Packet Chart */}
        <div className="bg-gray-700 rounded p-4 h-64 flex items-center justify-center">
          <div className="text-gray-400">
            Packet Rate Chart
            <div className="text-sm mt-2">(Chart.js integration pending)</div>
          </div>
        </div>

        {/* Placeholder for Threat Distribution */}
        <div className="bg-gray-700 rounded p-4 h-64 flex items-center justify-center">
          <div className="text-gray-400">
            Threat Distribution
            <div className="text-sm mt-2">(Chart.js integration pending)</div>
          </div>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6">
        <div className="bg-gray-700 rounded p-4 text-center">
          <div className="text-2xl font-bold text-blue-400">0</div>
          <div className="text-sm text-gray-400">Total Threats</div>
        </div>
        <div className="bg-gray-700 rounded p-4 text-center">
          <div className="text-2xl font-bold text-green-400">0</div>
          <div className="text-sm text-gray-400">Incidents</div>
        </div>
        <div className="bg-gray-700 rounded p-4 text-center">
          <div className="text-2xl font-bold text-purple-400">0</div>
          <div className="text-sm text-gray-400">Honeypot Hits</div>
        </div>
        <div className="bg-gray-700 rounded p-4 text-center">
          <div className="text-2xl font-bold text-yellow-400">0</div>
          <div className="text-sm text-gray-400">Unique IPs</div>
        </div>
      </div>
    </div>
  )
}
