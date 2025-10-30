/**
 * ThreatFeed Component
 * Hours 18-20 Implementation
 * 
 * Displays real-time threat alerts
 */

export default function ThreatFeed({ threats = [] }) {
  const getSeverityColor = (severity) => {
    switch (severity?.toUpperCase()) {
      case 'HIGH': return 'bg-red-500'
      case 'MEDIUM': return 'bg-yellow-500'
      case 'LOW': return 'bg-blue-500'
      default: return 'bg-gray-500'
    }
  }

  return (
    <div className="bg-gray-800 rounded-lg shadow-lg p-6">
      <h2 className="text-xl font-bold text-white mb-4">
        🚨 Threat Feed
      </h2>
      
      {threats.length === 0 ? (
        <div className="text-center text-gray-400 py-8">
          No threats detected
        </div>
      ) : (
        <div className="space-y-3 max-h-96 overflow-y-auto">
          {threats.map((threat, index) => (
            <div 
              key={index}
              className="bg-gray-700 rounded p-4 border-l-4 border-red-500"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center">
                  <span className={`${getSeverityColor(threat.severity)} h-2 w-2 rounded-full mr-2`} />
                  <span className="font-bold text-white">{threat.type || 'UNKNOWN'}</span>
                </div>
                <span className="text-sm text-gray-400">
                  {new Date(threat.timestamp).toLocaleTimeString()}
                </span>
              </div>
              {threat.details && (
                <div className="mt-2 text-sm text-gray-300">
                  {threat.details.description || JSON.stringify(threat.details)}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
