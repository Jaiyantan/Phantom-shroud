/**
 * AlertPanel Component
 * Hours 20-22 Implementation
 * 
 * Toast-style notification panel
 */

export default function AlertPanel({ alerts = [] }) {
  const getAlertColor = (type) => {
    switch (type) {
      case 'success': return 'bg-green-600'
      case 'error': return 'bg-red-600'
      case 'warning': return 'bg-yellow-600'
      default: return 'bg-blue-600'
    }
  }

  return (
    <div className="fixed top-4 right-4 z-50 space-y-2 max-w-sm">
      {alerts.map((alert) => (
        <div
          key={alert.id}
          className={`${getAlertColor(alert.type)} text-white px-6 py-4 rounded-lg shadow-lg transform transition-all duration-300`}
        >
          <div className="font-bold mb-1">
            {alert.type === 'success' && '✓ '}
            {alert.type === 'error' && '✗ '}
            {alert.type === 'warning' && '⚠ '}
            {alert.message}
          </div>
          <div className="text-sm opacity-75">
            {new Date(alert.timestamp).toLocaleTimeString()}
          </div>
        </div>
      ))}
    </div>
  )
}
