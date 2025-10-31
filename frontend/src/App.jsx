import { useState, useEffect } from 'react'
import { io } from 'socket.io-client'
import './App.css'
import NetworkStatus from './components/NetworkStatus'
import ThreatFeed from './components/ThreatFeed'
import VPNControl from './components/VPNControl'
import Stats from './components/Stats'
import AlertPanel from './components/AlertPanel'
import MLAnalytics from './components/MLAnalytics'

function App() {
  const [socket, setSocket] = useState(null)
  const [networkStatus, setNetworkStatus] = useState({})
  const [threats, setThreats] = useState([])
  const [vpnStatus, setVPNStatus] = useState({ connected: false })
  const [alerts, setAlerts] = useState([])
  const [activeTab, setActiveTab] = useState('overview') // 'overview' or 'ml-analytics'

  useEffect(() => {
    // Connect to WebSocket
    try {
      const newSocket = io('http://localhost:5000', {
        reconnection: true,
        reconnectionDelay: 1000,
        reconnectionAttempts: 5
      })
      setSocket(newSocket)

      // Listen for network updates
      newSocket.on('network_update', (data) => {
        setNetworkStatus(data)
      })

      // Listen for threat updates
      newSocket.on('threat_update', (data) => {
        // TODO: Update threats state
      })

      // Handle connection errors gracefully
      newSocket.on('connect_error', (error) => {
        console.log('WebSocket connection error:', error.message)
      })

      // Cleanup on unmount
      return () => newSocket.close()
    } catch (error) {
      console.error('Failed to initialize WebSocket:', error)
    }
  }, [])

  const addAlert = (message, type = 'info') => {
    const alert = {
      id: Date.now(),
      message,
      type,
      timestamp: new Date().toISOString()
    }
    setAlerts(prev => [...prev, alert])
    // Auto-remove after 5 seconds
    setTimeout(() => {
      setAlerts(prev => prev.filter(a => a.id !== alert.id))
    }, 5000)
  }

  return (
    <div className="min-h-screen bg-cyber-dark">
      {/* Header with Navigation */}
      <header className="bg-cyber-card shadow-card border-b border-cyber-border sticky top-0 z-50 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h1 className="text-3xl font-bold text-white flex items-center gap-3">
                <span className="text-neon-blue">🛡️</span>
                <span className="gradient-text">Phantom-shroud</span>
              </h1>
              <p className="text-gray-400 mt-1 text-sm">
                Real-time Network Security & ML-based Threat Detection
              </p>
            </div>
            <div className="flex items-center gap-4">
              <div className="text-right">
                <div className="text-xs text-gray-500">Status</div>
                <div className="flex items-center gap-2 mt-1">
                  <div className="w-2 h-2 rounded-full bg-neon-green animate-pulse"></div>
                  <span className="text-neon-green font-semibold text-sm">ACTIVE</span>
                </div>
              </div>
            </div>
          </div>
          
          {/* Navigation Tabs */}
          <nav className="flex gap-2 bg-cyber-darker rounded-lg p-1">
            <button
              onClick={() => setActiveTab('overview')}
              className={`flex items-center gap-2 px-6 py-3 rounded-md font-medium transition-all duration-300 ${
                activeTab === 'overview'
                  ? 'bg-gradient-cyber text-white shadow-neon'
                  : 'text-gray-400 hover:text-white hover:bg-cyber-card'
              }`}
            >
              <span className="text-xl">📊</span>
              <span>Overview</span>
            </button>
            <button
              onClick={() => setActiveTab('ml-analytics')}
              className={`flex items-center gap-2 px-6 py-3 rounded-md font-medium transition-all duration-300 ${
                activeTab === 'ml-analytics'
                  ? 'bg-gradient-neon text-white shadow-neon-purple'
                  : 'text-gray-400 hover:text-white hover:bg-cyber-card'
              }`}
            >
              <span className="text-xl">🧠</span>
              <span>ML Analytics</span>
              <span className="px-2 py-0.5 bg-neon-purple/20 text-neon-purple rounded-full text-xs font-bold">
                NEW
              </span>
            </button>
          </nav>
        </div>
      </header>

      {/* Main Content - Conditional Rendering */}
      {activeTab === 'overview' ? (
        <main className="max-w-7xl mx-auto py-6 px-4">
          {/* Top Row: Network Status and VPN Control */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
            <div className="lg:col-span-2">
              <NetworkStatus status={networkStatus} />
            </div>
            <div>
              <VPNControl status={vpnStatus} onAlert={addAlert} />
            </div>
          </div>

          {/* Middle Row: Threat Feed */}
          <div className="mb-6">
            <ThreatFeed threats={threats} />
          </div>

          {/* Bottom Row: Statistics */}
          <div>
            <Stats />
          </div>
        </main>
      ) : (
        <MLAnalytics />
      )}

      {/* Alert Panel (Floating) */}
      <AlertPanel alerts={alerts} />
    </div>
  )
}

export default App
