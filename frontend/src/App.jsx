import { useState, useEffect } from 'react'
import { io } from 'socket.io-client'
import './App.css'
import NetworkStatus from './components/NetworkStatus'
import ThreatFeed from './components/ThreatFeed'
import VPNControl from './components/VPNControl'
import Stats from './components/Stats'
import AlertPanel from './components/AlertPanel'

function App() {
  const [socket, setSocket] = useState(null)
  const [networkStatus, setNetworkStatus] = useState({})
  const [threats, setThreats] = useState([])
  const [vpnStatus, setVPNStatus] = useState({ connected: false })
  const [alerts, setAlerts] = useState([])

  useEffect(() => {
    // Connect to WebSocket
    const newSocket = io('http://localhost:5000')
    setSocket(newSocket)

    // Listen for network updates
    newSocket.on('network_update', (data) => {
      setNetworkStatus(data)
    })

    // Listen for threat updates
    newSocket.on('threat_update', (data) => {
      // TODO: Update threats state
    })

    // Cleanup on unmount
    return () => newSocket.close()
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
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 shadow-lg">
        <div className="max-w-7xl mx-auto py-6 px-4">
          <h1 className="text-3xl font-bold text-white">
            🛡️ Phantom-shroud Dashboard
          </h1>
          <p className="text-gray-400 mt-2">
            24-Hour Hackathon MVP - Real-time Network Security Monitoring
          </p>
        </div>
      </header>

      {/* Main Content */}
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

      {/* Alert Panel (Floating) */}
      <AlertPanel alerts={alerts} />
    </div>
  )
}

export default App
