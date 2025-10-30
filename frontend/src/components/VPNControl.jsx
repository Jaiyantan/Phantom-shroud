/**
 * VPNControl Component
 * Hours 18-20 Implementation
 * 
 * VPN connection control interface
 */

import { useState } from 'react'

export default function VPNControl({ status = {}, onAlert }) {
  const [connecting, setConnecting] = useState(false)

  const handleConnect = async () => {
    setConnecting(true)
    try {
      const response = await fetch('/api/vpn/connect', { method: 'POST' })
      const data = await response.json()
      onAlert?.(data.message, data.success ? 'success' : 'error')
    } catch (error) {
      onAlert?.('Failed to connect to VPN', 'error')
    } finally {
      setConnecting(false)
    }
  }

  const handleDisconnect = async () => {
    setConnecting(true)
    try {
      const response = await fetch('/api/vpn/disconnect', { method: 'POST' })
      const data = await response.json()
      onAlert?.(data.message, data.success ? 'success' : 'error')
    } catch (error) {
      onAlert?.('Failed to disconnect from VPN', 'error')
    } finally {
      setConnecting(false)
    }
  }

  return (
    <div className="bg-gray-800 rounded-lg shadow-lg p-6">
      <h2 className="text-xl font-bold text-white mb-4">
        🔐 VPN Control
      </h2>
      
      <div className="text-center">
        {/* Status */}
        <div className="mb-4">
          <div className={`inline-flex items-center px-4 py-2 rounded-full ${
            status.connected ? 'bg-green-500' : 'bg-gray-700'
          }`}>
            <span className={`h-3 w-3 rounded-full mr-2 ${
              status.connected ? 'bg-white' : 'bg-gray-500'
            }`} />
            <span className="text-white font-bold">
              {status.connected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
        </div>

        {/* Control Button */}
        <button
          onClick={status.connected ? handleDisconnect : handleConnect}
          disabled={connecting}
          className={`w-full py-3 px-6 rounded-lg font-bold transition-colors ${
            status.connected
              ? 'bg-red-600 hover:bg-red-700 text-white'
              : 'bg-green-600 hover:bg-green-700 text-white'
          } ${connecting ? 'opacity-50 cursor-not-allowed' : ''}`}
        >
          {connecting ? 'Processing...' : (status.connected ? 'Disconnect' : 'Connect')}
        </button>

        {/* Kill Switch Indicator */}
        {status.kill_switch && (
          <div className="mt-4 text-sm text-yellow-400">
            🛡️ Kill Switch Active
          </div>
        )}
      </div>
    </div>
  )
}
