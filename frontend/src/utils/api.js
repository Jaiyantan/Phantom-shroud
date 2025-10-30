/**
 * API Client Utility
 * Helper functions for API calls
 */

const API_BASE_URL = 'http://localhost:5000/api'

export const api = {
  // Get system status
  getStatus: async () => {
    const response = await fetch(`${API_BASE_URL}/status`)
    return response.json()
  },

  // Get recent threats
  getThreats: async (limit = 10) => {
    const response = await fetch(`${API_BASE_URL}/threats/recent?limit=${limit}`)
    return response.json()
  },

  // Get incidents
  getIncidents: async (limit = 10) => {
    const response = await fetch(`${API_BASE_URL}/threats/incidents?limit=${limit}`)
    return response.json()
  },

  // VPN control
  vpn: {
    connect: async () => {
      const response = await fetch(`${API_BASE_URL}/vpn/connect`, { method: 'POST' })
      return response.json()
    },
    disconnect: async () => {
      const response = await fetch(`${API_BASE_URL}/vpn/disconnect`, { method: 'POST' })
      return response.json()
    },
    getStatus: async () => {
      const response = await fetch(`${API_BASE_URL}/vpn/status`)
      return response.json()
    }
  },

  // Honeypot logs
  getHoneypotLogs: async (limit = 20) => {
    const response = await fetch(`${API_BASE_URL}/honeypot/logs?limit=${limit}`)
    return response.json()
  },

  // Network flows
  getNetworkFlows: async (limit = 10) => {
    const response = await fetch(`${API_BASE_URL}/network/flows?limit=${limit}`)
    return response.json()
  },

  // Summary statistics
  getSummaryStats: async () => {
    const response = await fetch(`${API_BASE_URL}/stats/summary`)
    return response.json()
  }
}

export default api
