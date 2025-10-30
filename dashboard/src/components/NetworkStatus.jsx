/**
 * NetworkStatus Component
 * Hours 18-20 Implementation
 * 
 * Displays real-time network statistics
 */

export default function NetworkStatus({ status = {} }) {
  const {
    packet_count = 0,
    flow_count = 0,
    packets_per_second = 0,
    interface: iface = 'N/A',
    is_running = false
  } = status

  return (
    <div className="bg-gray-800 rounded-lg shadow-lg p-6">
      <h2 className="text-xl font-bold text-white mb-4">
        📊 Network Status
      </h2>
      
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {/* Status Indicator */}
        <div className="col-span-2 md:col-span-4 flex items-center">
          <span className={`h-3 w-3 rounded-full mr-2 ${is_running ? 'bg-green-500' : 'bg-red-500'}`} />
          <span className="text-gray-300">
            {is_running ? 'Active' : 'Inactive'}
          </span>
        </div>

        {/* Packet Count */}
        <div className="bg-gray-700 rounded p-4">
          <div className="text-2xl font-bold text-blue-400">{packet_count.toLocaleString()}</div>
          <div className="text-sm text-gray-400">Packets</div>
        </div>

        {/* Flow Count */}
        <div className="bg-gray-700 rounded p-4">
          <div className="text-2xl font-bold text-green-400">{flow_count.toLocaleString()}</div>
          <div className="text-sm text-gray-400">Flows</div>
        </div>

        {/* Packets per Second */}
        <div className="bg-gray-700 rounded p-4">
          <div className="text-2xl font-bold text-purple-400">{packets_per_second.toFixed(1)}</div>
          <div className="text-sm text-gray-400">Packets/sec</div>
        </div>

        {/* Interface */}
        <div className="bg-gray-700 rounded p-4">
          <div className="text-2xl font-bold text-yellow-400">{iface}</div>
          <div className="text-sm text-gray-400">Interface</div>
        </div>
      </div>
    </div>
  )
}
