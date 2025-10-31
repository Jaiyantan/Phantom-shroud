// Custom React hooks for ML Analytics API
import { useState, useEffect, useCallback } from 'react';

// API base URL - uses environment variable or fallback to localhost
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000';
const API_BASE = `${API_BASE_URL}/api/security/ml`;

/**
 * Generic fetch hook with auto-refresh and error handling
 */
function useFetch(endpoint, refreshInterval = 5000) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastUpdate, setLastUpdate] = useState(null);

  const fetchData = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}${endpoint}`);
      
      if (response.status === 503) {
        // ML not available
        setError({ type: 'unavailable', message: 'ML packages not installed' });
        setLoading(false);
        return;
      }

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const result = await response.json();
      setData(result);
      setError(null);
      setLastUpdate(new Date());
    } catch (err) {
      setError({ type: 'fetch', message: err.message });
    } finally {
      setLoading(false);
    }
  }, [endpoint]);

  useEffect(() => {
    fetchData();
    
    if (refreshInterval && refreshInterval > 0) {
      const interval = setInterval(fetchData, refreshInterval);
      return () => clearInterval(interval);
    }
  }, [fetchData, refreshInterval]);

  return { data, loading, error, lastUpdate, refetch: fetchData };
}

/**
 * Hook for ML statistics
 * GET /api/security/ml/stats
 */
export function useMLStats(refreshInterval = 5000) {
  return useFetch('/stats', refreshInterval);
}

/**
 * Hook for ML status and configuration
 * GET /api/security/ml/status
 */
export function useMLStatus(refreshInterval = 10000) {
  return useFetch('/status', refreshInterval);
}

/**
 * Hook for active flows
 * GET /api/security/ml/flows
 */
export function useMLFlows(refreshInterval = 3000) {
  return useFetch('/flows', refreshInterval);
}

/**
 * Hook for detected threats
 * GET /api/security/ml/threats
 */
export function useMLThreats(refreshInterval = 4000) {
  return useFetch('/threats', refreshInterval);
}

/**
 * Hook for animated number counter
 */
export function useCountUp(target, duration = 1000) {
  const [count, setCount] = useState(0);

  useEffect(() => {
    if (target === undefined || target === null) return;

    let startTime;
    let animationFrame;
    const startValue = count;
    const change = target - startValue;

    const animate = (timestamp) => {
      if (!startTime) startTime = timestamp;
      const progress = Math.min((timestamp - startTime) / duration, 1);
      
      // Easing function (easeOutQuad)
      const easeOut = progress * (2 - progress);
      const currentValue = Math.floor(startValue + change * easeOut);
      
      setCount(currentValue);

      if (progress < 1) {
        animationFrame = requestAnimationFrame(animate);
      } else {
        setCount(target);
      }
    };

    animationFrame = requestAnimationFrame(animate);

    return () => {
      if (animationFrame) {
        cancelAnimationFrame(animationFrame);
      }
    };
  }, [target]);

  return count;
}

/**
 * Hook for formatting bytes to human-readable
 */
export function useFormatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

/**
 * Hook for formatting duration
 */
export function useFormatDuration(seconds) {
  if (!seconds || seconds < 0) return '0s';
  
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);
  
  const parts = [];
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0) parts.push(`${minutes}m`);
  if (secs > 0 || parts.length === 0) parts.push(`${secs}s`);
  
  return parts.join(' ');
}
