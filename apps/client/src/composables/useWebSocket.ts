import { ref, onMounted, onUnmounted } from 'vue';
import type { HookEvent, WebSocketMessage } from '../types';

export function useWebSocket(url: string) {
  const events = ref<HookEvent[]>([]);
  const isConnected = ref(false);
  const error = ref<string | null>(null);

  let ws: WebSocket | null = null;
  let reconnectTimeout: number | null = null;
  let reconnectAttempts = 0;
  let isCleaningUp = false;

  // Get max events from environment variable or use default
  const maxEvents = parseInt(import.meta.env.VITE_MAX_EVENTS_TO_DISPLAY || '300');

  // Exponential backoff for reconnection (max 30 seconds)
  const getReconnectDelay = () => Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);

  const connect = () => {
    // Prevent connection if cleaning up
    if (isCleaningUp) return;

    // Prevent multiple simultaneous connections
    if (ws && (ws.readyState === WebSocket.CONNECTING || ws.readyState === WebSocket.OPEN)) {
      return;
    }

    try {
      ws = new WebSocket(url);

      ws.onopen = () => {
        console.log('WebSocket connected');
        isConnected.value = true;
        error.value = null;
        reconnectAttempts = 0; // Reset on successful connection
      };

      ws.onmessage = (event) => {
        try {
          const message: WebSocketMessage = JSON.parse(event.data);

          if (message.type === 'initial') {
            const initialEvents = Array.isArray(message.data) ? message.data : [];
            // Only keep the most recent events up to maxEvents
            events.value = initialEvents.slice(-maxEvents);
          } else if (message.type === 'event') {
            const newEvent = message.data as HookEvent;
            events.value.push(newEvent);

            // Limit events array to maxEvents, removing the oldest when exceeded
            if (events.value.length > maxEvents) {
              // Remove the oldest events (first 10) when limit is exceeded
              events.value = events.value.slice(events.value.length - maxEvents + 10);
            }
          }
        } catch (err) {
          console.error('Failed to parse WebSocket message:', err);
        }
      };

      ws.onerror = (err) => {
        console.error('WebSocket error:', err);
        error.value = 'WebSocket connection error';
      };

      ws.onclose = () => {
        console.log('WebSocket disconnected');
        isConnected.value = false;

        // Don't reconnect if cleaning up
        if (isCleaningUp) return;

        // Exponential backoff for reconnection
        reconnectAttempts++;
        const delay = getReconnectDelay();
        console.log(`Attempting to reconnect in ${delay/1000}s (attempt ${reconnectAttempts})...`);

        reconnectTimeout = window.setTimeout(() => {
          connect();
        }, delay);
      };
    } catch (err) {
      console.error('Failed to connect:', err);
      error.value = 'Failed to connect to server';
    }
  };
  
  const disconnect = () => {
    isCleaningUp = true;

    if (reconnectTimeout) {
      clearTimeout(reconnectTimeout);
      reconnectTimeout = null;
    }

    if (ws) {
      ws.close();
      ws = null;
    }
  };
  
  onMounted(() => {
    connect();
  });
  
  onUnmounted(() => {
    disconnect();
  });

  const clearEvents = () => {
    events.value = [];
  };

  return {
    events,
    isConnected,
    error,
    clearEvents
  };
}