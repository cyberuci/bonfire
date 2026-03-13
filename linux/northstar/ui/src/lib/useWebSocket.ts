import { useEffect, useRef } from "react";
import { useQueryClient } from "@tanstack/react-query";

export function useWebSocket() {
  const queryClient = useQueryClient();
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    let shouldReconnect = true;
    let timeoutId: ReturnType<typeof setTimeout> | undefined = undefined;

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${protocol}//${window.location.host}/api/ws`;

    function connect() {
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type) {
            queryClient.invalidateQueries({ queryKey: [data.type] });
          }
        } catch {
          // ignore parse errors
        }
      };

      ws.onclose = () => {
        if (shouldReconnect) {
          timeoutId = setTimeout(connect, 3000);
        }
      };

      ws.onerror = () => {
        ws.close();
      };
    }

    connect();

    return () => {
      shouldReconnect = false;
      if (timeoutId !== undefined) clearTimeout(timeoutId);
      wsRef.current?.close();
    };
  }, [queryClient]);
}
