import { createClient } from "@connectrpc/connect";
import { createConnectTransport } from "@connectrpc/connect-web";
import { Northstar } from "../gen/northstar_connect.ts";

// Create the transport
const transport = createConnectTransport({
  baseUrl: window.location.origin, // Assuming the backend serves the frontend
});

// Create the client
export const client = createClient(Northstar, transport);
