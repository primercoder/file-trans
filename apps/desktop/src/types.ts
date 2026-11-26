export interface Status {
  configured: boolean;
  registered: boolean;
  deviceId: string | null;
  name: string | null;
  serverUrl: string | null;
  fingerprint: string | null;
}

export interface DeviceInfo {
  device_id: string;
  name: string;
  online: boolean;
  last_seen: number;
}

export interface Peer {
  deviceId: string;
  name: string | null;
  status: string;
}

export interface ChatView {
  peer: string;
  direction: "in" | "out" | "system";
  kind: string;
  text: string;
  fileId: string | null;
  fileName: string | null;
  size: number | null;
  ts: number;
}
