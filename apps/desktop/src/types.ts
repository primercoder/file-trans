export interface Status {
  configured: boolean;
  registered: boolean;
  deviceId: string | null;
  name: string | null;
  serverUrl: string | null;
  theme: string;
  locale: string;
}

export interface AccountView {
  id: string;
  serverUrl: string;
  deviceId: string | null;
  name: string | null;
  active: boolean;
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

export interface PeerSecurity {
  deviceId: string;
  safetyNumber: string | null;
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

export interface Conversation {
  peer: string;
  text: string;
  kind: string;
  direction: string;
  ts: number;
}

export interface ShareFile {
  path: string;
  name: string;
}

export interface SharePayload {
  text: string | null;
  files: ShareFile[];
}

export interface PollResult {
  messages: ChatView[];
  devicesChanged: boolean;
}

export interface GroupMember {
  device_id: string;
  name: string;
  role: string;
}

export interface GroupDto {
  group_id: string;
  name: string;
  owner: string;
  members: GroupMember[];
}
