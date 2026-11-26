import { invoke } from "@tauri-apps/api/core";
import type {
  AccountView,
  ChatView,
  DeviceInfo,
  GroupDto,
  Peer,
  PeerSecurity,
  PollResult,
  Status,
} from "./types";

export const api = {
  status: () => invoke<Status>("status"),
  accounts: () => invoke<AccountView[]>("accounts"),
  register: (serverUrl: string, fingerprint: string | null, name: string) =>
    invoke<Status>("register", { serverUrl, fingerprint, name }),
  switchAccount: (id: string) => invoke<Status>("switch_account", { id }),
  deleteAccount: (id: string) => invoke<Status>("delete_account", { id }),
  updatePreferences: (theme: string, locale: string) =>
    invoke<Status>("update_preferences", { theme, locale }),
  listDevices: () => invoke<DeviceInfo[]>("list_devices"),
  listPeers: () => invoke<Peer[]>("list_peers"),
  peerSecurity: (peer: string) => invoke<PeerSecurity>("peer_security", { peer }),
  unpair: (peer: string) => invoke<void>("unpair", { peer }),
  listGroups: () => invoke<GroupDto[]>("list_groups"),
  createGroup: (name: string, members: string[]) => invoke<GroupDto>("create_group", { name, members }),
  sendGroupMessage: (groupId: string, text: string) =>
    invoke<void>("send_group_message", { groupId, text }),
  pair: (peer: string) => invoke<void>("pair", { peer }),
  confirmPair: (peer: string) => invoke<void>("confirm_pair", { peer }),
  rejectPair: (peer: string) => invoke<void>("reject_pair", { peer }),
  sendMessage: (peer: string, text: string) => invoke<void>("send_message", { peer, text }),
  sendFile: (peer: string, path: string) => invoke<string>("send_file", { peer, path }),
  sendFileData: (peer: string, name: string, data: string) =>
    invoke<string>("send_file_data", { peer, name, data }),
  downloadFile: (fileId: string) => invoke<string>("download_file", { fileId }),
  poll: () => invoke<PollResult>("poll"),
  history: (peer: string) => invoke<ChatView[]>("history", { peer }),
};

export function shortId(id: string): string {
  return id.slice(0, 8);
}

export function formatSize(bytes: number | null): string {
  if (bytes == null) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

export function formatTime(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function groupSafety(code: string | null | undefined): string {
  if (!code) return "";
  return (code.match(/.{5}/g) || [code]).join(" ");
}
