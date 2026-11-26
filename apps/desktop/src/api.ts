import { invoke } from "@tauri-apps/api/core";
import type { ChatView, DeviceInfo, GroupDto, Peer, Status } from "./types";

export const api = {
  status: () => invoke<Status>("status"),
  register: (serverUrl: string, fingerprint: string, name: string) =>
    invoke<Status>("register", { serverUrl, fingerprint, name }),
  listDevices: () => invoke<DeviceInfo[]>("list_devices"),
  listPeers: () => invoke<Peer[]>("list_peers"),
  listGroups: () => invoke<GroupDto[]>("list_groups"),
  createGroup: (name: string, members: string[]) => invoke<GroupDto>("create_group", { name, members }),
  sendGroupMessage: (groupId: string, text: string) =>
    invoke<void>("send_group_message", { groupId, text }),
  pair: (peer: string) => invoke<void>("pair", { peer }),
  confirmPair: (peer: string) => invoke<void>("confirm_pair", { peer }),
  rejectPair: (peer: string) => invoke<void>("reject_pair", { peer }),
  sendMessage: (peer: string, text: string) => invoke<void>("send_message", { peer, text }),
  sendFile: (peer: string, path: string) => invoke<string>("send_file", { peer, path }),
  downloadFile: (fileId: string) => invoke<string>("download_file", { fileId }),
  poll: () => invoke<ChatView[]>("poll"),
  history: (peer: string) => invoke<ChatView[]>("history", { peer }),
  exportIdentity: (passphrase: string) => invoke<string>("export_identity", { passphrase }),
  importIdentity: (passphrase: string, blob: string) =>
    invoke<Status>("import_identity", { passphrase, blob }),
};

export function formatSize(bytes: number | null): string {
  if (bytes == null) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

export function shortId(id: string): string {
  return id.slice(0, 8);
}

export function formatTime(ts: number): string {
  const date = new Date(ts * 1000);
  return date.toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit" });
}
