<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { open } from "@tauri-apps/plugin-dialog";
import { isPermissionGranted, requestPermission } from "@tauri-apps/plugin-notification";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { listen } from "@tauri-apps/api/event";
import { api, groupSafety, shortId } from "./api";
import { translate } from "./i18n";
import type {
  AccountView,
  ChatView,
  Conversation,
  DeviceInfo,
  GroupDto,
  Peer,
  SharePayload,
  Status,
} from "./types";
import Onboarding from "./components/Onboarding.vue";
import MessageItem from "./components/MessageItem.vue";
import SettingsSheet from "./components/SettingsSheet.vue";
import AddContact from "./components/AddContact.vue";

type Locale = "zh" | "en";

const status = ref<Status | null>(null);
const accounts = ref<AccountView[]>([]);
const peers = ref<Peer[]>([]);
const devices = ref<DeviceInfo[]>([]);
const groups = ref<GroupDto[]>([]);
const messages = ref<ChatView[]>([]);
const activeId = ref<string | null>(null);
const pending = ref<{ peer: string; name: string }[]>([]);
const input = ref("");
const busy = ref(false);
const sendingFile = ref(false);
const downloading = ref<string | null>(null);
const toast = ref("");
const fatal = ref("");
const showSettings = ref(false);
const showAdd = ref(false);
const showOnboarding = ref(false);
const onboardingServer = ref("");
const showGroup = ref(false);
const groupName = ref("");
const groupMembers = ref<string[]>([]);
const security = ref<{ peer: string; code: string | null } | null>(null);
const confirming = ref<{ peer: string; name: string } | null>(null);
const isMobile = ref(false);
const dragOver = ref(false);
const scroller = ref<HTMLElement | null>(null);
const fileInput = ref<HTMLInputElement | null>(null);
const conversations = ref<Record<string, Conversation>>({});
const pendingShare = ref<SharePayload | null>(null);
const shareBusy = ref(false);
const lastRead = ref<Record<string, number>>({});
const nameCache = ref<Record<string, string>>({});

let timer: number | undefined;
let polling = false;
let pollFailures = 0;
let lastToastAt = 0;

const locale = computed<Locale>(() => (status.value?.locale === "en" ? "en" : "zh"));
const t = (key: string, vars?: Record<string, string | number>) => translate(locale.value, key, vars);

const deviceMap = computed(() => {
  const map: Record<string, DeviceInfo> = {};
  for (const device of devices.value) map[device.device_id] = device;
  return map;
});

const activeGroup = computed(() => groups.value.find((group) => group.group_id === activeId.value) ?? null);
const activePeer = computed(() => {
  if (!activeId.value || activeGroup.value) return null;
  return peers.value.find((peer) => peer.deviceId === activeId.value) ?? null;
});

function peerName(id: string): string {
  return deviceMap.value[id]?.name || nameCache.value[id] || shortId(id);
}

const contactRows = computed(() =>
  peers.value
    .filter((peer) => peer.status !== "pending_accept")
    .map((peer) => {
      const device = deviceMap.value[peer.deviceId];
      const conversation = conversations.value[peer.deviceId];
      const paired = peer.status === "paired";
      const archived = peer.status === "removed" || peer.status === "deleted";
      const statusLabel = peer.status === "deleted"
        ? t("list.deleted")
        : peer.status === "removed"
          ? t("list.removed")
          : paired
            ? device?.online
              ? t("list.online")
              : t("list.offline")
            : t("pair.waiting");
      return {
        id: peer.deviceId,
        title: peerName(peer.deviceId),
        subtitle: archived && !conversation ? statusLabel : previewOf(conversation) || statusLabel,
        badge: peer.status === "deleted"
          ? t("list.deleted")
          : peer.status === "removed"
            ? t("list.removed")
            : paired
              ? t("list.friend")
              : t("list.pending"),
        archived,
        online: Boolean(device?.online && paired),
        ts: conversation?.ts ?? 0,
        unread: Boolean(
          conversation &&
            conversation.direction === "in" &&
            conversation.ts * 1000 > (lastRead.value[peer.deviceId] ?? 0),
        ),
      };
    }),
);

const pairedContacts = computed(() =>
  contactRows.value.filter(
    (row) => peers.value.find((peer) => peer.deviceId === row.id)?.status === "paired",
  ),
);

const groupRows = computed(() =>
  groups.value.map((group) => {
    const conversation = conversations.value[group.group_id];
    return {
      id: group.group_id,
      title: group.name,
      subtitle: previewOf(conversation) || t("list.members", { n: group.members.length }),
      badge: t("list.group"),
      archived: false,
      online: false,
      ts: conversation?.ts ?? 0,
      unread: Boolean(
        conversation &&
          conversation.direction === "in" &&
          conversation.ts * 1000 > (lastRead.value[group.group_id] ?? 0),
      ),
    };
  }),
);

const rows = computed(() =>
  [...contactRows.value, ...groupRows.value].sort((left, right) => right.ts - left.ts),
);
const isEmpty = computed(() => !pending.value.length && !rows.value.length);

const activeTitle = computed(() => {
  if (activeGroup.value) return activeGroup.value.name;
  if (activeId.value) return peerName(activeId.value);
  return "";
});

const activeSubtitle = computed(() => {
  if (activeGroup.value) return t("list.members", { n: activeGroup.value.members.length });
  if (!activePeer.value) return "";
  if (activePeer.value.status === "deleted") return t("list.deleted");
  if (activePeer.value.status === "removed") return t("list.removed");
  if (activePeer.value.status !== "paired") return t("pair.waiting");
  return deviceMap.value[activePeer.value.deviceId]?.online ? t("list.online") : t("list.offline");
});

function readStoreKey(): string {
  return `kite.lastRead.${status.value?.deviceId ?? "unknown"}`;
}

function namesStoreKey(): string {
  return `kite.names.${status.value?.deviceId ?? "unknown"}`;
}

function loadNameCache() {
  try {
    nameCache.value = JSON.parse(localStorage.getItem(namesStoreKey()) ?? "{}");
  } catch {
    nameCache.value = {};
  }
}

function rememberNames(devices: DeviceInfo[]) {
  let changed = false;
  const next = { ...nameCache.value };
  for (const device of devices) {
    if (device.name && next[device.device_id] !== device.name) {
      next[device.device_id] = device.name;
      changed = true;
    }
  }
  if (changed) {
    nameCache.value = next;
    try {
      localStorage.setItem(namesStoreKey(), JSON.stringify(next));
    } catch {
      // best effort
    }
  }
}

function loadLastRead() {
  try {
    lastRead.value = JSON.parse(localStorage.getItem(readStoreKey()) ?? "{}");
  } catch {
    lastRead.value = {};
  }
}

function markRead(peer: string) {
  lastRead.value = { ...lastRead.value, [peer]: Date.now() };
  try {
    localStorage.setItem(readStoreKey(), JSON.stringify(lastRead.value));
  } catch {
    // storage is best effort
  }
}

function previewOf(conversation: Conversation | undefined): string {
  if (!conversation) return "";
  if (conversation.kind === "file" || conversation.kind === "file_offer") {
    return `${t("list.previewFile")} ${conversation.text}`;
  }
  return conversation.text;
}

function formatListTime(ts: number | undefined): string {
  if (!ts) return "";
  const date = new Date(ts * 1000);
  const today = new Date();
  if (date.toDateString() === today.toDateString()) {
    return date.toLocaleTimeString(locale.value === "zh" ? "zh-CN" : "en", {
      hour: "2-digit",
      minute: "2-digit",
    });
  }
  return `${date.getMonth() + 1}/${date.getDate()}`;
}

function reload() {
  window.location.reload();
}

const activeArchived = computed(() => {
  if (!activePeer.value) return null;
  if (activePeer.value.status === "deleted") return "deleted";
  if (activePeer.value.status === "removed") return "removed";
  return null;
});

function showToast(message: string) {
  toast.value = message;
  window.setTimeout(() => {
    if (toast.value === message) toast.value = "";
  }, 3200);
}

function applyTheme() {
  const preference = status.value?.theme ?? "system";
  const resolved =
    preference === "system"
      ? window.matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light"
      : preference;
  document.documentElement.dataset.theme = resolved;
}

async function bootstrap() {
  try {
    status.value = await api.status();
  } catch (error) {
    fatal.value = String(error);
    return;
  }
  applyTheme();
  if (!status.value.configured || !status.value.registered) {
    showOnboarding.value = true;
    return;
  }
  accounts.value = await api.accounts().catch(() => []);
  loadNameCache();
  loadLastRead();
  await refreshLists();
  startPolling();
}

async function afterAuth(next: Status) {
  status.value = next;
  showOnboarding.value = false;
  onboardingServer.value = "";
  applyTheme();
  accounts.value = await api.accounts().catch(() => []);
  loadNameCache();
  loadLastRead();
  pending.value = [];
  activeId.value = null;
  messages.value = [];
  await refreshLists();
  startPolling();
}

async function refreshLists() {
  if (!status.value?.registered) return;
  const [peersResult, groupsResult, devicesResult, conversationsResult] = await Promise.allSettled([
    api.listContacts(),
    api.listGroups(),
    api.listDevices(),
    api.conversations(),
  ]);
  if (peersResult.status === "fulfilled") peers.value = peersResult.value;
  if (groupsResult.status === "fulfilled") groups.value = groupsResult.value;
  if (devicesResult.status === "fulfilled") {
    devices.value = devicesResult.value;
    rememberNames(devices.value);
  }
  if (conversationsResult.status === "fulfilled") {
    const map: Record<string, Conversation> = {};
    for (const conversation of conversationsResult.value) map[conversation.peer] = conversation;
    conversations.value = map;
  }
  for (const peer of peers.value) {
    if (
      peer.status === "pending_accept" &&
      !pending.value.some((request) => request.peer === peer.deviceId)
    ) {
      pending.value.push({ peer: peer.deviceId, name: peerName(peer.deviceId) });
    }
  }
  if (activeId.value && !rows.value.some((row) => row.id === activeId.value)) {
    activeId.value = null;
    messages.value = [];
  }
  if (!activeId.value && rows.value.length && !isMobile.value) {
    await select(rows.value[0].id);
  }
}

async function select(id: string) {
  activeId.value = id;
  markRead(id);
  try {
    messages.value = await api.history(id);
  } catch (error) {
    messages.value = [];
    showToast(String(error));
  }
  await scrollToBottom();
}

async function scrollToBottom() {
  await nextTick();
  if (scroller.value) scroller.value.scrollTop = scroller.value.scrollHeight;
}

function startPolling() {
  if (timer) window.clearInterval(timer);
  pollFailures = 0;
  timer = window.setInterval(() => void poll(), 2000);
  void poll();
}

async function poll() {
  if (polling || !status.value?.registered) return;
  polling = true;
  try {
    const result = await api.poll();
    pollFailures = 0;
    let dirty = result.devicesChanged;
    for (const message of result.messages) {
      if (message.kind === "pair_request") {
        if (!pending.value.some((request) => request.peer === message.peer)) {
          pending.value.push({ peer: message.peer, name: message.text || shortId(message.peer) });
        }
        dirty = true;
        continue;
      }
      if (message.kind === "peer_removed" || message.kind === "peer_deleted") {
        pending.value = pending.value.filter((request) => request.peer !== message.peer);
        dirty = true;
        if (activeId.value === message.peer) {
          await select(message.peer);
        }
        continue;
      }
      if (message.peer === activeId.value) {
        messages.value.push(message);
      }
      if (message.kind === "pair_ok" || message.kind === "pair_rejected" || message.kind === "group_ready") {
        dirty = true;
      }
    }
    if (dirty) await refreshLists();
    if (messages.value.length) await scrollToBottom();
  } catch (error) {
    pollFailures += 1;
    const nowMs = Date.now();
    if (pollFailures >= 3 && nowMs - lastToastAt > 15000) {
      lastToastAt = nowMs;
      showToast(`${t("error.network")}: ${String(error)}`);
    }
  } finally {
    polling = false;
  }
}

async function accept(peer: string) {
  if (busy.value) return;
  busy.value = true;
  try {
    await api.confirmPair(peer);
    pending.value = pending.value.filter((request) => request.peer !== peer);
    await refreshLists();
    await select(peer);
    showToast(t("pair.accepted"));
  } catch (error) {
    showToast(String(error));
  } finally {
    busy.value = false;
  }
}

async function reject(peer: string) {
  if (busy.value) return;
  busy.value = true;
  try {
    await api.rejectPair(peer);
    pending.value = pending.value.filter((request) => request.peer !== peer);
  } catch (error) {
    showToast(String(error));
  } finally {
    busy.value = false;
  }
}

async function requestPair(peer: string) {
  if (busy.value) return;
  busy.value = true;
  try {
    await api.pair(peer);
    showToast(t("pair.sent"));
    showAdd.value = false;
    await refreshLists();
  } catch (error) {
    showToast(String(error));
  } finally {
    busy.value = false;
  }
}

async function removeContact() {
  const peer = activePeer.value;
  if (!peer) return;
  confirming.value = null;
  try {
    await api.removeContact(peer.deviceId);
    delete conversations.value[peer.deviceId];
    activeId.value = null;
    messages.value = [];
    await refreshLists();
  } catch (error) {
    showToast(String(error));
  }
}

async function openSecurity(peer: string) {
  try {
    const info = await api.peerSecurity(peer);
    security.value = { peer, code: info.safetyNumber };
  } catch (error) {
    showToast(String(error));
  }
}

async function copySafety() {
  if (!security.value?.code) return;
  try {
    await navigator.clipboard.writeText(groupSafety(security.value.code));
    showToast(t("common.copied"));
  } catch {
    showToast(groupSafety(security.value.code));
  }
}

async function send() {
  const text = input.value.trim();
  if (!text || !activeId.value || busy.value) return;
  busy.value = true;
  try {
    if (activeGroup.value) {
      await api.sendGroupMessage(activeId.value, text);
    } else {
      await api.sendMessage(activeId.value, text);
    }
    input.value = "";
    messages.value = await api.history(activeId.value);
    await scrollToBottom();
  } catch (error) {
    showToast(String(error));
  } finally {
    busy.value = false;
  }
}

async function attach() {
  if (!activeId.value || sendingFile.value) return;
  if (activeGroup.value) {
    showToast(t("chat.attach"));
    return;
  }
  // Android's system picker returns content:// URIs; the WebView input path
  // works on every platform and lets us read the bytes directly.
  if (isMobile.value || !("__TAURI_INTERNALS__" in window)) {
    fileInput.value?.click();
    return;
  }
  try {
    const path = await open({ multiple: false, directory: false });
    if (typeof path === "string") await sendPath(path);
  } catch (error) {
    showToast(String(error));
  }
}

function readFileBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error ?? new Error("read failed"));
    reader.onload = () => {
      const result = String(reader.result ?? "");
      resolve(result.slice(result.indexOf(",") + 1));
    };
    reader.readAsDataURL(file);
  });
}

async function onFilePicked(event: Event) {
  const input = event.target as HTMLInputElement;
  const file = input.files?.[0];
  input.value = "";
  if (!file || !activeId.value || activeGroup.value) return;
  sendingFile.value = true;
  showToast(t("chat.sendingFile"));
  try {
    const data = await readFileBase64(file);
    await api.sendFileData(activeId.value, file.name, data);
    messages.value = await api.history(activeId.value);
    await scrollToBottom();
  } catch (error) {
    showToast(String(error));
  } finally {
    sendingFile.value = false;
  }
}

async function sendPath(path: string) {
  if (!activeId.value || activeGroup.value) return;
  sendingFile.value = true;
  showToast(t("chat.sendingFile"));
  try {
    await api.sendFile(activeId.value, path);
    messages.value = await api.history(activeId.value);
    await scrollToBottom();
  } catch (error) {
    showToast(String(error));
  } finally {
    sendingFile.value = false;
  }
}

async function download(fileId: string) {
  if (downloading.value) return;
  downloading.value = fileId;
  try {
    const saved = await api.downloadFile(fileId);
    showToast(t("chat.saved", { path: saved }));
  } catch (error) {
    showToast(String(error));
  } finally {
    downloading.value = null;
  }
}

async function submitGroup() {
  const name = groupName.value.trim();
  if (!name || busy.value) return;
  busy.value = true;
  try {
    await api.createGroup(name, groupMembers.value);
    showGroup.value = false;
    groupName.value = "";
    groupMembers.value = [];
    await refreshLists();
  } catch (error) {
    showToast(String(error));
  } finally {
    busy.value = false;
  }
}

function toggleMember(id: string) {
  groupMembers.value = groupMembers.value.includes(id)
    ? groupMembers.value.filter((member) => member !== id)
    : [...groupMembers.value, id];
}

async function onPreferences(next: Status) {
  status.value = next;
  applyTheme();
  accounts.value = await api.accounts().catch(() => []);
  if (!next.configured || !next.registered) {
    showSettings.value = false;
    showOnboarding.value = true;
    return;
  }
  pending.value = [];
  activeId.value = null;
  messages.value = [];
  await refreshLists();
}

async function onOnboardingReady(next: Status) {
  await afterAuth(next);
}

function openAddAccount() {
  showSettings.value = false;
  onboardingServer.value = status.value?.serverUrl || "https://";
  showOnboarding.value = true;
}

async function checkShare() {
  if (!status.value?.registered) return;
  try {
    const share = await api.takeShare();
    if (share) pendingShare.value = share;
  } catch (error) {
    console.warn("share check failed", error);
  }
}

async function sendShare(target: string) {
  const share = pendingShare.value;
  if (!share || shareBusy.value) return;
  const group = groups.value.some((item) => item.group_id === target);
  if (group && share.files.length) {
    showToast(t("share.groupFiles"));
    return;
  }
  shareBusy.value = true;
  try {
    if (!group) {
      for (const file of share.files) {
        await api.sendFile(target, file.path);
      }
    }
    if (share.text?.trim()) {
      const text = share.text.trim();
      if (group) await api.sendGroupMessage(target, text);
      else await api.sendMessage(target, text);
    }
    pendingShare.value = null;
    await refreshLists();
    await select(target);
  } catch (error) {
    showToast(String(error));
  } finally {
    shareBusy.value = false;
  }
}

onMounted(async () => {
  isMobile.value = window.matchMedia("(max-width: 760px)").matches;
  window.matchMedia("(max-width: 760px)").addEventListener("change", (event) => {
    isMobile.value = event.matches;
  });
  window.addEventListener("error", (event) => {
    if (!fatal.value) fatal.value = event.message || String(event.error);
  });
  window.addEventListener("unhandledrejection", (event) => {
    if (!fatal.value) fatal.value = String(event.reason);
  });
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") void poll();
  });
  window
    .matchMedia("(prefers-color-scheme: dark)")
    .addEventListener("change", () => status.value?.theme === "system" && applyTheme());

  try {
    if (!(await isPermissionGranted())) await requestPermission();
  } catch {
    // notifications are optional (desktop without a daemon, Android before 13)
  }

  try {
    await getCurrentWebview().onDragDropEvent(async (event) => {
      if (event.payload.type === "over") dragOver.value = true;
      if (event.payload.type === "leave") dragOver.value = false;
      if (event.payload.type === "drop") {
        dragOver.value = false;
        const paths = event.payload.paths;
        if (paths.length) await sendPath(paths[0]);
      }
    });
  } catch {
    // drag & drop is desktop-only
  }

  await bootstrap();
  await checkShare();
  try {
    await listen("kite://share", () => void checkShare());
  } catch {
    // web-only fallback
  }
  window.setInterval(() => void checkShare(), 3000);
});

onBeforeUnmount(() => {
  if (timer) window.clearInterval(timer);
});

</script>

<template>
  <div v-if="fatal" class="fatal">
    <h2>{{ t("error.prefix") }}</h2>
    <pre>{{ fatal }}</pre>
    <button class="primary" @click="reload">{{ t("error.reload") }}</button>
  </div>
  <div v-else-if="!status" class="splash">{{ t("common.loading") }}</div>
  <Onboarding
    v-else-if="showOnboarding"
    :locale="locale"
    :initial-server="onboardingServer"
    :can-cancel="accounts.length > 0"
    @ready="onOnboardingReady"
    @cancel="showOnboarding = false"
    @error="showToast"
  />
  <div v-else class="app" :class="{ mobile: isMobile, 'chat-open': Boolean(activeId) }">
    <aside class="sidebar">
      <header class="brand">
        <img src="/kite-icon.png" alt="" class="brand-logo" />
        <div class="brand-text">
          <strong>{{ t("app.name") }}</strong>
          <span class="muted small">{{ status.name }} · {{ shortId(status.deviceId || "") }}</span>
        </div>
        <button class="icon" :title="t('nav.settings')" @click="showSettings = true">⚙</button>
      </header>

      <div class="list-head">
        <h2>{{ t("nav.contacts") }}</h2>
        <div class="list-actions">
          <button class="icon" :title="t('group.create')" @click="showGroup = true">群</button>
          <button class="icon" :title="t('nav.add')" @click="showAdd = true">＋</button>
        </div>
      </div>

      <div class="list">
        <div v-for="request in pending" :key="`req-${request.peer}`" class="request-card">
          <div>
            <strong>{{ request.name }}</strong>
            <span class="muted small">{{ t("pair.incoming", { name: shortId(request.peer) }) }}</span>
          </div>
          <div class="request-actions">
            <button class="small" :disabled="busy" @click="reject(request.peer)">
              {{ t("pair.reject") }}
            </button>
            <button class="primary small" :disabled="busy" @click="accept(request.peer)">
              {{ t("pair.accept") }}
            </button>
          </div>
        </div>

        <button
          v-for="row in rows"
          :key="row.id"
          class="contact"
          :class="{ active: row.id === activeId }"
          @click="select(row.id)"
        >
          <span class="avatar" :class="{ group: groupRows.some((group) => group.id === row.id) }">
            {{ row.title.slice(0, 1).toUpperCase() }}
          </span>
          <span class="contact-meta">
            <strong>{{ row.title }}</strong>
            <span class="muted small">
              <span v-if="row.online" class="dot" />
              {{ row.subtitle }}
            </span>
          </span>
          <span class="contact-side">
            <span class="list-time">{{ formatListTime(row.ts) }}</span>
            <span v-if="row.unread" class="unread-dot" />
            <span v-else class="badge">{{ row.badge }}</span>
          </span>
        </button>

        <div v-if="isEmpty" class="list-empty">
          <p>{{ t("list.empty") }}</p>
          <p class="muted small">{{ t("list.emptyHint") }}</p>
          <button class="primary small" @click="showAdd = true">{{ t("nav.add") }}</button>
        </div>
      </div>
    </aside>

    <main v-if="activeId" class="chat">
      <header class="chat-head">
        <button v-if="isMobile" class="icon" @click="activeId = null">←</button>
        <div class="chat-title">
          <strong>{{ activeTitle }}</strong>
          <span class="muted small">{{ activeSubtitle }}</span>
        </div>
        <div v-if="activePeer" class="chat-actions">
          <button class="icon" :title="t('chat.safety')" @click="openSecurity(activePeer.deviceId)">◎</button>
          <button
            class="icon"
            :title="t('chat.remove')"
            @click="confirming = { peer: activePeer.deviceId, name: peerName(activePeer.deviceId) }"
          >
            ⌫
          </button>
        </div>
      </header>

      <div v-if="activeArchived" class="readonly-banner">
        {{ t(activeArchived === "deleted" ? "chat.readOnlyDeleted" : "chat.readOnlyRemoved") }}
      </div>
      <div ref="scroller" class="messages">
        <div v-if="!messages.length" class="chat-empty">{{ t("chat.empty") }}</div>
        <MessageItem
          v-for="(message, index) in messages"
          :key="`${message.ts}-${index}`"
          :locale="locale"
          :message="message"
          :downloading="downloading === message.fileId"
          :group="Boolean(activeGroup)"
          @download="download"
        />
      </div>

      <footer v-if="!activeArchived" class="composer">
        <button
          class="icon attach"
          :title="t('chat.attach')"
          :disabled="sendingFile"
          @click="attach"
        >
          ＋
        </button>
        <textarea
          v-model="input"
          rows="1"
          :placeholder="t('chat.placeholder')"
          @keydown.enter.exact.prevent="send"
        />
        <button class="primary" :disabled="busy || !input.trim()" @click="send">
          {{ t("chat.send") }}
        </button>
      </footer>
    </main>

    <div v-else class="chat empty-state">
      <img src="/kite-icon.png" alt="" class="empty-logo" />
      <p class="muted">{{ t("list.emptyHint") }}</p>
    </div>

    <input ref="fileInput" type="file" class="hidden-input" @change="onFilePicked" />
    <div v-if="dragOver" class="drop-overlay">{{ t("chat.attach") }}</div>
    <div v-if="toast" class="toast">{{ toast }}</div>

    <div v-if="pendingShare" class="sheet-mask" @click.self="pendingShare = null">
      <div class="sheet">
        <header class="sheet-header">
          <h2>{{ t("share.title") }}</h2>
          <button class="icon" @click="pendingShare = null">×</button>
        </header>
        <section class="sheet-section">
          <p class="muted small">
            {{ pendingShare.files.length ? pendingShare.files.map((file) => file.name).join(", ") : pendingShare.text }}
          </p>
          <p v-if="!pairedContacts.length && !groupRows.length" class="muted small">{{ t("share.empty") }}</p>
          <button
            v-for="row in [...pairedContacts, ...groupRows]"
            :key="`share-${row.id}`"
            class="device-row"
            :disabled="shareBusy"
            @click="sendShare(row.id)"
          >
            <span class="avatar" :class="{ group: groupRows.some((group) => group.id === row.id) }">
              {{ row.title.slice(0, 1).toUpperCase() }}
            </span>
            <span class="device-meta">
              <strong>{{ row.title }}</strong>
              <span class="muted small">{{ row.badge }}</span>
            </span>
          </button>
        </section>
      </div>
    </div>

    <SettingsSheet
      v-if="showSettings && status"
      :locale="locale"
      :status="status"
      :accounts="accounts"
      @close="showSettings = false"
      @toast="showToast"
      @updated="onPreferences"
      @add-account="openAddAccount"
    />

    <AddContact
      v-if="showAdd"
      :locale="locale"
      :devices="devices"
      :paired="peers.map((peer) => peer.deviceId)"
      :self-id="status.deviceId"
      :busy="busy"
      @close="showAdd = false"
      @pair="requestPair"
      @refresh="refreshLists"
    />

    <div v-if="showGroup" class="sheet-mask" @click.self="showGroup = false">
      <div class="sheet">
        <header class="sheet-header">
          <h2>{{ t("group.create") }}</h2>
          <button class="icon" @click="showGroup = false">×</button>
        </header>
        <section class="sheet-section">
          <label class="field">
            <span>{{ t("group.name") }}</span>
            <input v-model="groupName" maxlength="40" />
          </label>
          <p class="muted small">{{ t("group.members") }}</p>
          <label v-for="peer in pairedContacts" :key="peer.id" class="check-row">
            <input
              type="checkbox"
              :checked="groupMembers.includes(peer.id)"
              @change="toggleMember(peer.id)"
            />
            <span>{{ peer.title }}</span>
          </label>
          <button class="primary block" :disabled="busy || !groupName.trim()" @click="submitGroup">
            {{ t("group.submit") }}
          </button>
        </section>
      </div>
    </div>

    <div v-if="security" class="sheet-mask" @click.self="security = null">
      <div class="sheet">
        <header class="sheet-header">
          <h2>{{ t("security.title") }}</h2>
          <button class="icon" @click="security = null">×</button>
        </header>
        <section class="sheet-section">
          <p class="muted small">{{ t("security.hint") }}</p>
          <div v-if="security.code" class="safety-code">{{ groupSafety(security.code) }}</div>
          <p v-else class="muted small">{{ t("security.none") }}</p>
          <p class="muted small mono">{{ t("security.device") }}: {{ security.peer }}</p>
          <div class="row-actions">
            <button class="small" :disabled="!security.code" @click="copySafety">
              {{ t("security.copy") }}
            </button>
            <button class="primary small" @click="security = null">{{ t("common.close") }}</button>
          </div>
        </section>
      </div>
    </div>

    <div v-if="confirming" class="sheet-mask" @click.self="confirming = null">
      <div class="sheet small-sheet">
        <header class="sheet-header">
          <h2>{{ t("chat.remove") }}</h2>
          <button class="icon" @click="confirming = null">×</button>
        </header>
        <section class="sheet-section">
          <p>{{ t("chat.removeConfirm", { name: confirming.name }) }}</p>
          <div class="row-actions">
            <button class="small" @click="confirming = null">{{ t("common.cancel") }}</button>
            <button class="small danger" @click="removeContact">{{ t("common.delete") }}</button>
          </div>
        </section>
      </div>
    </div>
  </div>
</template>
