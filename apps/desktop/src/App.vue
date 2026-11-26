<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { open } from "@tauri-apps/plugin-dialog";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { api, formatSize, shortId } from "./api";
import type { ChatView, DeviceInfo, Peer, Status } from "./types";
import Onboarding from "./components/Onboarding.vue";
import MessageItem from "./components/MessageItem.vue";
import SettingsPanel from "./components/SettingsPanel.vue";

const status = ref<Status | null>(null);
const peers = ref<Peer[]>([]);
const devices = ref<DeviceInfo[]>([]);
const activePeer = ref<string | null>(null);
const messages = ref<ChatView[]>([]);
const input = ref("");
const busy = ref(false);
const toast = ref("");
const showSettings = ref(false);
const dragOver = ref(false);
let timer: number | undefined;

const deviceNames = computed(() => {
  const map: Record<string, string> = {};
  for (const device of devices.value) map[device.device_id] = device.name;
  return map;
});

const pairedIds = computed(() => new Set(peers.value.map((peer) => peer.deviceId)));
const discoverable = computed(() =>
  devices.value.filter((device) => !pairedIds.value.has(device.device_id) && device.device_id !== status.value?.deviceId),
);
const activePeerName = computed(() => {
  if (!activePeer.value) return "";
  return deviceNames.value[activePeer.value] || `设备 ${shortId(activePeer.value)}`;
});
const pendingRequests = computed(() =>
  messages.value.filter((message) => message.kind === "pair_request"),
);
const pendingForActive = computed(() => {
  if (!activePeer.value) return null;
  return pendingRequests.value.find((request) => request.peer === activePeer.value) ?? null;
});

function showToast(message: string) {
  toast.value = message;
  window.setTimeout(() => {
    if (toast.value === message) toast.value = "";
  }, 3600);
}

async function refreshStatus() {
  status.value = await api.status();
  if (status.value.registered) {
    await refreshLists();
    await poll();
  }
}

async function refreshLists() {
  try {
    peers.value = await api.listPeers();
    const deviceList = await api.listDevices();
    devices.value = deviceList;
    if (!activePeer.value) {
      const first = deviceList.find((device) => pairedIds.value.has(device.device_id));
      if (first) await selectPeer(first.device_id);
    }
  } catch (error) {
    showToast(String(error));
  }
}

async function poll() {
  if (!status.value?.registered) return;
  try {
    const events = await api.poll();
    for (const event of events) {
      if (event.kind === "pair_request" && event.peer && !activePeer.value) {
        activePeer.value = event.peer;
      }
      if (event.peer === activePeer.value || event.kind === "pair_request") {
        messages.value.push(event);
      }
    }
    if (events.length) {
      peers.value = await api.listPeers();
      devices.value = await api.listDevices();
    }
  } catch (error) {
    // transient network failures are expected while the server restarts
    console.warn(error);
  }
}

async function selectPeer(peer: string) {
  activePeer.value = peer;
  messages.value = await api.history(peer);
}

async function requestPair(deviceId: string) {
  try {
    await api.pair(deviceId);
    showToast("配对请求已发送，等待对方确认");
    await refreshLists();
  } catch (error) {
    showToast(String(error));
  }
}

async function acceptPair(peer: string) {
  try {
    await api.confirmPair(peer);
    showToast("已接受配对");
    messages.value = messages.value.filter(
      (message) => !(message.kind === "pair_request" && message.peer === peer),
    );
    await refreshLists();
  } catch (error) {
    showToast(String(error));
  }
}

async function rejectPair(peer: string) {
  try {
    await api.rejectPair(peer);
    messages.value = messages.value.filter(
      (message) => !(message.kind === "pair_request" && message.peer === peer),
    );
    showToast("已拒绝配对");
  } catch (error) {
    showToast(String(error));
  }
}

async function send() {
  const text = input.value.trim();
  if (!text || !activePeer.value) return;
  busy.value = true;
  try {
    await api.sendMessage(activePeer.value, text);
    input.value = "";
    messages.value = await api.history(activePeer.value);
  } catch (error) {
    showToast(String(error));
  } finally {
    busy.value = false;
  }
}

async function attach() {
  if (!activePeer.value) return;
  const picked = await open({ multiple: false, title: "选择要发送的文件" });
  if (typeof picked === "string") await sendPath(picked);
}

async function sendPath(path: string) {
  if (!activePeer.value) return;
  busy.value = true;
  try {
    await api.sendFile(activePeer.value, path);
    messages.value = await api.history(activePeer.value);
    showToast("文件已发送");
  } catch (error) {
    showToast(String(error));
  } finally {
    busy.value = false;
  }
}

async function download(fileId: string) {
  try {
    const path = await api.downloadFile(fileId);
    showToast(`已保存到 ${path}`);
  } catch (error) {
    showToast(String(error));
  }
}

function handleReady(next: Status) {
  status.value = next;
  refreshLists();
  poll();
}

onMounted(async () => {
  await refreshStatus();
  timer = window.setInterval(poll, 2000);
  try {
    await getCurrentWebview().onDragDropEvent(async (event) => {
      if (event.payload.type === "over") dragOver.value = true;
      if (event.payload.type === "drop") {
        dragOver.value = false;
        const paths = event.payload.paths;
        if (paths.length && activePeer.value) await sendPath(paths[0]);
      }
      if (event.payload.type === "leave") dragOver.value = false;
    });
  } catch (error) {
    console.warn("drag-drop unavailable", error);
  }
});

onBeforeUnmount(() => {
  if (timer) window.clearInterval(timer);
});

watch(activePeer, (peer) => {
  if (peer) selectPeer(peer);
});
</script>

<template>
  <div v-if="!status" class="loading">正在启动…</div>
  <Onboarding v-else-if="!status.registered" @ready="handleReady" @error="showToast" />
  <div v-else class="shell">
    <aside class="sidebar">
      <div class="brand">
        <img src="/kite-icon.png" alt="" class="brand-icon" />
        <div>
          <strong>Kite</strong>
          <span class="muted small">{{ status.name }} · {{ shortId(status.deviceId || "") }}</span>
        </div>
        <button class="icon" title="设置" @click="showSettings = true">⚙</button>
      </div>

      <div class="section-title">会话</div>
      <div v-if="!peers.length" class="muted small pad">还没有配对设备</div>
      <button
        v-for="peer in peers"
        :key="peer.deviceId"
        class="peer"
        :class="{ active: peer.deviceId === activePeer }"
        @click="selectPeer(peer.deviceId)"
      >
        <span class="avatar">{{ (deviceNames[peer.deviceId] || "?").slice(0, 1) }}</span>
        <span class="peer-info">
          <strong>{{ deviceNames[peer.deviceId] || `设备 ${shortId(peer.deviceId)}` }}</strong>
          <span class="muted small">{{ peer.status === "paired" ? "已配对" : "待确认" }}</span>
        </span>
      </button>

      <div class="section-title">发现设备</div>
      <div v-if="!discoverable.length" class="muted small pad">暂无其他设备</div>
      <div v-for="device in discoverable" :key="device.device_id" class="peer">
        <span class="avatar">{{ device.name.slice(0, 1) }}</span>
        <span class="peer-info">
          <strong>{{ device.name }}</strong>
          <span class="muted small">{{ device.online ? "在线" : "离线" }}</span>
        </span>
        <button class="small" @click="requestPair(device.device_id)">配对</button>
      </div>
    </aside>

    <main class="chat">
      <template v-if="activePeer">
        <header class="chat-header">
          <div>
            <strong>{{ activePeerName }}</strong>
            <span class="muted small">{{ shortId(activePeer) }}</span>
          </div>
        </header>
        <div class="messages">
          <div v-if="pendingForActive" class="pair-banner">
            <span>对方请求与你配对</span>
            <div>
              <button class="primary small" @click="acceptPair(pendingForActive.peer)">接受</button>
              <button class="small" @click="rejectPair(pendingForActive.peer)">拒绝</button>
            </div>
          </div>
          <div v-if="!messages.length" class="empty muted">开始发送第一条消息吧</div>
          <MessageItem
            v-for="(message, index) in messages"
            :key="`${message.ts}-${index}`"
            :message="message"
            @download="download"
          />
        </div>
        <footer class="composer">
          <button class="icon attach" title="发送文件" :disabled="busy" @click="attach">📎</button>
          <textarea
            v-model="input"
            rows="1"
            placeholder="输入消息，Enter 发送，Shift+Enter 换行"
            @keydown.enter.exact.prevent="send"
          ></textarea>
          <button class="primary" :disabled="busy || !input.trim()" @click="send">发送</button>
        </footer>
      </template>
      <div v-else class="empty-state">
        <img src="/kite-icon.png" alt="" class="empty-logo" />
        <h2>选择一个会话</h2>
        <p class="muted">从左侧发现设备并配对，即可安全地发送消息与文件</p>
      </div>
    </main>

    <div v-if="dragOver" class="drop-overlay">
      <div>松开鼠标，将文件发送给 {{ activePeerName || "对方" }}</div>
    </div>
    <div v-if="toast" class="toast">{{ toast }}</div>
    <SettingsPanel
      v-if="showSettings"
      :status="status"
      @close="showSettings = false"
      @toast="showToast"
      @refresh="(next) => { status = next; refreshStatus(); }"
    />
  </div>
</template>
