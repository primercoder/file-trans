<script setup lang="ts">
import { ref } from "vue";
import { api } from "../api";
import type { Status } from "../types";

const emit = defineEmits<{ (e: "ready", status: Status): void; (e: "error", message: string): void }>();

const serverUrl = ref("https://127.0.0.1:8443");
const fingerprint = ref("");
const name = ref("");
const busy = ref(false);

async function submit() {
  if (!name.value.trim()) {
    emit("error", "请填写设备名称");
    return;
  }
  busy.value = true;
  try {
    const status = await api.register(serverUrl.value.trim(), fingerprint.value.trim(), name.value.trim());
    emit("ready", status);
  } catch (error) {
    emit("error", String(error));
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <div class="onboarding">
    <div class="card">
      <div class="logo-row">
        <img src="/kite-icon.png" alt="Kite" class="logo" />
        <div>
          <h1>Kite</h1>
          <p class="muted">端到端加密的文件与消息传输</p>
        </div>
      </div>
      <label>
        服务器地址
        <input v-model="serverUrl" placeholder="https://your-server:8443" />
      </label>
      <label>
        服务器证书指纹（SHA-256）
        <input v-model="fingerprint" placeholder="64 位十六进制" spellcheck="false" />
        <span class="hint">首次启动时服务端会打印指纹，也可在部署目录的 fingerprint.txt 中查看</span>
      </label>
      <label>
        设备名称
        <input v-model="name" placeholder="例如：办公室-台式机" @keyup.enter="submit" />
      </label>
      <button class="primary" :disabled="busy" @click="submit">
        {{ busy ? "正在注册…" : "注册并连接" }}
      </button>
      <p class="muted small">
        设备身份由本机生成的密钥决定，不随网络变化；请妥善保管。
      </p>
    </div>
  </div>
</template>
