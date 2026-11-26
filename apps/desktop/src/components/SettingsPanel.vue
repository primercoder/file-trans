<script setup lang="ts">
import { ref } from "vue";
import { api } from "../api";
import type { Status } from "../types";

const props = defineProps<{ status: Status }>();
const emit = defineEmits<{ (e: "close"): void; (e: "toast", message: string): void; (e: "refresh", status: Status): void }>();

const exportPass = ref("");
const importPass = ref("");
const importBlob = ref("");
const busy = ref(false);

async function exportIdentity() {
  if (exportPass.value.length < 8) {
    emit("toast", "口令至少 8 位");
    return;
  }
  busy.value = true;
  try {
    const blob = await api.exportIdentity(exportPass.value);
    const data = new Blob([blob], { type: "text/plain" });
    const url = URL.createObjectURL(data);
    const link = document.createElement("a");
    link.href = url;
    link.download = "kite-identity-backup.txt";
    link.click();
    URL.revokeObjectURL(url);
    emit("toast", "身份备份已导出（请离线保管，内含私钥）");
    exportPass.value = "";
  } catch (error) {
    emit("toast", String(error));
  } finally {
    busy.value = false;
  }
}

async function importIdentity() {
  if (!importPass.value || !importBlob.value.trim()) {
    emit("toast", "请填写口令与备份内容");
    return;
  }
  busy.value = true;
  try {
    const status = await api.importIdentity(importPass.value, importBlob.value);
    emit("refresh", status);
    emit("toast", "身份已恢复，会话将继续使用");
    importPass.value = "";
    importBlob.value = "";
  } catch (error) {
    emit("toast", String(error));
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <div class="modal-mask" @click.self="emit('close')">
    <div class="modal">
      <header>
        <h2>设置</h2>
        <button class="icon" @click="emit('close')">×</button>
      </header>
      <section>
        <h3>连接</h3>
        <p class="muted">服务器：{{ props.status.serverUrl ?? "未配置" }}</p>
        <p class="muted">设备名称：{{ props.status.name ?? "-" }}</p>
        <p class="muted">设备 ID：{{ props.status.deviceId ?? "-" }}</p>
      </section>
      <section>
        <h3>导出身份备份</h3>
        <p class="muted small">
          备份可用口令加密后迁移到新设备；导入后旧设备请停用，避免会话密钥分叉。
        </p>
        <input v-model="exportPass" type="password" placeholder="设置备份口令（至少 8 位）" />
        <button class="primary" :disabled="busy" @click="exportIdentity">导出备份文件</button>
      </section>
      <section>
        <h3>导入身份备份</h3>
        <p class="muted small">仅能导入到全新设备（已有身份的设备会被拒绝）。</p>
        <input v-model="importPass" type="password" placeholder="备份口令" />
        <textarea v-model="importBlob" rows="4" placeholder="粘贴备份内容（KITE-BACKUP-V1…）"></textarea>
        <button class="primary" :disabled="busy" @click="importIdentity">恢复身份</button>
      </section>
    </div>
  </div>
</template>
