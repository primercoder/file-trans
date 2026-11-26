<script setup lang="ts">
import { computed, ref } from "vue";
import { shortId } from "../api";
import { translate } from "../i18n";
import type { DeviceInfo } from "../types";

const props = defineProps<{
  locale: "zh" | "en";
  devices: DeviceInfo[];
  paired: string[];
  selfId: string | null;
  busy: boolean;
}>();

const emit = defineEmits<{
  close: [];
  pair: [string];
  refresh: [];
}>();

const t = (key: string, vars?: Record<string, string | number>) => translate(props.locale, key, vars);
const deviceId = ref("");
const error = ref("");

const discovered = computed(() =>
  props.devices.filter(
    (device) => device.device_id !== props.selfId && !props.paired.includes(device.device_id),
  ),
);

function submit() {
  const id = deviceId.value.trim().toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(id)) {
    error.value = t("add.idHint");
    return;
  }
  error.value = "";
  emit("pair", id);
  deviceId.value = "";
}
</script>

<template>
  <div class="sheet-mask" @click.self="emit('close')">
    <div class="sheet">
      <header class="sheet-header">
        <h2>{{ t("add.title") }}</h2>
        <button class="icon" @click="emit('close')">×</button>
      </header>

      <section class="sheet-section">
        <label class="field">
          <span>{{ t("add.idLabel") }}</span>
          <input
            v-model="deviceId"
            class="mono"
            autocomplete="off"
            spellcheck="false"
            :placeholder="t('add.idHint')"
            @keydown.enter="submit"
          />
        </label>
        <p v-if="error" class="error-text">{{ error }}</p>
        <button class="primary block" :disabled="busy || !deviceId.trim()" @click="submit">
          {{ t("add.submit") }}
        </button>
      </section>

      <section class="sheet-section">
        <div class="section-head">
          <h3>{{ t("add.discovered") }}</h3>
          <button class="small" :disabled="busy" @click="emit('refresh')">{{ t("add.refresh") }}</button>
        </div>
        <p v-if="!discovered.length" class="muted small">{{ t("add.empty") }}</p>
        <button
          v-for="device in discovered"
          :key="device.device_id"
          class="device-row"
          :disabled="busy"
          @click="emit('pair', device.device_id)"
        >
          <span class="avatar">{{ device.name.slice(0, 1).toUpperCase() }}</span>
          <span class="device-meta">
            <strong>{{ device.name }}</strong>
            <span class="muted small mono">{{ shortId(device.device_id) }}</span>
          </span>
          <span class="badge" :class="{ online: device.online }">
            {{ device.online ? t("list.online") : t("list.offline") }}
          </span>
        </button>
      </section>
    </div>
  </div>
</template>
