<script setup lang="ts">
import { computed } from "vue";
import { formatSize, formatTime } from "../api";
import { translate } from "../i18n";
import type { ChatView } from "../types";

const props = defineProps<{
  locale: "zh" | "en";
  message: ChatView;
  downloading: boolean;
  group: boolean;
}>();

defineEmits<{ download: [string] }>();

const t = (key: string, vars?: Record<string, string | number>) => translate(props.locale, key, vars);

const isSystem = computed(() => props.message.direction === "system");
const isFile = computed(() => props.message.kind === "file" || props.message.kind === "file_offer");

const systemText = computed(() => {
  switch (props.message.kind) {
    case "peer_removed":
      return t("chat.peerRemoved");
    case "peer_deleted":
      return t("chat.peerDeleted");
    case "pair_ok":
      return t("chat.pairOk");
    case "pair_rejected":
      return t("chat.pairRejected");
    case "group_ready":
      return t("chat.groupReady");
    case "file_unavailable":
      return t("chat.fileUnavailable");
    default:
      return props.message.text;
  }
});
</script>

<template>
  <div v-if="isSystem" class="system-line">{{ systemText }}</div>
  <div v-else class="bubble-row" :class="message.direction">
    <div class="bubble" :class="{ file: isFile }">
      <template v-if="isFile">
        <div class="file-card">
          <span class="file-icon">▣</span>
          <span class="file-meta">
            <strong>{{ message.fileName || message.text }}</strong>
            <span class="muted small">{{ formatSize(message.size) }}</span>
          </span>
          <button
            v-if="message.direction === 'in' && message.fileId"
            class="small"
            :disabled="downloading"
            @click="$emit('download', message.fileId!)"
          >
            {{ downloading ? t("chat.downloading") : t("chat.download") }}
          </button>
        </div>
      </template>
      <template v-else>
        <span class="bubble-text">{{ message.text }}</span>
        <span class="bubble-time">{{ formatTime(message.ts) }}</span>
      </template>
    </div>
  </div>
</template>
