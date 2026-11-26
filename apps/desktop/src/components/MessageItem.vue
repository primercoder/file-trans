<script setup lang="ts">
import { computed } from "vue";
import type { ChatView } from "../types";
import { formatSize, formatTime } from "../api";

const props = defineProps<{ message: ChatView }>();
const emit = defineEmits<{ (e: "download", fileId: string): void }>();

const isSystem = computed(() => props.message.direction === "system");
const isMine = computed(() => props.message.direction === "out");
</script>

<template>
  <div v-if="isSystem" class="system-line">
    <span>{{ message.text }}</span>
  </div>
  <div v-else class="bubble-row" :class="{ mine: isMine }">
    <div class="bubble" :class="{ mine: isMine }">
      <template v-if="message.kind === 'text'">
        <p class="text">{{ message.text }}</p>
      </template>
      <template v-else-if="message.kind === 'file' || message.kind === 'file_offer'">
        <div class="file-card">
          <div class="file-icon">FILE</div>
          <div class="file-meta">
            <strong>{{ message.fileName || message.text }}</strong>
            <span class="muted">{{ formatSize(message.size) }}</span>
          </div>
          <button v-if="!isMine && message.fileId" class="small" @click="emit('download', message.fileId!)">
            下载
          </button>
        </div>
      </template>
      <template v-else-if="message.kind === 'file_unavailable'">
        <p class="muted">文件已被服务器清理</p>
      </template>
      <span class="time">{{ formatTime(message.ts) }}</span>
    </div>
  </div>
</template>
