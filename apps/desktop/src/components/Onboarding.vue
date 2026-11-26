<script setup lang="ts">
import { computed, ref } from "vue";
import { api } from "../api";
import { translate } from "../i18n";
import type { Status } from "../types";

const props = defineProps<{ locale: "zh" | "en"; initialServer?: string; canCancel?: boolean }>();
const emit = defineEmits<{ ready: [Status]; error: [string]; cancel: [] }>();

const server = ref(props.initialServer || "https://");
const name = ref("");
const pin = ref("");
const advanced = ref(false);
const busy = ref(false);
const error = ref("");

const t = (key: string, vars?: Record<string, string | number>) => translate(props.locale, key, vars);
const canSubmit = computed(() => server.value.trim().length > 8 && name.value.trim().length > 0);

async function submit() {
  if (!canSubmit.value || busy.value) return;
  busy.value = true;
  error.value = "";
  try {
    const status = await api.register(server.value.trim(), pin.value.trim() || null, name.value.trim());
    emit("ready", status);
  } catch (cause) {
    error.value = String(cause);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <div class="onboarding">
    <div class="onboarding-card">
      <img src="/kite-icon.png" alt="" class="onboarding-logo" />
      <div class="onboarding-heading">
        <h1>{{ t("app.name") }}</h1>
        <p class="muted">{{ t("app.tagline") }}</p>
      </div>

      <label class="field">
        <span>{{ t("onboarding.server") }}</span>
        <input
          v-model="server"
          type="url"
          inputmode="url"
          autocomplete="off"
          spellcheck="false"
          :placeholder="t('onboarding.serverHint')"
        />
      </label>
      <label class="field">
        <span>{{ t("onboarding.name") }}</span>
        <input v-model="name" autocomplete="off" :placeholder="t('onboarding.nameHint')" maxlength="40" />
      </label>

      <button class="link" type="button" @click="advanced = !advanced">
        {{ t("onboarding.advanced") }}
      </button>
      <label v-if="advanced" class="field">
        <span>{{ t("onboarding.pin") }}</span>
        <input
          v-model="pin"
          autocomplete="off"
          spellcheck="false"
          :placeholder="t('onboarding.pinHint')"
        />
      </label>

      <p v-if="error" class="error-text">{{ error }}</p>
      <button class="primary block" :disabled="!canSubmit || busy" @click="submit">
        {{ busy ? t("onboarding.registering") : t("onboarding.submit") }}
      </button>
      <button v-if="canCancel" class="link" type="button" @click="emit('cancel')">
        {{ t("common.cancel") }}
      </button>
    </div>
  </div>
</template>
