<script setup lang="ts">
import { computed, ref } from "vue";
import { api, shortId } from "../api";
import { translate } from "../i18n";
import type { AccountView, Status } from "../types";

const props = defineProps<{
  locale: "zh" | "en";
  status: Status;
  accounts: AccountView[];
}>();

const emit = defineEmits<{
  close: [];
  updated: [Status];
  toast: [string];
  addAccount: [];
}>();

const t = (key: string, vars?: Record<string, string | number>) => translate(props.locale, key, vars);
const confirming = ref<string | null>(null);
const busy = ref(false);

const active = computed(() => props.accounts.find((account) => account.active) ?? null);

async function save(theme: string, locale: string) {
  try {
    const status = await api.updatePreferences(theme, locale);
    emit("updated", status);
  } catch (error) {
    emit("toast", String(error));
  }
}

async function switchTo(id: string) {
  if (busy.value) return;
  busy.value = true;
  try {
    const status = await api.switchAccount(id);
    emit("updated", status);
  } catch (error) {
    emit("toast", String(error));
  } finally {
    busy.value = false;
  }
}

async function remove(id: string) {
  if (busy.value) return;
  busy.value = true;
  try {
    const status = await api.deleteAccount(id);
    confirming.value = null;
    emit("updated", status);
  } catch (error) {
    emit("toast", String(error));
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <div class="sheet-mask" @click.self="emit('close')">
    <div class="sheet">
      <header class="sheet-header">
        <h2>{{ t("settings.title") }}</h2>
        <button class="icon" @click="emit('close')">×</button>
      </header>

      <section class="sheet-section">
        <h3>{{ t("settings.account") }}</h3>
        <div v-if="active" class="account-card">
          <div>
            <strong>{{ active.name || shortId(active.deviceId || active.id) }}</strong>
            <span class="muted small">{{ active.serverUrl }}</span>
          </div>
          <span class="muted small mono">{{ shortId(active.deviceId || "") }}</span>
        </div>

        <div v-if="accounts.filter((account) => !account.active).length" class="account-list">
          <button
            v-for="account in accounts.filter((account) => !account.active)"
            :key="account.id"
            class="account-row"
            :class="{ active: account.active }"
            @click="!account.active && switchTo(account.id)"
          >
            <span class="account-name">{{ account.name || shortId(account.deviceId || account.id) }}</span>
            <span class="muted small">{{ account.serverUrl }}</span>
            <span v-if="account.active" class="badge">{{ t("settings.current") }}</span>
          </button>
        </div>

        <div class="row-actions">
          <button class="small" @click="emit('addAccount')">{{ t("settings.addAccount") }}</button>
          <button
            v-if="active"
            class="small danger"
            :disabled="busy"
            @click="confirming = active.serverUrl"
          >
            {{ t("settings.deleteAccount") }}
          </button>
        </div>

        <div v-if="confirming && active" class="confirm-box">
          <p>{{ t("settings.deleteConfirm", { name: active.name || active.serverUrl }) }}</p>
          <div class="row-actions">
            <button class="small" @click="confirming = null">{{ t("common.cancel") }}</button>
            <button class="small danger" :disabled="busy" @click="remove(active.id)">
              {{ t("common.delete") }}
            </button>
          </div>
        </div>
      </section>

      <section class="sheet-section">
        <h3>{{ t("settings.appearance") }}</h3>
        <div class="segmented">
          <button
            v-for="option in ['system', 'light', 'dark']"
            :key="option"
            :class="{ active: status.theme === option }"
            @click="save(option, status.locale)"
          >
            {{ t(`settings.theme${option[0].toUpperCase()}${option.slice(1)}`) }}
          </button>
        </div>
      </section>

      <section class="sheet-section">
        <h3>{{ t("settings.language") }}</h3>
        <div class="segmented">
          <button :class="{ active: status.locale === 'zh' }" @click="save(status.theme, 'zh')">中文</button>
          <button :class="{ active: status.locale === 'en' }" @click="save(status.theme, 'en')">English</button>
        </div>
      </section>

      <section class="sheet-section">
        <h3>{{ t("settings.about") }}</h3>
        <p class="muted small">{{ t("settings.version") }} · {{ t("app.tagline") }}</p>
        <p class="muted small mono">{{ t("settings.deviceId") }}: {{ status.deviceId || "—" }}</p>
      </section>
    </div>
  </div>
</template>
