<script setup lang="ts">
import {computed} from 'vue'
import type {report} from '../../wailsjs/go/models'
import {zh} from '../i18n/zh'

const props = defineProps<{
  status: report.StatusView | null
  error: string
  loading: boolean
}>()

const emit = defineEmits<{
  refresh: []
}>()

// Colour class per backend state code (the text always comes from the
// backend label, so colour is never the only signal).
const SMART_TONE: Record<string, string> = {disabled: 'ok', enabled: 'warn'}
const TUN_TONE: Record<string, string> = {on: 'on'}
const CONCLUSION_TONE: Record<string, string> = {risk: 'bad', protected: 'ok', 'tun-off': 'plain', unknown: 'warn'}

const items = computed(() => {
  const s = props.status
  if (!s) return []
  return [
    {key: 'smart', item: s.smart, tone: SMART_TONE[s.smart.state] ?? 'muted'},
    {key: 'tun', item: s.tun, tone: TUN_TONE[s.tun.state] ?? 'muted'},
  ]
})
</script>

<template>
  <section class="sysstatus" :class="{risk: status?.risk}" :aria-busy="loading">
    <div class="row">
      <span class="title">{{ zh.systemStatus }}</span>
      <template v-if="status">
        <span v-for="it in items" :key="it.key" class="item">
          {{ it.item.title }}
          <span class="badge" :class="'tone-' + it.tone">{{ it.item.label }}</span>
        </span>
      </template>
      <span v-else-if="loading" class="muted">{{ zh.statusChecking }}</span>
      <span v-else-if="error" class="err">{{ zh.statusFailed(error) }}</span>
      <span class="spacer"></span>
      <span v-if="loading && status" class="muted small">{{ zh.statusChecking }}</span>
      <button type="button" :disabled="loading" @click="emit('refresh')">{{ zh.refreshStatus }}</button>
    </div>

    <template v-if="status">
      <p class="conclusion" :class="'tone-' + (CONCLUSION_TONE[status.conclusion_code] ?? 'muted')">
        {{ status.conclusion }}
      </p>

      <details class="more">
        <summary>{{ zh.statusEvidence }}</summary>
        <div v-for="it in items" :key="it.key" class="evidence">
          <div class="ev-title">{{ zh.statusItem(it.item.title, it.item.label) }}</div>
          <ul>
            <li v-for="(d, i) in it.item.detail" :key="i">{{ d }}</li>
            <li v-if="it.item.note" class="note">{{ it.item.note }}</li>
          </ul>
        </div>
      </details>

      <details v-if="status.fix.length > 0" class="more fix" :open="status.risk">
        <summary>{{ zh.statusFix }}</summary>
        <ol>
          <li v-for="(f, i) in status.fix" :key="i">
            {{ f.text }}
            <code v-if="f.command" class="cmd">{{ f.command }}</code>
          </li>
        </ol>
      </details>
    </template>
  </section>
</template>

<style scoped>
.sysstatus {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 8px 14px;
  border-bottom: 1px solid var(--border);
  border-left: 4px solid transparent;
  background: var(--panel);
  font-size: 13px;
}
.sysstatus.risk {
  border-left-color: var(--sev-high);
}
.row {
  display: flex;
  align-items: center;
  gap: 14px;
  flex-wrap: wrap;
  min-width: 0;
}
.title {
  font-weight: 600;
}
.item {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.spacer {
  flex: 1;
}
.badge {
  padding: 1px 9px;
  border-radius: 999px;
  border: 1px solid var(--tone);
  color: var(--tone);
  font-size: 12px;
  font-weight: 600;
}
.tone-ok {
  --tone: var(--ok);
}
.tone-warn {
  --tone: var(--sev-medium);
}
.tone-bad {
  --tone: var(--sev-high);
}
.tone-on {
  --tone: var(--accent);
}
.tone-plain {
  --tone: var(--fg);
}
.tone-muted {
  --tone: var(--muted);
}
.conclusion {
  margin: 0;
  line-height: 1.6;
  color: var(--tone);
}
.conclusion.tone-bad {
  font-weight: 600;
}
.muted {
  color: var(--muted);
}
.small {
  font-size: 12px;
}
.err {
  color: var(--sev-high);
  word-break: break-word;
}
.more summary {
  cursor: pointer;
  color: var(--muted);
  font-size: 12px;
  user-select: none;
}
.more ul,
.more ol {
  margin: 4px 0 2px;
  padding-left: 22px;
  line-height: 1.6;
}
.evidence {
  margin-top: 4px;
}
.ev-title {
  font-weight: 600;
}
.note {
  color: var(--sev-medium);
}
.fix summary {
  color: var(--fg);
  font-weight: 600;
}
.cmd {
  display: block;
  margin: 4px 0;
  padding: 6px 8px;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: var(--code-bg);
  font-family: var(--mono);
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
  user-select: text;
}
</style>
