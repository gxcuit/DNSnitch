<script setup lang="ts">
import type {report} from '../../wailsjs/go/models'
import {zh} from '../i18n/zh'
import {SEVERITIES, label} from '../labels'

defineProps<{
  currentFile: string
  result: report.CheckResult | null
  loading: boolean
  isClean: boolean
  labels: report.Labels | null
  notice: string
}>()

const emit = defineEmits<{
  choose: []
  recheck: []
}>()
</script>

<template>
  <header class="summary">
    <div class="row">
      <button class="primary" type="button" @click="emit('choose')">{{ zh.chooseFile }}</button>
      <button type="button" :disabled="!currentFile || loading" @click="emit('recheck')">{{ zh.recheck }}</button>
      <span class="file" :title="currentFile">{{ currentFile }}</span>
    </div>
    <div v-if="result" class="row">
      <span
        v-for="s in SEVERITIES"
        :key="s"
        class="chip"
        :class="['sev-' + s, {zero: result.summary[s] === 0}]"
      >{{ label(labels, 'severity', s) }} {{ result.summary[s] }}</span>
      <span v-if="isClean" class="status ok">✓ {{ zh.statusOk }}<small>{{ zh.statusOkDetail }}</small></span>
      <span v-else class="status bad">{{ zh.statusBad }}</span>
    </div>
    <div v-if="notice" class="notice">{{ notice }}</div>
  </header>
</template>

<style scoped>
.summary {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 10px 14px;
  border-bottom: 1px solid var(--border);
  background: var(--panel);
}
.row {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  min-width: 0;
}
.file {
  font-family: var(--mono);
  font-size: 12px;
  color: var(--muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  min-width: 0;
  flex: 1;
}
.chip {
  padding: 2px 10px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 600;
  color: #fff;
  background: var(--sev-color);
}
.chip.zero {
  color: var(--muted);
  background: transparent;
  border: 1px solid var(--border);
  font-weight: 400;
}
.status {
  margin-left: 8px;
  font-weight: 600;
}
.status small {
  margin-left: 8px;
  font-weight: 400;
  color: var(--muted);
}
.status.ok {
  color: var(--ok);
}
.status.bad {
  color: var(--sev-high);
}
.notice {
  font-size: 12px;
  color: var(--sev-medium);
}
</style>
