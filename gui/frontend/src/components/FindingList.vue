<script setup lang="ts">
import type {model, report} from '../../wailsjs/go/models'
import type {Selection} from '../composables/useCheck'
import {zh} from '../i18n/zh'
import FindingCard from './FindingCard.vue'

// Findings are shown in the order given by the backend (same as the CLI);
// they are never re-sorted or rewritten here.
defineProps<{
  findings: report.FindingView[]
  labels: report.Labels | null
  selected: Selection | null
}>()

const emit = defineEmits<{
  select: [sel: Selection, loc: model.Location]
}>()
</script>

<template>
  <div class="list">
    <h3>{{ zh.findingsTitle(findings.length) }}</h3>
    <p v-if="findings.length === 0" class="empty">{{ zh.noFindings }}</p>
    <FindingCard
      v-for="(f, i) in findings"
      :key="i"
      :finding="f"
      :index="i"
      :labels="labels"
      :selected="selected"
      @select="(sel, loc) => emit('select', sel, loc)"
    />
  </div>
</template>

<style scoped>
.list {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 12px;
}
h3 {
  margin: 0;
  font-size: 13px;
  color: var(--muted);
  font-weight: 600;
}
.empty {
  color: var(--muted);
}
</style>
