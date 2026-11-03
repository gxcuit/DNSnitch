<script setup lang="ts">
import {computed, ref} from 'vue'
import type {model, report} from '../../wailsjs/go/models'
import type {Selection} from '../composables/useCheck'
import {zh} from '../i18n/zh'
import {baseName, label} from '../labels'

const props = defineProps<{
  finding: report.FindingView
  index: number
  labels: report.Labels | null
  selected: Selection | null
}>()

const emit = defineEmits<{
  select: [sel: Selection, loc: model.Location]
}>()

/** Locations shown before "show all" (the CLI text output shows 6 per role). */
const COLLAPSED = 8

const expanded = ref(false)
const shown = computed(() =>
  expanded.value ? props.finding.locations : props.finding.locations.slice(0, COLLAPSED),
)

function where(l: model.Location): string {
  if (l.line > 0) return `${baseName(l.file)}:${l.line}`
  if (l.path) return `${baseName(l.file)} (${l.path}, ${label(props.labels, 'text', 'unknown_line')})`
  return baseName(l.file)
}

function isSelected(i: number): boolean {
  return props.selected?.finding === props.index && props.selected.location === i
}
</script>

<template>
  <article class="card" :class="'sev-' + finding.severity">
    <header>
      <span class="badge">{{ label(labels, 'severity', finding.severity) }}</span>
      <span class="id">{{ finding.id }}</span>
    </header>
    <p class="message">{{ finding.message }}</p>

    <section v-if="finding.locations.length">
      <h4>{{ zh.locations }}</h4>
      <ul class="locs">
        <li v-for="(l, i) in shown" :key="i">
          <button
            type="button"
            class="loc"
            :class="{active: isSelected(i)}"
            :title="l.file + (l.line > 0 ? ':' + l.line : '')"
            @click="emit('select', {finding: index, location: i}, l)"
          >
            <span class="role">{{ label(labels, 'role', l.role) }}</span>
            <span class="where">{{ where(l) }}</span>
            <code v-if="l.text" class="text">{{ l.text }}</code>
            <span v-if="l.resolver" class="resolver" :class="'level-' + l.resolver.level">
              {{ zh.resolver(label(labels, 'role', 'resolver'), label(labels, 'level', l.resolver.level),
                 label(labels, 'resolver_source', l.resolver.source) + (l.resolver.policy_key ? ': ' + l.resolver.policy_key : '')) }}
            </span>
          </button>
        </li>
      </ul>
      <button
        v-if="finding.locations.length > COLLAPSED"
        type="button"
        class="link"
        @click="expanded = !expanded"
      >{{ expanded ? zh.showFewerLocations : zh.showAllLocations(finding.locations.length) }}</button>
    </section>

    <section v-if="finding.fix">
      <h4>{{ zh.fix }}</h4>
      <p>{{ finding.fix }}</p>
    </section>

    <section v-if="finding.notes.length">
      <h4>{{ zh.notes }}</h4>
      <ul class="notes">
        <li v-for="(n, i) in finding.notes" :key="i">{{ n }}</li>
      </ul>
    </section>
  </article>
</template>

<style scoped>
.card {
  border: 1px solid var(--border);
  border-left: 4px solid var(--sev-color);
  border-radius: 6px;
  padding: 10px 12px;
  background: var(--panel);
}
header {
  display: flex;
  align-items: center;
  gap: 8px;
}
.badge {
  padding: 1px 8px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 600;
  color: #fff;
  background: var(--sev-color);
}
.id {
  font-family: var(--mono);
  font-weight: 600;
}
.message {
  margin: 8px 0;
  line-height: 1.6;
}
h4 {
  margin: 10px 0 4px;
  font-size: 12px;
  color: var(--muted);
  font-weight: 600;
}
section p {
  margin: 0;
  line-height: 1.6;
}
.locs,
.notes {
  margin: 0;
  padding: 0;
  list-style: none;
}
.notes li {
  padding-left: 1em;
  text-indent: -1em;
  line-height: 1.6;
}
.notes li::before {
  content: '- ';
}
.loc {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 4px 10px;
  width: 100%;
  text-align: left;
  border: 1px solid transparent;
  border-radius: 4px;
  background: transparent;
  padding: 3px 6px;
  font: inherit;
  color: inherit;
  cursor: pointer;
}
.loc:hover {
  background: var(--hover);
}
.loc.active {
  border-color: var(--accent);
  background: var(--selected);
}
.role {
  min-width: 4.5em;
  font-size: 12px;
  color: var(--muted);
}
.where {
  font-family: var(--mono);
  font-size: 12px;
  color: var(--accent);
}
.text {
  font-family: var(--mono);
  font-size: 12px;
  word-break: break-all;
}
.resolver {
  font-size: 12px;
  color: var(--muted);
}
.resolver.level-plain {
  color: var(--sev-high);
}
.resolver.level-cn,
.resolver.level-foreign {
  color: var(--sev-medium);
}
.link {
  border: none;
  background: none;
  color: var(--accent);
  cursor: pointer;
  padding: 4px 6px;
  font: inherit;
  font-size: 12px;
}
</style>
