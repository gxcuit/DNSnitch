<script setup lang="ts">
import {computed, onMounted, ref} from 'vue'
import type {fix, main, report} from '../../wailsjs/go/models'
import {zh} from '../i18n/zh'
import {SEVERITIES, baseName, label} from '../labels'

const props = defineProps<{
  result: report.FixResult | null
  error: main.GUIError | null
  loading: boolean
  saving: boolean
  saveError: main.GUIError | null
  labels: report.Labels | null
}>()

const emit = defineEmits<{
  save: []
  close: []
}>()

/** Skip reason whose line belongs to another file (e.g. a rule-set). */
const REASON_OTHER_FILE = 'other-file'

const dialog = ref<HTMLElement | null>(null)
onMounted(() => dialog.value?.focus())

const canSave = computed(
  () => !!props.result && props.result.edits.length > 0 && !props.loading && !props.saving,
)

/** Severity counts of the config and of the fixed text (from the backend). */
const sums = computed(() => {
  const r = props.result
  if (!r) return []
  return [
    {key: 'before', title: zh.fixSummaryBefore, s: r.before},
    {key: 'after', title: zh.fixSummaryAfter, s: r.after},
  ]
})

const afterClean = computed(() => {
  const s = props.result?.after
  return !!s && s.error + s.high + s.medium === 0
})

/** Unified diff range, written like the CLI (`fix.Unified`): ",1" is omitted. */
function range(start: number, n: number): string {
  return n === 1 ? String(start) : `${start},${n}`
}

function hunkHeader(h: fix.Hunk): string {
  return `@@ -${range(h.old_start, h.old_lines)} +${range(h.new_start, h.new_lines)} @@`
}

interface DiffRow {
  kind: 'hunk' | 'ctx' | 'del' | 'add' | 'nonl'
  text: string
  old?: number
  new?: number
}

const OP_KIND: Record<string, DiffRow['kind']> = {' ': 'ctx', '-': 'del', '+': 'add'}

/** Hunks flattened into rows with old / new line numbers for the gutter. */
const rows = computed(() => {
  const out: DiffRow[] = []
  for (const h of props.result?.diff ?? []) {
    out.push({kind: 'hunk', text: hunkHeader(h)})
    let o = h.old_start
    let n = h.new_start
    for (const l of h.lines) {
      const kind = OP_KIND[l.op] ?? 'ctx'
      const row: DiffRow = {kind, text: l.op + l.text}
      if (kind !== 'add') row.old = o++
      if (kind !== 'del') row.new = n++
      out.push(row)
      if (l.no_newline) out.push({kind: 'nonl', text: zh.fixNoNewline})
    }
  }
  return out
})

const gutterChars = computed(() => {
  let max = 1
  for (const r of rows.value) max = Math.max(max, r.old ?? 0, r.new ?? 0)
  return String(max).length
})

function skipWhere(s: report.FixSkip): string {
  if (s.reason === REASON_OTHER_FILE || s.line <= 0) return ''
  return zh.fixLine(s.line)
}
</script>

<template>
  <div class="backdrop" @click.self="emit('close')">
    <section
      ref="dialog"
      class="dialog"
      role="dialog"
      aria-modal="true"
      aria-labelledby="fix-title"
      tabindex="-1"
      @keydown.esc="emit('close')"
    >
      <header>
        <h2 id="fix-title">{{ zh.fixTitle }}</h2>
        <span v-if="result" class="path" :title="result.file">{{ result.file }}</span>
      </header>

      <div class="content">
        <p v-if="loading" class="state">
          <span class="spinner" aria-hidden="true"></span>{{ zh.fixLoading }}
        </p>

        <div v-else-if="error" class="error-box" role="alert">
          <h3>{{ zh.fixFailed }}</h3>
          <p>{{ error.message }}</p>
        </div>

        <template v-else-if="result">
          <p class="note">{{ zh.fixNote }}</p>

          <section class="sums">
            <div v-for="row in sums" :key="row.key" class="sum-row">
              <span class="sum-title">{{ row.title }}</span>
              <span
                v-for="sev in SEVERITIES"
                :key="sev"
                class="chip"
                :class="['sev-' + sev, {zero: row.s[sev] === 0}]"
              >{{ label(labels, 'severity', sev) }} {{ row.s[sev] }}</span>
            </div>
            <p class="verdict" :class="afterClean ? 'ok' : 'bad'">
              {{ afterClean ? '✓ ' + zh.fixAfterOk : zh.fixAfterBad }}
            </p>
          </section>

          <section>
            <h3>{{ zh.fixEdits(result.edits.length) }}</h3>
            <p v-if="result.edits.length === 0" class="muted">{{ zh.fixNoEdits }}</p>
            <ul v-else class="items">
              <li v-for="(e, i) in result.edits" :key="i">
                <div class="item-head">
                  <span class="id">{{ e.id }}</span>
                  <span class="where">{{ zh.fixLine(e.line) }}</span>
                  <code class="ypath">{{ e.path }}</code>
                </div>
                <div class="change">
                  <code class="line del"><span class="op">-</span>{{ e.before }}</code>
                  <code v-if="e.after" class="line add"><span class="op">+</span>{{ e.after }}</code>
                  <span v-else class="deleted">{{ zh.fixDeleted }}</span>
                </div>
              </li>
            </ul>
          </section>

          <section v-if="result.skipped.length > 0">
            <h3>{{ zh.fixSkipped(result.skipped.length) }}</h3>
            <ul class="items">
              <li v-for="(s, i) in result.skipped" :key="i">
                <div class="item-head">
                  <span class="id">{{ s.id }}</span>
                  <span v-if="skipWhere(s)" class="where">{{ skipWhere(s) }}</span>
                  <code class="ypath">{{ s.path }}</code>
                </div>
                <p class="reason">{{ s.reason_text }}</p>
              </li>
            </ul>
          </section>

          <section v-if="rows.length > 0">
            <h3>{{ zh.fixDiff }}</h3>
            <div class="diff" tabindex="0" :aria-label="zh.fixDiff">
              <div class="diff-body">
                <div v-for="(r, i) in rows" :key="i" class="dl" :class="r.kind">
                  <span class="no" :style="{width: gutterChars + 'ch'}">{{ r.old ?? '' }}</span>
                  <span class="no" :style="{width: gutterChars + 'ch'}">{{ r.new ?? '' }}</span>
                  <span class="text">{{ r.text }}</span>
                </div>
              </div>
            </div>
          </section>
        </template>
      </div>

      <footer>
        <p v-if="saveError" class="save-error" role="alert">{{ saveError.message }}</p>
        <div class="buttons">
          <span v-if="result && result.edits.length > 0" class="default-name" :title="result.output">
            {{ zh.fixDefaultName(baseName(result.output)) }}
          </span>
          <button class="primary" type="button" :disabled="!canSave" @click="emit('save')">
            {{ saving ? zh.fixSaving : zh.fixSave }}
          </button>
          <button type="button" @click="emit('close')">{{ zh.fixClose }}</button>
        </div>
      </footer>
    </section>
  </div>
</template>

<style scoped>
.backdrop {
  position: fixed;
  inset: 0;
  z-index: 10;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  background: var(--backdrop);
}
.dialog {
  display: flex;
  flex-direction: column;
  width: min(980px, 100%);
  max-height: 100%;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--bg);
  outline: none;
  overflow: hidden;
}
header {
  display: flex;
  align-items: baseline;
  gap: 12px;
  padding: 12px 16px;
  border-bottom: 1px solid var(--border);
  background: var(--panel);
  min-width: 0;
}
h2 {
  margin: 0;
  font-size: 16px;
  white-space: nowrap;
}
.path {
  font-family: var(--mono);
  font-size: 12px;
  color: var(--muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.content {
  flex: 1;
  min-height: 0;
  overflow: auto;
  padding: 12px 16px;
}
.content > section {
  margin-bottom: 14px;
}
h3 {
  margin: 0 0 6px;
  font-size: 13px;
  color: var(--muted);
  font-weight: 600;
}
.state {
  display: flex;
  align-items: center;
  gap: 10px;
  margin: 24px 0;
  justify-content: center;
  font-weight: 600;
}
.spinner {
  width: 16px;
  height: 16px;
  border: 2px solid var(--border);
  border-top-color: var(--accent);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}
@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
.error-box {
  padding: 12px 14px;
  border: 1px solid var(--sev-high);
  border-left-width: 4px;
  border-radius: 6px;
  background: var(--panel);
}
.error-box h3 {
  color: var(--sev-high);
  font-size: 15px;
}
.error-box p {
  margin: 4px 0;
  line-height: 1.6;
  word-break: break-word;
}
.note {
  margin: 0 0 12px;
  color: var(--muted);
}
.muted {
  margin: 0;
  color: var(--muted);
}
.sums {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 10px 12px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--panel);
}
.sum-row {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px;
}
.sum-title {
  min-width: 4em;
  font-weight: 600;
}
.chip {
  padding: 1px 9px;
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
.verdict {
  margin: 2px 0 0;
  font-weight: 600;
}
.verdict.ok {
  color: var(--ok);
}
.verdict.bad {
  color: var(--sev-medium);
}
.items {
  margin: 0;
  padding: 0;
  list-style: none;
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.items li {
  padding: 8px 10px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--panel);
}
.item-head {
  display: flex;
  align-items: baseline;
  flex-wrap: wrap;
  gap: 4px 10px;
}
.id {
  font-family: var(--mono);
  font-weight: 600;
}
.where {
  font-size: 12px;
  color: var(--accent);
}
.ypath {
  font-family: var(--mono);
  font-size: 12px;
  color: var(--muted);
}
.change {
  display: flex;
  flex-direction: column;
  gap: 2px;
  margin-top: 6px;
}
.line {
  display: block;
  padding: 1px 6px;
  border-radius: 3px;
  font-family: var(--mono);
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
}
.line .op {
  user-select: none;
  margin-right: 6px;
}
.line.add {
  background: var(--diff-add-bg);
  color: var(--diff-add-fg);
}
.line.del {
  background: var(--diff-del-bg);
  color: var(--diff-del-fg);
}
.deleted {
  font-size: 12px;
  color: var(--diff-del-fg);
  background: var(--diff-del-bg);
  padding: 1px 6px;
  border-radius: 3px;
  align-self: flex-start;
}
.reason {
  margin: 4px 0 0;
  line-height: 1.6;
}
.diff {
  overflow-x: auto;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--code-bg);
}
.diff-body {
  width: max-content;
  min-width: 100%;
  padding: 4px 0;
}
.dl {
  display: flex;
  font-family: var(--mono);
  font-size: 12px;
  line-height: 18px;
  white-space: pre;
}
.dl .no {
  flex: none;
  box-sizing: content-box;
  padding: 0 6px;
  text-align: right;
  color: var(--muted);
  user-select: none;
}
.dl .text {
  padding: 0 12px 0 4px;
}
.dl.add {
  background: var(--diff-add-bg);
  color: var(--diff-add-fg);
}
.dl.del {
  background: var(--diff-del-bg);
  color: var(--diff-del-fg);
}
.dl.add .no,
.dl.del .no {
  color: inherit;
  opacity: 0.7;
}
.dl.hunk {
  background: var(--diff-hunk-bg);
  color: var(--diff-hunk-fg);
}
.dl.nonl .text {
  color: var(--muted);
  font-style: italic;
}
footer {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 10px 16px;
  border-top: 1px solid var(--border);
  background: var(--panel);
}
.save-error {
  margin: 0;
  color: var(--sev-high);
  line-height: 1.6;
  word-break: break-word;
}
.buttons {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 8px;
}
.default-name {
  flex: 1;
  min-width: 0;
  font-size: 12px;
  color: var(--muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>
