<script setup lang="ts">
import {computed, nextTick, onBeforeUnmount, onMounted, ref, watch} from 'vue'
import type {main} from '../../wailsjs/go/models'
import {zh} from '../i18n/zh'

const props = defineProps<{
  path: string
  configFile: string
  source: main.SourceFile | null
  loading: boolean
  error: string
  line: number
  /** Incremented on every location click, so the same line can be revealed again. */
  reveal: number
}>()

// Rows have a fixed height so only the visible lines are rendered; rule-set
// files can have tens of thousands of lines.
const ROW = 20
const OVERSCAN = 30

const scroller = ref<HTMLElement | null>(null)
const scrollTop = ref(0)
const viewHeight = ref(600)
let observer: ResizeObserver | null = null

const lines = computed(() => props.source?.lines ?? [])
const gutterChars = computed(() => String(Math.max(lines.value.length, 1)).length)
const start = computed(() => Math.max(0, Math.floor(scrollTop.value / ROW) - OVERSCAN))
const end = computed(() =>
  Math.min(lines.value.length, Math.ceil((scrollTop.value + viewHeight.value) / ROW) + OVERSCAN),
)
const visible = computed(() => {
  const out: {n: number; text: string}[] = []
  for (let i = start.value; i < end.value; i++) out.push({n: i + 1, text: lines.value[i]})
  return out
})
const isRuleSet = computed(() => !!props.path && props.path !== props.configFile)

function onScroll() {
  if (scroller.value) scrollTop.value = scroller.value.scrollTop
}

async function revealLine() {
  await nextTick()
  const el = scroller.value
  if (!el || !props.source) return
  if (props.line <= 0) {
    el.scrollTop = 0
  } else {
    el.scrollTop = Math.max(0, (props.line - 1) * ROW - el.clientHeight / 2 + ROW / 2)
  }
  scrollTop.value = el.scrollTop
}

// Re-run on every selection (even of the same line) and on new content.
watch(() => [props.source, props.line, props.path, props.reveal] as const, revealLine)

onMounted(() => {
  if (!scroller.value) return
  viewHeight.value = scroller.value.clientHeight
  observer = new ResizeObserver(() => {
    if (scroller.value) viewHeight.value = scroller.value.clientHeight
  })
  observer.observe(scroller.value)
})
onBeforeUnmount(() => observer?.disconnect())
</script>

<template>
  <section class="source">
    <header>
      <span class="title">{{ isRuleSet ? zh.ruleSetTitle : zh.sourceTitle }}</span>
      <span class="path" :title="path">{{ path }}</span>
    </header>
    <div ref="scroller" class="scroller" @scroll.passive="onScroll">
      <p v-if="!path" class="state">{{ zh.sourceEmpty }}</p>
      <p v-else-if="loading" class="state">{{ zh.sourceLoading }}</p>
      <p v-else-if="error" class="state error">{{ error }}</p>
      <p v-else-if="source && lines.length === 0" class="state">{{ zh.sourceEmptyFile }}</p>
      <div v-else-if="source" class="canvas" :style="{height: lines.length * ROW + 'px'}">
        <div class="rows" :style="{transform: `translateY(${start * ROW}px)`}">
          <div
            v-for="r in visible"
            :key="r.n"
            class="row"
            :class="{hl: r.n === line}"
            :style="{height: ROW + 'px'}"
          >
            <span class="no" :style="{width: gutterChars + 1 + 'ch'}">{{ r.n }}</span>
            <span class="code">{{ r.text }}</span>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.source {
  display: flex;
  flex-direction: column;
  min-height: 0;
  height: 100%;
}
header {
  display: flex;
  gap: 10px;
  align-items: baseline;
  padding: 8px 12px;
  border-bottom: 1px solid var(--border);
  min-width: 0;
}
.title {
  font-weight: 600;
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
.scroller {
  flex: 1;
  overflow: auto;
  min-height: 0;
  background: var(--code-bg);
}
.state {
  padding: 12px;
  margin: 0;
  color: var(--muted);
}
.state.error {
  color: var(--sev-high);
}
.canvas {
  position: relative;
}
.rows {
  position: absolute;
  top: 0;
  left: 0;
  width: max-content;
  min-width: 100%;
}
.row {
  display: flex;
  font-family: var(--mono);
  font-size: 13px;
  line-height: 20px;
  white-space: pre;
}
.row.hl {
  background: var(--highlight);
  box-shadow: inset 3px 0 0 var(--accent);
}
.no {
  flex: none;
  padding-right: 12px;
  text-align: right;
  color: var(--muted);
  user-select: none;
  box-sizing: content-box;
  padding-left: 8px;
}
.code {
  padding-right: 16px;
}
</style>
