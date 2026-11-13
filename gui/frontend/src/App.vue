<script setup lang="ts">
import {onBeforeUnmount, onMounted, ref} from 'vue'
import {OnFileDrop, OnFileDropOff} from '../wailsjs/runtime/runtime'
import FindingList from './components/FindingList.vue'
import FixPreview from './components/FixPreview.vue'
import SourceView from './components/SourceView.vue'
import SummaryBar from './components/SummaryBar.vue'
import SystemStatusBar from './components/SystemStatusBar.vue'
import {useCheck} from './composables/useCheck'
import {useFix} from './composables/useFix'
import {useSystemStatus} from './composables/useSystemStatus'
import {zh} from './i18n/zh'

const {
  currentFile, result, error, loading, notice, labels, isClean,
  selected, sourcePath, source, sourceError, sourceLoading, highlightLine, reveal, version,
  loadLabels, check, choose, recheck, onDropped, selectLocation,
} = useCheck()

// Auto-fix preview; a successful save checks the saved file, and any new
// Check closes the preview.
const {
  open: fixOpen, loading: fixLoading, result: fixResult, error: fixError,
  saving: fixSaving, saveError: fixSaveError,
  openPreview, save: saveFix, close: closeFix,
} = useFix(check, loading)

const {status, statusError, statusLoading, refreshStatus} = useSystemStatus()

// Drop overlay: dragenter / dragleave fire for every child element, so
// count them. The dropped paths come from the Wails runtime (absolute).
const dragDepth = ref(0)
const hasFiles = (e: DragEvent) => !!e.dataTransfer?.types.includes('Files')
function onDragEnter(e: DragEvent) {
  if (hasFiles(e)) dragDepth.value++
}
function onDragLeave(e: DragEvent) {
  if (hasFiles(e)) dragDepth.value = Math.max(0, dragDepth.value - 1)
}
function onDrop() {
  dragDepth.value = 0
}

let dropRegistered = false
onMounted(() => {
  void loadLabels()
  void refreshStatus()
  window.addEventListener('dragenter', onDragEnter)
  window.addEventListener('dragleave', onDragLeave)
  window.addEventListener('drop', onDrop)
  try {
    // Registers the runtime's window drop listener; useDropTarget = false
    // means a drop anywhere in the window counts.
    OnFileDrop((_x: number, _y: number, paths: string[]) => onDropped(paths), false)
    dropRegistered = true
  } catch {
    // Wails runtime not present (plain `vite` dev server): no file drop.
  }
})
onBeforeUnmount(() => {
  window.removeEventListener('dragenter', onDragEnter)
  window.removeEventListener('dragleave', onDragLeave)
  window.removeEventListener('drop', onDrop)
  if (dropRegistered) OnFileDropOff()
})
</script>

<template>
  <div class="app">
    <SummaryBar
      :current-file="currentFile"
      :result="result"
      :loading="loading"
      :is-clean="isClean"
      :labels="labels"
      :notice="notice"
      @choose="choose"
      @recheck="recheck"
      @autofix="openPreview"
    />
    <SystemStatusBar
      :status="status"
      :error="statusError"
      :loading="statusLoading"
      @refresh="refreshStatus"
    />

    <main class="body">
      <div v-if="!currentFile" class="welcome">
        <h2>{{ zh.noFileTitle }}</h2>
        <p>{{ zh.noFileHint }}</p>
        <button class="primary" type="button" @click="choose">{{ zh.chooseFile }}</button>
      </div>

      <template v-else>
        <div class="left">
          <div v-if="error" class="error-box">
            <h3>{{ zh.errorTitle[error.kind] ?? zh.errorTitle.internal }}</h3>
            <p>{{ error.message }}</p>
            <p class="hint">{{ zh.errorHint }}</p>
          </div>
          <FindingList
            v-else-if="result"
            :key="version"
            :findings="result.findings"
            :labels="labels"
            :selected="selected"
            @select="selectLocation"
          />
        </div>
        <div class="right">
          <SourceView
            :path="sourcePath"
            :config-file="result?.file ?? currentFile"
            :source="source"
            :loading="sourceLoading"
            :error="sourceError"
            :line="highlightLine"
            :reveal="reveal"
          />
        </div>
      </template>

      <div v-if="loading" class="overlay">
        <div class="spinner" aria-hidden="true"></div>
        <span>{{ zh.checking }}</span>
      </div>
    </main>

    <FixPreview
      v-if="fixOpen"
      :result="fixResult"
      :error="fixError"
      :loading="fixLoading"
      :saving="fixSaving"
      :save-error="fixSaveError"
      :labels="labels"
      @save="saveFix"
      @close="closeFix"
    />

    <div v-if="dragDepth > 0" class="drop-overlay">{{ zh.dropHint }}</div>
  </div>
</template>

<style scoped>
.app {
  display: flex;
  flex-direction: column;
  height: 100vh;
}
.body {
  position: relative;
  flex: 1;
  min-height: 0;
  display: flex;
}
.left {
  flex: 0 0 46%;
  min-width: 360px;
  overflow: auto;
  border-right: 1px solid var(--border);
}
.right {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
}
.welcome {
  margin: auto;
  text-align: center;
  color: var(--muted);
}
.welcome h2 {
  color: var(--fg);
}
.error-box {
  margin: 12px;
  padding: 12px 14px;
  border: 1px solid var(--sev-high);
  border-left-width: 4px;
  border-radius: 6px;
  background: var(--panel);
}
.error-box h3 {
  margin: 0 0 6px;
  color: var(--sev-high);
  font-size: 15px;
}
.error-box p {
  margin: 4px 0;
  line-height: 1.6;
  word-break: break-word;
}
.error-box .hint {
  color: var(--muted);
  font-size: 12px;
}
.overlay {
  position: absolute;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  background: var(--veil);
  font-weight: 600;
}
.spinner {
  width: 18px;
  height: 18px;
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
.drop-overlay {
  position: fixed;
  inset: 8px;
  z-index: 20;
  display: flex;
  align-items: center;
  justify-content: center;
  border: 3px dashed var(--accent);
  border-radius: 10px;
  background: var(--veil);
  font-size: 18px;
  font-weight: 600;
  pointer-events: none;
}
</style>
