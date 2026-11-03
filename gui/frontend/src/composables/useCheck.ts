import {computed, ref, shallowRef} from 'vue'
import {Check, ChooseFile, Labels, ReadSource} from '../../wailsjs/go/main/App'
import type {main, model, report} from '../../wailsjs/go/models'
import {zh} from '../i18n/zh'

/** Kind used when the bound call itself fails (not a config problem). */
export const INTERNAL_ERROR = 'internal'

export interface Selection {
  finding: number
  location: number
}

function errText(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

/**
 * useCheck owns the whole GUI state: the checked file, the result from
 * the backend (kept in backend order), the selected location and the
 * source view. Results of superseded requests are dropped.
 */
export function useCheck() {
  const currentFile = ref('')
  const result = shallowRef<report.CheckResult | null>(null)
  const error = shallowRef<main.GUIError | null>(null)
  const loading = ref(false)
  const notice = ref('')
  const labels = shallowRef<report.Labels | null>(null)

  const selected = ref<Selection | null>(null)
  const sourcePath = ref('')
  const source = shallowRef<main.SourceFile | null>(null)
  const sourceError = ref('')
  const sourceLoading = ref(false)
  const highlightLine = ref(0)
  const reveal = ref(0) // bumped on every source request, to re-scroll to the same line
  const version = ref(0) // bumped on every new check result

  let checkSeq = 0
  let sourceSeq = 0

  /** True when there is no error / high / medium finding. */
  const isClean = computed(() => {
    const s = result.value?.summary
    return !!s && s.error + s.high + s.medium === 0
  })

  async function loadLabels() {
    try {
      labels.value = await Labels()
    } catch {
      labels.value = null // codes are shown as-is
    }
  }

  async function openSource(file: string, line: number) {
    highlightLine.value = line
    reveal.value++
    if (file === sourcePath.value && (source.value || sourceLoading.value)) {
      return
    }
    const seq = ++sourceSeq
    sourcePath.value = file
    source.value = null
    sourceError.value = ''
    sourceLoading.value = true
    try {
      const s = await ReadSource(file)
      if (seq === sourceSeq) source.value = s
    } catch (e) {
      if (seq === sourceSeq) sourceError.value = errText(e)
    } finally {
      if (seq === sourceSeq) sourceLoading.value = false
    }
  }

  function resetSource() {
    sourceSeq++
    sourcePath.value = ''
    source.value = null
    sourceError.value = ''
    sourceLoading.value = false
    highlightLine.value = 0
  }

  async function check(path: string, message = '') {
    if (!path) return
    const seq = ++checkSeq
    currentFile.value = path
    notice.value = message
    loading.value = true
    selected.value = null
    resetSource()
    try {
      const r = await Check(path)
      if (seq !== checkSeq) return
      version.value++
      result.value = r.result ?? null
      error.value = r.error ?? null
      if (r.result) {
        currentFile.value = r.result.file
        void openSource(r.result.file, 0)
      } else if (r.error?.kind === 'parse') {
        void openSource(path, 0)
      }
    } catch (e) {
      if (seq !== checkSeq) return
      result.value = null
      error.value = {kind: INTERNAL_ERROR, message: errText(e)}
    } finally {
      if (seq === checkSeq) loading.value = false
    }
  }

  async function choose() {
    try {
      const path = await ChooseFile()
      if (path) await check(path)
    } catch (e) {
      notice.value = errText(e)
    }
  }

  function recheck() {
    if (currentFile.value) void check(currentFile.value)
  }

  function onDropped(paths: string[]) {
    if (!paths || paths.length === 0) return
    void check(paths[0], paths.length > 1 ? zh.onlyFirstDropped(paths.length) : '')
  }

  function selectLocation(sel: Selection, loc: model.Location) {
    selected.value = sel
    void openSource(loc.file, loc.line)
  }

  return {
    currentFile, result, error, loading, notice, labels, isClean,
    selected, sourcePath, source, sourceError, sourceLoading, highlightLine, reveal, version,
    loadLabels, check, choose, recheck, onDropped, selectLocation,
  }
}
