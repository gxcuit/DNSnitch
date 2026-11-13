import {ref, shallowRef, watch, type Ref} from 'vue'
import {PlanFix, SaveFix} from '../../wailsjs/go/main/App'
import type {main, report} from '../../wailsjs/go/models'
import {INTERNAL_ERROR} from './useCheck'

function errText(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

/**
 * useFix owns the auto-fix preview. The backend computes the fix for the
 * config of the latest Check (PlanFix) and writes it to a path chosen in
 * the native save dialog (SaveFix); the frontend never supplies content or
 * a path. After a successful save, `check` (from useCheck) runs on the
 * saved file so the window switches to its results.
 *
 * Any Check that starts (`checking` turns true) closes the preview: the
 * backend drops the stored plan at the same moment. Results of a
 * superseded PlanFix / SaveFix are dropped.
 */
export function useFix(check: (path: string) => Promise<void>, checking: Ref<boolean>) {
  const open = ref(false)
  const loading = ref(false)
  const result = shallowRef<report.FixResult | null>(null)
  const error = shallowRef<main.GUIError | null>(null)
  const saving = ref(false)
  const saveError = shallowRef<main.GUIError | null>(null)

  let fixSeq = 0

  function reset() {
    fixSeq++
    loading.value = false
    result.value = null
    error.value = null
    saving.value = false
    saveError.value = null
  }

  async function openPreview() {
    reset()
    const seq = fixSeq
    open.value = true
    loading.value = true
    try {
      const r = await PlanFix()
      if (seq !== fixSeq) return
      result.value = r.result ?? null
      error.value = r.error ?? null
    } catch (e) {
      if (seq === fixSeq) error.value = {kind: INTERNAL_ERROR, message: errText(e)}
    } finally {
      if (seq === fixSeq) loading.value = false
    }
  }

  async function save() {
    if (!result.value || result.value.edits.length === 0 || saving.value) return
    const seq = fixSeq
    saving.value = true
    saveError.value = null
    let saved = ''
    try {
      const r = await SaveFix()
      if (seq !== fixSeq) return
      if (r.error) saveError.value = r.error
      else if (r.path) saved = r.path
      // cancelled: keep the preview open as it is
    } catch (e) {
      if (seq === fixSeq) saveError.value = {kind: INTERNAL_ERROR, message: errText(e)}
    } finally {
      if (seq === fixSeq) saving.value = false
    }
    if (saved) {
      close()
      await check(saved)
    }
  }

  function close() {
    reset()
    open.value = false
  }

  watch(checking, (c) => {
    if (c && open.value) close()
  })

  return {open, loading, result, error, saving, saveError, openPreview, save, close}
}
