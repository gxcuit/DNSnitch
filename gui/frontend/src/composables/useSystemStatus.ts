import {ref, shallowRef} from 'vue'
import {SystemStatus} from '../../wailsjs/go/main/App'
import type {report} from '../../wailsjs/go/models'

/**
 * useSystemStatus owns the system status bar: TUN mode and smart
 * multi-homed name resolution, inspected read-only by the backend. It is
 * independent of the config check (useCheck). Results of a superseded
 * refresh are dropped.
 */
export function useSystemStatus() {
  const status = shallowRef<report.StatusView | null>(null)
  const statusError = ref('')
  const statusLoading = ref(false)

  let statusSeq = 0

  async function refreshStatus() {
    const seq = ++statusSeq
    statusLoading.value = true
    statusError.value = ''
    try {
      const s = await SystemStatus()
      if (seq === statusSeq) status.value = s
    } catch (e) {
      if (seq === statusSeq) {
        status.value = null
        statusError.value = e instanceof Error ? e.message : String(e)
      }
    } finally {
      if (seq === statusSeq) statusLoading.value = false
    }
  }

  return {status, statusError, statusLoading, refreshStatus}
}
