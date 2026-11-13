// Labels of the GUI chrome (buttons, headings, empty states).
// Finding text, severity / role / resolver names and error messages come
// from the Go backend (internal/report/messages_zh.go) and must not be
// repeated here.
export const zh = {
  chooseFile: '选择配置文件',
  recheck: '重新检查',
  noFileTitle: '检查 mihomo 配置中的 DNS 泄露',
  noFileHint: '点击「选择配置文件」，或把配置文件拖入窗口。',
  dropHint: '松开鼠标以检查该文件',
  onlyFirstDropped: (n: number) => `拖入了 ${n} 个文件，只检查第一个。`,
  checking: '正在检查…',
  statusOk: '未发现泄露风险',
  statusOkDetail: '没有「错误 / 高 / 中」等级的问题。',
  statusBad: '发现需要处理的问题',
  findingsTitle: (n: number) => `检查结果（${n} 项）`,
  noFindings: '没有任何检查结果。',
  locations: '位置',
  fix: '修复建议',
  notes: '假设与说明',
  showAllLocations: (n: number) => `显示全部 ${n} 个位置`,
  showFewerLocations: '收起',
  // Layout of the resolver annotation; the role / level / source names come
  // from the backend labels.
  resolver: (role: string, level: string, source: string) => `${role}：${level}（${source}）`,
  sourceTitle: '配置原文',
  ruleSetTitle: '规则集文件',
  sourceEmpty: '点击左侧问题中的位置，在此查看原文。',
  sourceLoading: '正在读取文件…',
  sourceEmptyFile: '（空文件）',
  errorTitle: {
    read: '无法读取配置文件',
    parse: '配置文件解析失败',
    encrypted: '配置文件已加密',
    internal: '检查失败',
  } as Record<string, string>,
  errorHint: '可以修改配置后点击「重新检查」，或选择其他文件。',
  // System status bar. Item names, state names, evidence, conclusion and
  // remedy text come from the backend (StatusView).
  systemStatus: '系统状态',
  refreshStatus: '刷新',
  statusChecking: '正在检测…',
  statusFailed: (msg: string) => `系统状态检测失败：${msg}`,
  statusItem: (title: string, label: string) => `${title}：${label}`,
  statusEvidence: '检测依据',
  statusFix: '处理方法（仅供参考，本工具不会执行）',
  // Auto-fix preview. Skip reasons, error messages and severity names come
  // from the backend (FixResult, GUIError, labels).
  autoFix: (n: number) => `自动修复（${n} 项）`,
  fixTitle: '自动修复预览',
  fixLoading: '正在生成修复…',
  fixFailed: '无法生成修复',
  fixNote: '修复结果只会保存为新文件，原配置文件不会被修改。',
  fixSummaryBefore: '修复前',
  fixSummaryAfter: '修复后',
  fixAfterOk: '修复后没有「错误 / 高 / 中」等级的问题。',
  fixAfterBad: '修复后仍有需要手动处理的问题，保存后可在检查结果中查看。',
  fixEdits: (n: number) => `将修改（${n} 处）`,
  fixNoEdits: '没有可自动修改的内容。',
  fixSkipped: (n: number) => `未自动修改（${n} 处），需要手动处理`,
  fixLine: (n: number) => `第 ${n} 行`,
  fixDeleted: '（删除此行）',
  fixDiff: '差异',
  fixNoNewline: '\\ 文件末尾没有换行符',
  fixDefaultName: (name: string) => `默认文件名：${name}`,
  fixSave: '保存修复后的配置…',
  fixSaving: '正在保存…',
  fixClose: '关闭',
}
