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
}
