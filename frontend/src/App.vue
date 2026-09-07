<script setup>
import { EventsOn } from '../wailsjs/runtime/runtime'
import { ref, reactive, onMounted, onBeforeUnmount, computed } from 'vue'
import { ElNotification } from 'element-plus'
import { GetConfig, SetConfig, GenerateCert, InstallCert, UninstallCert, StartProxy, StopProxy, Test, GetDevices, StartIPCapture, StopIPCapture, GetDataDir, CertStatus, Download, ExportHAR, Replay, SaveRewriteRules, SaveDecryptRule, DefaultRewriteRules, DefaultDecryptRule, GetStatus, GetPendingBreakpoints, ResolveBreakpoint, ReleaseAllBreakpoints, SaveBreakpointConfig, SaveWebSocketConfig, GetTCPStreams, GetTCPStream, ResetTCPStreams, SaveTCPStreamConfig, CopyAsCurl } from '../wailsjs/go/main/App'

const data = reactive({
  config: {
    // Breakpoint / WebSocket 需要预置：GetConfig 返回前模板就会访问它们的字段
    HTTP: {
      Breakpoint: { Enabled: false, OnRequest: true, OnResponse: false, URLRegex: "", Method: "", TimeoutSeconds: 60 },
      WebSocket: { Enabled: false, MaxPayloadBytes: 4096 },
    },
    IP: {
      TCPStream: { Enabled: false, MaxStreamBytes: 65536, MaxStreams: 256, IdleSeconds: 60 },
    },
  },
  resultText: "",
  devices: [],
  selectdevice: null,
  dataDir: "",
  cert: { Generated: false, TrustedScopes: [], CertPath: "", NotAfter: "" },
  // status 由后端推送：代理可能自己异常停止，只在点击后刷新会显示错
  status: { HTTPStatus: 0, IPStatus: 0, Port: 0, AutoProxy: false, RewriteRuleCount: 0, BreakpointEnabled: false, PendingBreakpoints: 0 },
  // 被断点挂住的请求，后端推送
  breakpoints: [],
  bpEdit: {
    visible: false,
    id: "",
    phase: "request",
    method: "GET",
    url: "",
    statusCode: 0,
    headerText: "",
    body: "",
    bodyBinary: false,
  },
  downloads: {},
  replay: {
    visible: false,
    method: "GET",
    url: "",
    headerText: "",
    body: "",
    truncated: false,
  },
  // follow 是"跟随流"视图，载荷按需拉取而不随列表推送
  follow: {
    visible: false,
    loading: false,
    detail: null,
  },
  // view 是显示过滤：只影响看到什么，不丢弃任何已抓到的记录。
  // 与配置里的抓取过滤不同，后者会在入库前直接丢弃且不可恢复。
  view: {
    keyword: "",
    methods: [],
    statusClasses: [],
    kinds: [],
    // deep 打开后关键字还会搜请求头与正文。正文可能很大，
    // 逐条扫描明显更慢，因此默认只搜 URL 等短字段
    deep: false,
    onlyRewritten: false,
  },
})

// 表格高度实测得来，不再用"窗口高 - 魔数"估算：
// 头部行数会随折叠面板展开、文字换行而变化，估算必然对不上，
// 结果是整页出现滚动条、头部与分页器被滚出视野。
const httpBodyRef = ref(null)
const ipBodyRef = ref(null)
const wsBodyRef = ref(null)
const streamBodyRef = ref(null)
const httpBodyHeight = ref(400)
const ipBodyHeight = ref(400)
const wsBodyHeight = ref(400)
const streamBodyHeight = ref(400)

// 分页栏在表格滚动区之外，table-height 只管滚动区，
// 因此要给它留出高度，否则分页器会被容器裁掉
const FOOTER_RESERVE = 56
const MIN_TABLE_HEIGHT = 160

const httpTableHeight = computed(() =>
  Math.max(MIN_TABLE_HEIGHT, httpBodyHeight.value - FOOTER_RESERVE))
const ipTableHeight = computed(() =>
  Math.max(MIN_TABLE_HEIGHT, ipBodyHeight.value - FOOTER_RESERVE))
const wsTableHeight = computed(() =>
  Math.max(MIN_TABLE_HEIGHT, wsBodyHeight.value - FOOTER_RESERVE))
const streamTableHeight = computed(() =>
  Math.max(MIN_TABLE_HEIGHT, streamBodyHeight.value - FOOTER_RESERVE))

let observers = []

// observeHeight 跟随容器实际高度更新表格高度。
// 标签页切换时未激活的面板高度为 0，此时保留上一次的值。
function observeHeight(elRef, target) {
  const el = elRef.value
  if (!el || typeof ResizeObserver === 'undefined') {
    return
  }
  const ro = new ResizeObserver(entries => {
    const h = Math.floor(entries[0].contentRect.height)
    if (h > 0) {
      target.value = h
    }
  })
  ro.observe(el)
  observers.push(ro)
}

onMounted(() => {
  GetConfig().then(config => {
    data.config = config
  })
  refreshCertStatus()
  GetStatus().then(s => {
    data.status = s
    if (s.Cert) {
      data.cert = s.Cert
    }
  })
  GetDataDir().then(dir => {
    data.dataDir = dir
  })
  GetPendingBreakpoints().then(list => {
    data.breakpoints = list || []
  })
  GetTCPStreams().then(list => {
    streamTableData.splice(0, streamTableData.length, ...(list || []))
  })
  observeHeight(httpBodyRef, httpBodyHeight)
  observeHeight(ipBodyRef, ipBodyHeight)
  observeHeight(wsBodyRef, wsBodyHeight)
  observeHeight(streamBodyRef, streamBodyHeight)
})

onBeforeUnmount(() => {
  observers.forEach(ro => ro.disconnect())
  observers = []
})


EventsOn("status", function (s) {
  data.status = s
  if (s.Cert) {
    data.cert = s.Cert
  }
});

EventsOn("breakpoints", function (list) {
  data.breakpoints = list || []
});

// 断点：放行 / 中止 / 编辑后放行
function resolveBreakpoint(hit, action) {
  ResolveBreakpoint({ ID: hit.ID, Action: action }).then(err => {
    if (err != null) {
      ElNotification({ title: 'Error', message: err.Message, type: 'error' })
    }
  })
}

function openBreakpointEditor(hit) {
  Object.assign(data.bpEdit, {
    visible: true,
    id: hit.ID,
    phase: hit.Phase,
    method: hit.Method || 'GET',
    url: hit.URL || '',
    statusCode: hit.StatusCode || 0,
    headerText: headerToText(hit.Header),
    body: hit.BodyBinary ? '' : (hit.Body || ''),
    bodyBinary: !!hit.BodyBinary,
  })
}

function submitBreakpointEdit() {
  const e = data.bpEdit
  data.bpEdit.visible = false
  const payload = {
    ID: e.id,
    Action: 'modify',
    Header: textToHeader(e.headerText),
    // 二进制正文不允许编辑，留空表示不改动
    Body: e.bodyBinary ? '' : e.body,
  }
  if (e.phase === 'request') {
    payload.Method = e.method
    payload.URL = e.url
  } else {
    payload.StatusCode = Number(e.statusCode) || 0
  }
  ResolveBreakpoint(payload).then(err => {
    if (err != null) {
      ElNotification({ title: 'Error', message: err.Message, type: 'error' })
    }
  })
}

function releaseAllBreakpoints() {
  ReleaseAllBreakpoints().then(notifyResult)
}

function saveBreakpointConfig() {
  SaveBreakpointConfig(data.config.HTTP.Breakpoint).then(notifyResult)
}

// 抓包与抓包设备的运行状态
const httpRunning = computed(() => data.status.HTTPStatus === 2)
const ipRunning = computed(() => data.status.IPStatus === 2)

// 证书状态归成三档，界面用不同颜色区分
const certLevel = computed(() => {
  const c = data.cert
  if (!c.Generated) {
    return { text: '证书未生成', type: 'danger' }
  }
  if (!c.TrustedScopes || c.TrustedScopes.length === 0) {
    return { text: '证书未安装', type: 'warning' }
  }
  const names = c.TrustedScopes.map(s => (s === 'machine' ? '本机' : '当前用户')).join('、')
  return { text: `证书已信任（${names}）`, type: 'success' }
})

function refreshCertStatus() {
  CertStatus().then(status => {
    data.cert = status
  })
}

// 证书状态提示：文件存在不等于系统已信任，两者要分开说
const certHint = computed(() => {
  const c = data.cert
  if (!c.Generated) {
    return '证书未生成，请先点击“生成证书”再“安装证书”'
  }
  const scopes = c.TrustedScopes || []
  if (scopes.length === 0) {
    return `证书已生成（有效期至 ${c.NotAfter}）但系统尚未信任，请点击“安装证书”`
  }
  const names = scopes.map(s => (s === 'machine' ? '本机' : '当前用户')).join('、')
  let hint = `证书已被系统信任（${names}，有效期至 ${c.NotAfter}）`
  if (!scopes.includes('machine')) {
    hint += '。Firefox 使用独立证书库，需手工导入 ' + c.CertPath
  }
  return hint
})

const activeName = ref('HTTP')

const handleTabChange = (tab, event) => {
  console.log(activeName.value, tab, event)
  if (activeName.value == "IP") {
    getDevices()
  }
}

EventsOn("error", function (v) {
  ElNotification({
    title: 'Error',
    message: v.Message,
    type: 'error',
  })
});

EventsOn("Test", function (v) {
  data.resultText = v
});

// 后端的通知类事件（安装证书结果、下载完成、导出完成等）
EventsOn("response", function (v) {
  ElNotification({
    title: '提示',
    message: v.Message,
    type: 'success',
    duration: 6000,
  })
});

EventsOn("DownloadProgress", function (p) {
  if (p.Done) {
    delete data.downloads[p.ID]
    return
  }
  const percent = p.Total > 0 ? Math.floor((p.Downloaded / p.Total) * 100) : -1
  data.downloads[p.ID] = { name: p.FileName, percent, downloaded: p.Downloaded, total: p.Total }
});




// 表格数据只保留最近的记录，长时间抓包时无上限追加会耗尽 WebView 内存
const MAX_ROWS = 5000

// 后端按 100ms 时间窗聚合成批推送，减少 IPC 调用次数
function pushBatch(list, items) {
  if (!items || items.length === 0) {
    return
  }
  list.push(...items)
  if (list.length > MAX_ROWS) {
    list.splice(0, list.length - MAX_ROWS)
  }
}

const packetTypeText = { 0: '请求', 1: '响应', 2: '隧道' }
const resourceTypeText = {
  text: '文本', image: '图片', audio: '音频',
  video: '视频', document: '文档', other: '其他',
}

const httpheaders = [
  { value: 'Date', text: '日期', width: 150, fixed: true },
  { value: 'TypeText', text: '类型', width: 60, fixed: true },
  { value: 'Method', text: '方式', width: 70 },
  { value: 'Host', text: '域名', width: 190 },
  // 地址不设固定宽度，吃掉剩余空间：URL 最需要展示长度
  { value: 'Path', text: '地址' },
  { value: 'KindText', text: '资源', width: 70 },
  { value: 'Proto', text: '协议', width: 80 },
  { value: 'ContentType', text: '内容类型', width: 150 },
  { value: 'StatusCode', text: '状态', width: 70 },
  { value: 'Duration', text: '耗时(ms)', width: 90 }
];
const httpTableData = reactive([
])
EventsOn("HTTPPackets", function (list) {
  for (const p of list) {
    p.TypeText = packetTypeText[p.HTTPPacketType ?? 0] ?? '-'
    p.KindText = p.ResourceType ? (resourceTypeText[p.ResourceType] ?? p.ResourceType) : '-'
  }
  pushBatch(httpTableData, list)
});

// 关键字支持空格分隔的多个词，全部命中才算匹配；
// 以 - 开头的词表示排除，例如 "api -png" 找带 api 又不含 png 的记录
function parseTerms(keyword) {
  const include = []
  const exclude = []
  for (const raw of keyword.toLowerCase().split(/\s+/)) {
    if (!raw) {
      continue
    }
    if (raw.startsWith('-')) {
      if (raw.length > 1) {
        exclude.push(raw.slice(1))
      }
      continue
    }
    include.push(raw)
  }
  return { include, exclude }
}

// 浅层只拼短字段，避免每次过滤都去扫可能上兆的正文
function shallowHaystack(item) {
  return [item.Method, item.Host, item.Path, item.URL,
    item.ContentType, item.StatusCode, item.Proto].join(' ').toLowerCase()
}

function deepHaystack(item) {
  const parts = [shallowHaystack(item)]
  for (const header of [item.Header, item.RequestHeader]) {
    if (!header) {
      continue
    }
    for (const name of Object.keys(header)) {
      parts.push(name, header[name].join(' '))
    }
  }
  if (item.Body) {
    parts.push(item.Body)
  }
  return parts.join(' ').toLowerCase()
}

const httpViewData = computed(() => {
  const v = data.view
  const { include, exclude } = parseTerms(v.keyword)
  const hasKeyword = include.length > 0 || exclude.length > 0
  const noFilter = !hasKeyword && v.methods.length === 0 &&
    v.statusClasses.length === 0 && v.kinds.length === 0 && !v.onlyRewritten
  if (noFilter) {
    return httpTableData
  }

  return httpTableData.filter(item => {
    if (v.methods.length && !v.methods.includes(item.Method)) {
      return false
    }
    // 请求记录没有状态码，按状态过滤时它们无从判断，一律排除
    if (v.statusClasses.length) {
      const cls = item.StatusCode ? `${Math.floor(item.StatusCode / 100)}xx` : ''
      if (!v.statusClasses.includes(cls)) {
        return false
      }
    }
    if (v.kinds.length && !v.kinds.includes(item.ResourceType || 'other')) {
      return false
    }
    if (v.onlyRewritten && !(item.Rewritten && item.Rewritten.length)) {
      return false
    }
    if (!hasKeyword) {
      return true
    }
    const hay = v.deep ? deepHaystack(item) : shallowHaystack(item)
    return include.every(t => hay.includes(t)) && !exclude.some(t => hay.includes(t))
  })
})

const httpViewFiltered = computed(() => httpViewData.value.length !== httpTableData.length)

function resetHTTPView() {
  Object.assign(data.view, {
    keyword: "", methods: [], statusClasses: [], kinds: [],
    deep: false, onlyRewritten: false,
  })
}

function copyAsCurl(item) {
  CopyAsCurl(item).then(notifyResult)
}


const tcpheaders = [
  { value: 'Date', text: '日期', width: 150, fixed: true },
  { value: 'ApplicationLayer', text: '应用层', width: 90, fixed: true },
  { value: 'SrcMAC', text: 'SrcMAC', width: 130 },
  { value: 'DstMAC', text: 'DstMAC', width: 130 },
  { value: 'SrcIP', text: 'SrcIP' },
  { value: 'DstIP', text: 'DstIP' },
  { value: 'Protocol', text: '协议', width: 70 },
  { value: 'SrcPort', text: 'SrcPort', width: 90 },
  { value: 'DstPort', text: 'DstPort', width: 90 },
  { value: 'Length', text: '长度', width: 70 },
];
const tcpTableData = reactive([
])
EventsOn("IPPackets", function (list) {
  pushBatch(tcpTableData, list)
});

const wsDirectionText = { send: '↑ 客户端', recv: '↓ 服务端' }

const wsheaders = [
  { value: 'Date', text: '日期', width: 150, fixed: true },
  { value: 'Direction', text: '方向', width: 100, fixed: true },
  { value: 'OpcodeName', text: '类型', width: 90 },
  { value: 'PayloadLen', text: '长度', width: 90 },
  { value: 'URL', text: 'URL' },
];
const wsTableData = reactive([
])
EventsOn("WSFrames", function (list) {
  pushBatch(wsTableData, list)
});

// 帧解析在每次握手时读配置，无需重启代理；已建立的连接要重连才生效
function saveWebSocketConfig() {
  SaveWebSocketConfig(data.config.HTTP.WebSocket).then(notifyResult)
}

function clearWSFrames() {
  wsTableData.splice(0, wsTableData.length)
}

const streamheaders = [
  { value: 'Date', text: '开始', width: 150, fixed: true },
  { value: 'ClientAddr', text: '客户端', width: 170 },
  { value: 'ServerAddr', text: '服务端', width: 170 },
  { value: 'ClientBytes', text: '上行', width: 100 },
  { value: 'ServerBytes', text: '下行', width: 100 },
  { value: 'MissingBytes', text: '缺失', width: 90 },
  { value: 'Closed', text: '状态', width: 90 },
  { value: 'operation', text: '操作', width: 110 },
];
const streamTableData = reactive([
])

// 推送的是整张流表快照：流会持续变化，追加式更新会出现重复行
EventsOn("TCPStreams", function (list) {
  streamTableData.splice(0, streamTableData.length, ...(list || []))
});

// 载荷按需拉取：流是长期变化的，随列表一起推送会让传输量高出几个数量级
function followStream(item) {
  data.follow.visible = true
  data.follow.loading = true
  data.follow.detail = null
  GetTCPStream(item.ID).then(detail => {
    data.follow.loading = false
    if (detail == null) {
      ElNotification({ title: 'Error', message: '该流已不在记录中', type: 'error' })
      data.follow.visible = false
      return
    }
    data.follow.detail = detail
  })
}

function resetTCPStreams() {
  ResetTCPStreams().then(notifyResult)
}

// formatSize 把 0 当作"未知"（响应体长度缺失时确实如此），
// 但流的方向字节数 0 是确定的事实，不能混为一谈
function formatBytes(n) {
  return n ? formatSize(n) : '0 B'
}


function saveTCPStreamConfig() {
  SaveTCPStreamConfig(data.config.IP.TCPStream).then(notifyResult)
}




function generateCert() {
  GenerateCert().then(err => {
    refreshCertStatus()
    if (err == null) {
      ElNotification({
        title: 'Success',
        message: "生成证书成功",
        type: 'success',
      })
    } else {
      ElNotification({
        title: 'Error',
        message: err.Message,
        type: 'error',
      })
    }
  })
}


// 安装证书成功时返回的是 NOTICE 事件（Type 1），里面带有装到哪个存储的说明；
// 只有 ERROR（Type 2）才是失败
function installCert() {
  InstallCert().then(result => {
    refreshCertStatus()
    if (result == null) {
      return
    }
    ElNotification({
      title: result.Type === 2 ? 'Error' : 'Success',
      message: result.Message,
      type: result.Type === 2 ? 'error' : 'success',
      duration: 8000,
    })
  })
}


function uninstallCert() {
  UninstallCert().then(err => {
    refreshCertStatus()
    if (err == null) {
      ElNotification({
        title: 'Success',
        message: "卸载证书成功",
        type: 'success',
      })
    } else {
      ElNotification({
        title: 'Error',
        message: err.Message,
        type: 'error',
      })
    }
  })
}

function getDevices() {
  GetDevices().then(result => {
    data.devices = result
  })
}

function startProxy() {
  StartProxy().then(err => {
    if (err == null) {
      ElNotification({
        title: 'Success',
        message: "启动成功",
        type: 'success',
      })
    } else {
      ElNotification({
        title: 'Error',
        message: err.Message,
        type: 'error',
      })
    }
  })
}

function stopProxy() {
  StopProxy().then(err => {
    if (err == null) {
      ElNotification({
        title: 'Success',
        message: "停止成功",
        type: 'success',
      })
    } else {
      ElNotification({
        title: 'Error',
        message: err.Message,
        type: 'error',
      })
    }
  })
}

// 只有响应记录才有可下载的资源
function canDownload(item) {
  return item.HTTPPacketType === 1 && !!item.URL
}

// 隧道记录不是 HTTP 往返，没有可重放的内容
function canReplay(item) {
  return item.HTTPPacketType !== 2 && !!item.URL
}

// 图片与音视频尝试内联预览。预览走的是 WebView 自己的请求，
// 带防盗链的站点可能加载失败，因此始终同时提供下载入口。
function canPreviewInline(item) {
  return ['image', 'audio', 'video'].includes(item.ResourceType)
}

function downloadResource(item) {
  Download(item).then(err => {
    if (err != null) {
      ElNotification({ title: 'Error', message: err.Message, type: 'error' })
    }
  })
}

// 请求记录带完整的请求头与请求体；
// 响应记录只保留了请求头，重放时请求体为空
function replayDraftFrom(item) {
  const header = item.HTTPPacketType === 0 ? item.Header : item.RequestHeader
  return {
    method: item.Method || 'GET',
    url: item.URL || '',
    headerText: headerToText(header),
    body: item.HTTPPacketType === 0 ? (item.Body || '') : '',
    truncated: item.HTTPPacketType === 0 && !!item.BodyTruncated,
  }
}

function headerToText(header) {
  if (!header) {
    return ''
  }
  const lines = []
  for (const name of Object.keys(header).sort()) {
    for (const value of header[name]) {
      lines.push(`${name}: ${value}`)
    }
  }
  return lines.join('\n')
}

// 解析 "Name: Value" 形式的多行文本，同名头允许出现多次
function textToHeader(text) {
  const header = {}
  for (const line of text.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed) {
      continue
    }
    const i = trimmed.indexOf(':')
    if (i <= 0) {
      continue
    }
    const name = trimmed.slice(0, i).trim()
    const value = trimmed.slice(i + 1).trim()
    if (!header[name]) {
      header[name] = []
    }
    header[name].push(value)
  }
  return header
}

// 直接按原样重放
function replayDirect(item) {
  const draft = replayDraftFrom(item)
  if (draft.truncated) {
    ElNotification({
      title: '提示',
      message: '该请求体超出记录上限已被截断，原样重放会发出不完整的数据，请改用“编辑重放”确认内容',
      type: 'warning',
      duration: 8000,
    })
    return
  }
  sendReplay(draft)
}

// 打开对话框，允许改完再发
function openReplayDialog(item) {
  Object.assign(data.replay, replayDraftFrom(item), { visible: true })
}

function submitReplay() {
  data.replay.visible = false
  sendReplay(data.replay)
}

function sendReplay(draft) {
  Replay({
    Method: draft.method,
    URL: draft.url,
    Header: textToHeader(draft.headerText),
    Body: draft.body,
  }).then(err => {
    if (err != null) {
      ElNotification({ title: 'Error', message: err.Message, type: 'error' })
    }
  })
}


// 导出当前看到的内容。但 HAR 是按 ID 配对请求与响应的，
// 如果过滤只留下了一半（比如按状态码筛，请求记录没有状态码会被排除），
// 直接导出会丢掉另一半，因此按命中记录的 ID 把配对的那条补回来。
function exportHar() {
  const view = httpViewData.value
  let packets
  if (view.length === httpTableData.length) {
    packets = httpTableData.slice()
  } else {
    const ids = new Set(view.map(p => p.ID).filter(Boolean))
    packets = httpTableData.filter(p => (p.ID ? ids.has(p.ID) : view.includes(p)))
  }
  ExportHAR(packets).then(result => {
    if (result == null) {
      return // 用户取消
    }
    ElNotification({
      title: result.Type === 2 ? 'Error' : 'Success',
      message: result.Message,
      type: result.Type === 2 ? 'error' : 'success',
      duration: 8000,
    })
  })
}

function formatSize(n) {
  if (!n || n < 0) {
    return '未知'
  }
  const units = ['B', 'KB', 'MB', 'GB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

// ApplicationPayload 经 JSON 传输后是 base64 字符串，这里解成可读文本
function formatPayload(b64) {
  if (!b64) {
    return "[no data]"
  }
  try {
    const bin = atob(b64)
    let text = ""
    for (let i = 0; i < bin.length; i++) {
      const code = bin.charCodeAt(i)
      text += (code === 9 || code === 10 || code === 13 || (code >= 32 && code < 127))
        ? bin[i]
        : "."
    }
    return `${bin.length} bytes\n${text}`
  } catch (e) {
    return "[decode error]"
  }
}

// 规则是多行文本，不做失焦自动保存：显式点保存才写入，
// 用户才能确定改动到底生效了没有
function notifyResult(result) {
  if (result == null) {
    return
  }
  ElNotification({
    title: result.Type === 2 ? 'Error' : 'Success',
    message: result.Message,
    type: result.Type === 2 ? 'error' : 'success',
    duration: result.Type === 2 ? 10000 : 4000,
  })
}

function saveDecryptRule() {
  SaveDecryptRule(data.config.HTTP.Rule || '').then(notifyResult)
}

function resetDecryptRule() {
  DefaultDecryptRule().then(text => {
    data.config.HTTP.Rule = text
    return SaveDecryptRule(text)
  }).then(notifyResult)
}

function saveRewriteRules() {
  SaveRewriteRules(data.config.HTTP.RewriteRules || '').then(notifyResult)
}

function resetRewriteRules() {
  DefaultRewriteRules().then(text => {
    data.config.HTTP.RewriteRules = text
    return SaveRewriteRules(text)
  }).then(notifyResult)
}

// 格式化只在本地做，不保存，方便先看清结构再决定是否提交
function formatRewriteRules() {
  const text = (data.config.HTTP.RewriteRules || '').trim()
  if (!text) {
    return
  }
  try {
    data.config.HTTP.RewriteRules = JSON.stringify(JSON.parse(text), null, 2)
  } catch (e) {
    ElNotification({ title: 'Error', message: 'JSON 格式错误：' + e.message, type: 'error', duration: 10000 })
  }
}

// 清除数据要清干净：四张表都清，否则用户以为清了却还看到旧记录。
// TCP 流表在后端，得让后端也清一次
function clear() {
  httpTableData.length = 0;
  tcpTableData.length = 0;
  wsTableData.length = 0;
  ResetTCPStreams();
}

function test() {
  Test().then(result => {
    //data.resultText = result
    console.log(result)
  })
}


function handleChange(field) {

  SetConfig(field, data.config).then(result => {
    //data.resultText = result
    if (result == null) {
      ElNotification({
        title: 'Success',
        message: '配置修改成功',
        type: 'success',
      })
    }
  })
}

function startIPCapture() {
  StartIPCapture(data.selectdevice).then(err => {
    if (err == null) {
      ElNotification({
        title: 'Success',
        message: "启动成功",
        type: 'success',
      })
    } else {
      ElNotification({
        title: 'Error',
        message: err.Message,
        type: 'error',
      })
    }
  })
}

function stopIPCapture() {
  StopIPCapture().then(err => {
    if (err == null) {
      ElNotification({
        title: 'Success',
        message: "停止成功",
        type: 'success',
      })
    } else {
      ElNotification({
        title: 'Error',
        message: err.Message,
        type: 'error',
      })
    }
  })
}
</script>

<template>
  <el-tabs type="border-card" v-model="activeName" class="main-tabs" @tab-change="handleTabChange">
    <el-tab-pane label="HTTP" name="HTTP">
      <div class="pane">
        <div class="pane-header">
      <el-row style="margin-bottom:5px">
        <el-col>
          <el-space wrap>
            <el-button type="primary" round @click="installCert">安装证书</el-button>
            <el-button type="success" round @click="generateCert">生成证书</el-button>
            <el-button type="warning" round @click="uninstallCert">卸载证书</el-button>
            <el-button-group>
              <el-button type="primary" @click="startProxy" :disabled="httpRunning">启动服务</el-button>
              <el-button type="warning" @click="stopProxy" :disabled="!httpRunning">停止服务</el-button>
              <el-button type="danger" @click="clear">清除数据</el-button>
            </el-button-group>
            <el-button type="info" round @click="exportHar">导出 HAR</el-button>
            <el-tag :type="httpRunning ? 'success' : 'info'" effect="dark" size="large">
              {{ httpRunning ? `抓包中 · 127.0.0.1:${data.status.Port}` : '未抓包' }}
            </el-tag>
            <el-tag :type="certLevel.type" effect="plain">{{ certLevel.text }}</el-tag>
            <el-tag v-if="data.status.RewriteRuleCount > 0" type="danger" effect="plain">
              改包 {{ data.status.RewriteRuleCount }} 条
            </el-tag>
            <el-tag v-if="data.status.BreakpointEnabled" type="warning" effect="dark">
              断点已开启{{ data.status.PendingBreakpoints > 0 ? ` · ${data.status.PendingBreakpoints} 个待处理` : '' }}
            </el-tag>
          </el-space>
        </el-col>
      </el-row>
      <el-row style="margin-bottom:5px">
        <el-col>
          <el-space wrap>
            <el-text>端口号</el-text><el-input-number v-model="data.config.HTTP.Port" @change="handleChange('HTTP.Port')"
              :controls="false" aria-label="端口号" />
            <el-switch v-model="data.config.HTTP.AutoProxy" inline-prompt active-text="自动代理" inactive-text="自动代理"
              @change="handleChange('HTTP.AutoProxy')" />
            <el-switch v-model="data.config.HTTP.SaveLogFile" inline-prompt active-text="保存到文件" inactive-text="保存到文件"
              @change="handleChange('HTTP.SaveLogFile')" class="item" />
            <el-switch v-model="data.config.HTTP.AllowHTTP2" inline-prompt active-text="HTTP/2" inactive-text="HTTP/2"
              @change="handleChange('HTTP.AllowHTTP2')" class="item" />
            <el-input v-model="data.config.HTTP.FilterHost" style="max-width: 200px" placeholder="Please input"
              @change="handleChange('HTTP.FilterHost')" class="item">
              <template #prepend>Host</template>
            </el-input>
            <el-input v-model="data.config.HTTP.UpstreamProxy" style="max-width: 240px"
              placeholder="http://127.0.0.1:7890" @change="handleChange('HTTP.UpstreamProxy')" class="item">
              <template #prepend>上游代理</template>
            </el-input>
          </el-space>
        </el-col>
      </el-row>
      <el-row style="margin-bottom:5px">
        <el-col>
          <el-collapse>
            <el-collapse-item name="rule">
              <template #title>
                <span>解密规则（未列入的域名只做转发，不解密）</span>
              </template>
              <el-input v-model="data.config.HTTP.Rule" type="textarea" :rows="8"
                placeholder="* 全部匹配；*.a.com 匹配域名及子域；!前缀 表示排除；# 为注释" />
              <el-space wrap style="margin-top: 8px">
                <el-button type="primary" size="small" @click="saveDecryptRule">保存规则</el-button>
                <el-button size="small" @click="resetDecryptRule">恢复默认</el-button>
              </el-space>
              <el-text size="small" type="info">
                做了证书固定的客户端（微信、部分银行 App）必须用 ! 排除，否则它们会无法联网。保存后立即生效，无需重启服务。
              </el-text>
            </el-collapse-item>
            <el-collapse-item name="rewrite">
              <template #title>
                <span>改包规则（按规则改写请求与响应）</span>
              </template>
              <el-input v-model="data.config.HTTP.RewriteRules" type="textarea" :rows="12"
                placeholder="JSON 数组，见下方字段说明" />
              <el-space wrap style="margin-top: 8px">
                <el-button type="primary" size="small" @click="saveRewriteRules">保存规则</el-button>
                <el-button size="small" @click="formatRewriteRules">格式化</el-button>
                <el-button size="small" @click="resetRewriteRules">恢复默认</el-button>
              </el-space>
              <el-text size="small" type="info">
                字段：Enabled 是否启用；Name 备注；Phase 为 request 或 response；
                URLRegex 匹配完整 URL 的正则（留空不限制）；Method 限定方法（留空不限制）；
                SetHeaders 设置头；RemoveHeaders 删除头；Replacements 正文字符串替换；
                StatusCode 改写响应状态码。
                匹配条件全留空会作用于所有流量，请至少填一个。
                压缩过的响应会先解压再替换，并去掉 Content-Encoding。
                保存后立即生效；JSON 有误时不会写入，并提示具体原因。
              </el-text>
            </el-collapse-item>
            <el-collapse-item name="breakpoint">
              <template #title>
                <span>断点（挂住请求等你处理，调试用，默认关闭）</span>
              </template>
              <el-space wrap>
                <el-switch v-model="data.config.HTTP.Breakpoint.Enabled" inline-prompt active-text="启用断点"
                  inactive-text="启用断点" />
                <el-switch v-model="data.config.HTTP.Breakpoint.OnRequest" inline-prompt active-text="拦请求"
                  inactive-text="拦请求" />
                <el-switch v-model="data.config.HTTP.Breakpoint.OnResponse" inline-prompt active-text="拦响应"
                  inactive-text="拦响应" />
                <el-input v-model="data.config.HTTP.Breakpoint.URLRegex" style="width: 260px"
                  placeholder="URL 正则，留空会拦下所有流量">
                  <template #prepend>URL</template>
                </el-input>
                <el-input v-model="data.config.HTTP.Breakpoint.Method" style="width: 150px" placeholder="留空不限制">
                  <template #prepend>方式</template>
                </el-input>
                <el-input v-model.number="data.config.HTTP.Breakpoint.TimeoutSeconds" style="width: 170px">
                  <template #prepend>超时(秒)</template>
                </el-input>
                <el-button type="primary" size="small" @click="saveBreakpointConfig">保存配置</el-button>
              </el-space>
              <el-text size="small" type="info">
                断点会真的把请求挂住，超时秒数是无人处理时自动放行的兜底，不填会被纠正为默认 60 秒。
                URL 留空且启用会拦下所有流量，等于把网络挂死，请务必填写匹配条件。
                停止代理服务时会自动放行所有挂住的请求。
              </el-text>
            </el-collapse-item>
          </el-collapse>
        </el-col>
      </el-row>
      <el-row style="margin-bottom:5px">
        <el-col>
          <el-space wrap>
            <el-input v-model="data.view.keyword" style="width: 300px" clearable
              placeholder="关键字，空格分隔多个词，-词 表示排除">
              <template #prepend>查找</template>
            </el-input>
            <el-select v-model="data.view.methods" multiple collapse-tags clearable placeholder="方式"
              style="width: 150px">
              <el-option v-for="m in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'CONNECT']" :key="m"
                :label="m" :value="m" />
            </el-select>
            <el-select v-model="data.view.statusClasses" multiple collapse-tags clearable placeholder="状态"
              style="width: 140px">
              <el-option v-for="s in ['2xx', '3xx', '4xx', '5xx']" :key="s" :label="s" :value="s" />
            </el-select>
            <el-select v-model="data.view.kinds" multiple collapse-tags clearable placeholder="资源"
              style="width: 150px">
              <el-option v-for="(label, key) in resourceTypeText" :key="key" :label="label" :value="key" />
            </el-select>
            <el-switch v-model="data.view.deep" inline-prompt active-text="含头与正文" inactive-text="含头与正文" />
            <el-switch v-model="data.view.onlyRewritten" inline-prompt active-text="仅改包" inactive-text="仅改包" />
            <el-button size="small" @click="resetHTTPView">重置</el-button>
            <el-text size="small" :type="httpViewFiltered ? 'warning' : 'info'">
              {{ httpViewFiltered ? `命中 ${httpViewData.length} / 共 ${httpTableData.length}` : `共 ${httpTableData.length} 条` }}
            </el-text>
          </el-space>
        </el-col>
      </el-row>
      <el-row style="margin-bottom:5px">
        <el-col>
          <el-text size="small" type="info">
            查找只影响显示，不会丢弃已抓到的记录；上方 Host 是抓取过滤，不匹配的记录会被直接丢弃且无法恢复。
            "含头与正文"会逐条扫描正文，记录多时明显更慢。
          </el-text>
        </el-col>
      </el-row>
      <el-row style="margin-bottom:5px">
        <el-col>
          <el-text size="small" type="info">
            {{ certHint }}，数据目录：{{ data.dataDir }}
          </el-text>
        </el-col>
      </el-row>
        </div>
        <div class="pane-body" ref="httpBodyRef">
      <el-alert v-if="data.breakpoints.length" type="warning" :closable="false" style="margin-bottom: 8px">
        <template #title>
          <el-space wrap>
            <span>{{ data.breakpoints.length }} 个请求被断点挂住，处理后才会继续</span>
            <el-button size="small" @click="releaseAllBreakpoints">全部放行</el-button>
          </el-space>
        </template>
        <div v-for="hit in data.breakpoints" :key="hit.ID" style="margin-top: 6px">
          <el-space wrap>
            <el-tag size="small" :type="hit.Phase === 'request' ? 'primary' : 'success'">
              {{ hit.Phase === 'request' ? '请求' : '响应' }}
            </el-tag>
            <span>{{ hit.Method }} {{ hit.URL }}</span>
            <el-tag v-if="hit.StatusCode" size="small" type="info">{{ hit.StatusCode }}</el-tag>
            <el-tag size="small" type="warning">{{ hit.DeadlineSeconds }}s 后自动放行</el-tag>
            <el-button type="success" size="small" @click="resolveBreakpoint(hit, 'resume')">放行</el-button>
            <el-button size="small" @click="openBreakpointEditor(hit)">编辑后放行</el-button>
            <el-button type="danger" size="small" @click="resolveBreakpoint(hit, 'abort')">中止</el-button>
          </el-space>
        </div>
      </el-alert>
      <EasyDataTable :headers="httpheaders" :items="httpViewData" :table-height="httpTableHeight">
        <template #expand="item">
          <div style="padding: 15px">
            <el-space wrap style="margin-bottom: 8px">
              <el-button v-if="canDownload(item)" type="primary" size="small" @click="downloadResource(item)">
                下载（{{ formatSize(item.ContentLength) }}）
              </el-button>
              <el-button v-if="canReplay(item)" type="success" size="small" @click="replayDirect(item)">
                重放
              </el-button>
              <el-button v-if="canReplay(item)" size="small" @click="openReplayDialog(item)">
                编辑重放
              </el-button>
              <el-button v-if="canReplay(item)" size="small" @click="copyAsCurl(item)">
                复制为 cURL
              </el-button>
              <el-text v-if="item.BodyTruncated" size="small" type="warning">正文已截断</el-text>
              <el-text v-if="item.Rewritten && item.Rewritten.length" size="small" type="danger">
                已被改包规则改写：{{ item.Rewritten.join('、') }}
              </el-text>
              <el-text v-if="data.downloads[item.ID]" size="small" type="warning">
                正在下载 {{ data.downloads[item.ID].name }}
                <span v-if="data.downloads[item.ID].percent >= 0">{{ data.downloads[item.ID].percent }}%</span>
                <span v-else>{{ formatSize(data.downloads[item.ID].downloaded) }}</span>
              </el-text>
            </el-space>

            <!-- 图片与音视频尝试内联预览，失败时仍可用上面的下载按钮 -->
            <div v-if="canPreviewInline(item)" style="margin-bottom: 8px">
              <img v-if="item.ResourceType === 'image'" :src="item.URL" style="max-width: 400px; max-height: 300px" />
              <video v-else-if="item.ResourceType === 'video'" :src="item.URL" controls
                style="max-width: 480px; max-height: 320px"></video>
              <audio v-else :src="item.URL" controls></audio>
            </div>

            <span v-for="(values, name) in item.Header" v-bind:key="name">
              <p>{{ name }}: {{ values.join(",") }}</p>
            </span>
            <pre v-if="item.ResourceType === 'text' || !item.ResourceType">{{ item.Body }}</pre>
            <el-text v-else size="small" type="info">{{ item.Body }}</el-text>
          </div>
        </template>
      </EasyDataTable>
        </div>
      </div>
    </el-tab-pane>
    <el-tab-pane label="IP" name="IP">
      <div class="pane">
        <div class="pane-header">
      <el-row style="margin-bottom:5px" :gutter="10">
        <el-col :span="6">
          <el-select v-model="data.selectdevice" placeholder="选择设备" clearable>
            <el-option v-for="item in data.devices" :key="item.Name" :label="item.Description" :value="item.Name" />
          </el-select>
        </el-col>
        <el-col :span="18">
          <el-space wrap>
            <el-button type="primary" round @click="getDevices">获取</el-button>
            <el-button-group>
              <el-button type="primary" @click="startIPCapture" :disabled="ipRunning">启动服务</el-button>
              <el-button type="warning" @click="stopIPCapture" :disabled="!ipRunning">停止服务</el-button>
            </el-button-group>
            <el-tag :type="ipRunning ? 'success' : 'info'" effect="dark" size="large">
              {{ ipRunning ? '抓包中' : '未抓包' }}
            </el-tag>
          </el-space>
        </el-col>
      </el-row>
      <el-row style="margin-bottom:5px">
        <el-col>
          <el-space wrap>
            <el-input v-model="data.config.IP.Filter" @change="handleChange('IP.Filter')" style="max-width: 600px" placeholder="请输入过滤条件">
              <template #prepend>过滤条件</template>
            </el-input>
            <el-input-number v-model="data.config.IP.Snaplen" @change="handleChange('IP.Snaplen')" :controls="false"
              aria-label="数据包长度">
              <template #prefix>
                <span>数据包长度</span>
              </template>
            </el-input-number>
            <el-text>超时时间</el-text><el-input-number v-model="data.config.IP.Timeout"
              @change="handleChange('IP.Timeout')" :controls="false" aria-label="超时时间">
              <template #suffix>
                <span>毫秒</span>
              </template>
            </el-input-number>
            <el-switch v-model="data.config.IP.Promisc" inline-prompt active-text="混杂模式" inactive-text="混杂模式"
              @change="handleChange('IP.Promisc')" />
            <el-switch v-model="data.config.IP.SavePcapFile" inline-prompt active-text="存为 pcap" inactive-text="存为 pcap"
              @change="handleChange('IP.SavePcapFile')" />
          </el-space>
        </el-col>
      </el-row>
        </div>
        <div class="pane-body" ref="ipBodyRef">
      <EasyDataTable :headers="tcpheaders" :items="tcpTableData" :table-height="ipTableHeight">
        <template #expand="item">
          <div style="padding: 15px">
            <p>ApplicationLayer: {{ item.ApplicationLayer || '-' }}</p>
            <pre>{{ formatPayload(item.ApplicationPayload) }}</pre>
          </div>
        </template>
      </EasyDataTable>
        </div>
      </div>
    </el-tab-pane>
    <el-tab-pane label="WebSocket" name="WS">
      <div class="pane">
        <div class="pane-header">
          <el-alert type="info" :closable="false" show-icon style="margin-bottom:5px"
            title="调试用途，默认关闭。开启后代理会在转发路径上旁路解析每一帧，只观察不修改；已建立的连接需重连后生效。" />
          <el-row style="margin-bottom:5px">
            <el-col>
              <el-space wrap>
                <el-switch v-model="data.config.HTTP.WebSocket.Enabled" inline-prompt active-text="解析帧"
                  inactive-text="解析帧" />
                <el-text>单帧留存</el-text>
                <el-input-number v-model="data.config.HTTP.WebSocket.MaxPayloadBytes" :min="1" :max="1048576"
                  :controls="false" aria-label="单帧留存字节数">
                  <template #suffix>
                    <span>字节</span>
                  </template>
                </el-input-number>
                <el-button type="primary" @click="saveWebSocketConfig">保存</el-button>
                <el-button @click="clearWSFrames">清空</el-button>
                <el-tag :type="data.config.HTTP.WebSocket.Enabled ? 'success' : 'info'" effect="dark" size="large">
                  {{ data.config.HTTP.WebSocket.Enabled ? '解析中' : '未解析' }}
                </el-tag>
              </el-space>
            </el-col>
          </el-row>
        </div>
        <div class="pane-body" ref="wsBodyRef">
          <EasyDataTable :headers="wsheaders" :items="wsTableData" :table-height="wsTableHeight">
            <template #item-Direction="item">
              <el-tag :type="item.Direction === 'send' ? 'warning' : 'success'" size="small">
                {{ wsDirectionText[item.Direction] || item.Direction }}
              </el-tag>
            </template>
            <template #item-PayloadLen="item">
              {{ item.PayloadLen }}<span v-if="item.Truncated"> (截断)</span>
            </template>
            <template #expand="item">
              <div style="padding: 15px">
                <p>连接: {{ item.ConnID || '-' }} / FIN: {{ item.Fin }} / 掩码: {{ item.Masked }} / opcode: {{ item.Opcode }}
                </p>
                <el-alert v-if="item.Compressed" type="warning" :closable="false" show-icon
                  title="该连接协商了 permessage-deflate，载荷是 deflate 流，下面显示的是压缩后的原始字节。" style="margin-bottom:8px" />
                <pre>{{ formatPayload(item.Payload) }}</pre>
              </div>
            </template>
          </EasyDataTable>
        </div>
      </div>
    </el-tab-pane>
    <el-tab-pane label="TCP 流" name="Stream">
      <div class="pane">
        <div class="pane-header">
          <el-alert type="info" :closable="false" show-icon style="margin-bottom:5px"
            title="调试用途，默认关闭。单个报文只能看到片段，重组按序列号把两个方向各自拼成连续字节流。开关改动需要重启 IP 抓包后生效。" />
          <el-row style="margin-bottom:5px">
            <el-col>
              <el-space wrap>
                <el-switch v-model="data.config.IP.TCPStream.Enabled" inline-prompt active-text="流重组"
                  inactive-text="流重组" />
                <el-text>单向留存</el-text>
                <el-input-number v-model="data.config.IP.TCPStream.MaxStreamBytes" :min="1" :max="4194304"
                  :controls="false" aria-label="单向留存字节数">
                  <template #suffix>
                    <span>字节</span>
                  </template>
                </el-input-number>
                <el-text>最多流数</el-text>
                <el-input-number v-model="data.config.IP.TCPStream.MaxStreams" :min="1" :max="4096" :controls="false"
                  aria-label="最多跟踪流数" />
                <el-text>空闲回收</el-text>
                <el-input-number v-model="data.config.IP.TCPStream.IdleSeconds" :min="1" :max="3600" :controls="false"
                  aria-label="空闲回收秒数">
                  <template #suffix>
                    <span>秒</span>
                  </template>
                </el-input-number>
                <el-button type="primary" @click="saveTCPStreamConfig">保存</el-button>
                <el-button @click="resetTCPStreams">清空</el-button>
              </el-space>
            </el-col>
          </el-row>
        </div>
        <div class="pane-body" ref="streamBodyRef">
          <EasyDataTable :headers="streamheaders" :items="streamTableData" :table-height="streamTableHeight">
            <template #item-ClientBytes="item">{{ formatBytes(item.ClientBytes) }}</template>
            <template #item-ServerBytes="item">{{ formatBytes(item.ServerBytes) }}</template>
            <template #item-MissingBytes="item">
              <el-text v-if="item.MissingBytes > 0" type="warning">{{ formatBytes(item.MissingBytes) }}</el-text>
              <span v-else>-</span>
            </template>
            <template #item-Closed="item">
              <el-tag :type="item.Closed ? 'info' : 'success'" size="small">
                {{ item.Closed ? '已关闭' : '进行中' }}
              </el-tag>
            </template>
            <template #item-operation="item">
              <el-button link type="primary" @click="followStream(item)">跟随流</el-button>
            </template>
          </EasyDataTable>
        </div>
      </div>
    </el-tab-pane>
  </el-tabs>

  <el-dialog v-model="data.follow.visible" title="跟随 TCP 流" width="820px">
    <div v-if="data.follow.loading">加载中…</div>
    <div v-else-if="data.follow.detail">
      <p>{{ data.follow.detail.ClientAddr }} → {{ data.follow.detail.ServerAddr }}</p>
      <el-alert v-if="data.follow.detail.MissingBytes > 0" type="warning" :closable="false" show-icon
        :title="`有 ${data.follow.detail.MissingBytes} 字节缺失（丢包或抓包开始于连接中途），下面的内容并不连续。`"
        style="margin-bottom:8px" />
      <el-tabs>
        <el-tab-pane :label="`上行 ${formatBytes(data.follow.detail.ClientBytes)}`">
          <el-text v-if="data.follow.detail.ClientTruncated" type="warning">只留存了前一段</el-text>
          <pre class="stream-payload">{{ formatPayload(data.follow.detail.ClientPayload) }}</pre>
        </el-tab-pane>
        <el-tab-pane :label="`下行 ${formatBytes(data.follow.detail.ServerBytes)}`">
          <el-text v-if="data.follow.detail.ServerTruncated" type="warning">只留存了前一段</el-text>
          <pre class="stream-payload">{{ formatPayload(data.follow.detail.ServerPayload) }}</pre>
        </el-tab-pane>
      </el-tabs>
    </div>
    <template #footer>
      <el-button @click="data.follow.visible = false">关闭</el-button>
    </template>
  </el-dialog>

  <el-dialog v-model="data.replay.visible" title="编辑并重放" width="720px">
    <el-form label-width="70px">
      <el-form-item label="方式">
        <el-select v-model="data.replay.method" style="width: 140px">
          <el-option v-for="m in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']" :key="m" :label="m"
            :value="m" />
        </el-select>
      </el-form-item>
      <el-form-item label="地址">
        <el-input v-model="data.replay.url" placeholder="https://example.com/api" />
      </el-form-item>
      <el-form-item label="请求头">
        <el-input v-model="data.replay.headerText" type="textarea" :rows="8"
          placeholder="每行一条，格式 Name: Value" />
      </el-form-item>
      <el-form-item label="请求体">
        <el-input v-model="data.replay.body" type="textarea" :rows="6" />
      </el-form-item>
    </el-form>
    <el-text v-if="data.replay.truncated" size="small" type="warning">
      原请求体已被截断，请确认内容完整后再发送
    </el-text>
    <el-text size="small" type="info">
      重放经由本机代理发出，结果会作为新记录出现在列表中。Content-Length 等长度相关的头会自动重算。
    </el-text>
    <template #footer>
      <el-button @click="data.replay.visible = false">取消</el-button>
      <el-button type="primary" @click="submitReplay">发送</el-button>
    </template>
  </el-dialog>

  <el-dialog v-model="data.bpEdit.visible" title="编辑并放行" width="720px">
    <el-form label-width="70px">
      <el-form-item v-if="data.bpEdit.phase === 'request'" label="方式">
        <el-select v-model="data.bpEdit.method" style="width: 140px">
          <el-option v-for="m in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']" :key="m" :label="m"
            :value="m" />
        </el-select>
      </el-form-item>
      <el-form-item v-if="data.bpEdit.phase === 'request'" label="地址">
        <el-input v-model="data.bpEdit.url" />
      </el-form-item>
      <el-form-item v-else label="状态码">
        <el-input v-model.number="data.bpEdit.statusCode" style="width: 140px" />
      </el-form-item>
      <el-form-item label="头">
        <el-input v-model="data.bpEdit.headerText" type="textarea" :rows="8"
          placeholder="每行一条，格式 Name: Value" />
      </el-form-item>
      <el-form-item label="正文">
        <el-input v-model="data.bpEdit.body" type="textarea" :rows="6" :disabled="data.bpEdit.bodyBinary"
          :placeholder="data.bpEdit.bodyBinary ? '二进制内容不支持编辑，放行后原样转发' : '留空表示不改动正文'" />
      </el-form-item>
    </el-form>
    <el-text size="small" type="info">
      正文留空表示不改动。改动正文后 Content-Length 会自动重算；响应正文改动会去掉 Content-Encoding。
    </el-text>
    <template #footer>
      <el-button @click="data.bpEdit.visible = false">取消</el-button>
      <el-button type="primary" @click="submitBreakpointEdit">放行</el-button>
    </template>
  </el-dialog>
</template>
<style scoped>
/* 整个界面撑满视口，页面本身不产生滚动条 */
.main-tabs {
  height: 100vh;
  display: flex;
  flex-direction: column;
}

.main-tabs :deep(.el-tabs__content) {
  flex: 1;
  min-height: 0;
  padding: 8px;
  overflow: hidden;
}

.main-tabs :deep(.el-tab-pane) {
  height: 100%;
}

.pane {
  display: flex;
  flex-direction: column;
  height: 100%;
}

/* 头部操作区固定不滚，内容再多也不会被滚出视野 */
.pane-header {
  flex: none;
}

/* 表格区吃掉剩余高度；min-height:0 是 flex 子项能被压缩的前提 */
.pane-body {
  flex: 1;
  min-height: 0;
  overflow: hidden;
}

.item {
  margin-right: 40px;
}

/* 流载荷可能很长，给个固定高度自己滚，避免把对话框顶出屏幕 */
.stream-payload {
  max-height: 380px;
  overflow: auto;
  margin: 4px 0 0;
  white-space: pre-wrap;
  word-break: break-all;
}
</style>