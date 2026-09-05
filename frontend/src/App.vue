<script setup>
import { EventsOn } from '../wailsjs/runtime/runtime'
import { ref, reactive, onMounted, onBeforeUnmount, computed } from 'vue'
import { ElNotification } from 'element-plus'
import { GetConfig, SetConfig, GenerateCert, InstallCert, UninstallCert, StartProxy, StopProxy, Test, GetDevices, StartIPCapture, StopIPCapture, GetDataDir, CertStatus, Download, ExportHAR, Replay } from '../wailsjs/go/main/App'

const data = reactive({
  config: {
    HTTP: {},
    IP: {},
  },
  resultText: "",
  devices: [],
  selectdevice: null,
  dataDir: "",
  cert: { Generated: false, TrustedScopes: [], CertPath: "", NotAfter: "" },
  downloads: {},
  replay: {
    visible: false,
    method: "GET",
    url: "",
    headerText: "",
    body: "",
    truncated: false,
  },
})

// 表格高度实测得来，不再用"窗口高 - 魔数"估算：
// 头部行数会随折叠面板展开、文字换行而变化，估算必然对不上，
// 结果是整页出现滚动条、头部与分页器被滚出视野。
const httpBodyRef = ref(null)
const ipBodyRef = ref(null)
const httpBodyHeight = ref(400)
const ipBodyHeight = ref(400)

// 分页栏在表格滚动区之外，table-height 只管滚动区，
// 因此要给它留出高度，否则分页器会被容器裁掉
const FOOTER_RESERVE = 56
const MIN_TABLE_HEIGHT = 160

const httpTableHeight = computed(() =>
  Math.max(MIN_TABLE_HEIGHT, httpBodyHeight.value - FOOTER_RESERVE))
const ipTableHeight = computed(() =>
  Math.max(MIN_TABLE_HEIGHT, ipBodyHeight.value - FOOTER_RESERVE))

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
  GetDataDir().then(dir => {
    data.dataDir = dir
  })
  observeHeight(httpBodyRef, httpBodyHeight)
  observeHeight(ipBodyRef, ipBodyHeight)
})

onBeforeUnmount(() => {
  observers.forEach(ro => ro.disconnect())
  observers = []
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


function exportHar() {
  ExportHAR(httpTableData.slice()).then(result => {
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

function clear() {
  httpTableData.length = 0;
  tcpTableData.length = 0;
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
              <el-button type="primary" @click="startProxy">启动服务</el-button>
              <el-button type="warning" @click="stopProxy">停止服务</el-button>
              <el-button type="danger" @click="clear">清除数据</el-button>
            </el-button-group>
            <el-button type="info" round @click="exportHar">导出 HAR</el-button>
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
                placeholder="* 全部匹配；*.a.com 匹配域名及子域；!前缀 表示排除；# 为注释"
                @change="handleChange('HTTP.Rule')" />
              <el-text size="small" type="info">
                做了证书固定的客户端（微信、部分银行 App）必须用 ! 排除，否则它们会无法联网。规则修改后立即生效，无需重启服务。
              </el-text>
            </el-collapse-item>
          </el-collapse>
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
      <EasyDataTable :headers="httpheaders" :items="httpTableData" :table-height="httpTableHeight">
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
              <el-text v-if="item.BodyTruncated" size="small" type="warning">正文已截断</el-text>
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
              <el-button type="primary" @click="startIPCapture">启动服务</el-button>
              <el-button type="warning" @click="stopIPCapture">停止服务</el-button>
            </el-button-group>
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
  </el-tabs>

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
</style>