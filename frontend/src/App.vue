<script setup>
import { EventsOn } from '../wailsjs/runtime/runtime'
import { ref, reactive, useTemplateRef, watch, onMounted, computed } from 'vue'
import { ElNotification } from 'element-plus'
import { GetConfig, SetConfig, GenerateCert, InstallCert, UninstallCert, StartProxy, StopProxy, Test, GetDevices, StartIPCapture, StopIPCapture, GetDataDir, CertStatus, Download, ExportHAR } from '../wailsjs/go/main/App'

const data = reactive({
  config: {
    HTTP: {},
    IP: {},
  },
  resultText: "",
  windowWidth: 1024,
  windowHeight: 768,
  headerheight: 185,
  ftooerheight: 100,
  rate: 0,
  devices: [],
  selectdevice: null,
  dataDir: "",
  cert: { Generated: false, TrustedScopes: [], CertPath: "", NotAfter: "" },
  downloads: {},
})

let mainheight = computed(() => data.windowHeight - data.headerheight)
let httpheight = computed(() => data.windowHeight - 185)

const getWindowInfo = () => {
  data.windowWidth = window.innerWidth
  data.windowHeight = window.innerHeight
};

const debounce = (fn, delay) => {
  let timer;
  return function () {
    if (timer) {
      clearTimeout(timer);
    }
    timer = setTimeout(() => {
      fn();
    }, delay);
  }
};

onMounted(() => {
  getWindowInfo();
  GetConfig().then(config => {
    data.config = config
  })
  refreshCertStatus()
  GetDataDir().then(dir => {
    data.dataDir = dir
  })
  window.addEventListener('resize', debounce(getWindowInfo, 200));// 监听窗口大小变化
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
  { value: 'Date', text: '日期', width: 160, fixed: true },
  { value: 'TypeText', text: '类型', width: 80, fixed: true },
  { value: 'Method', text: '方式', width: 90, fixed: true },
  { value: 'Host', text: '域名', width: 220 },
  { value: 'Path', text: '地址', width: 240 },
  { value: 'KindText', text: '资源', width: 80 },
  { value: 'Proto', text: '协议', width: 90 },
  { value: 'ContentType', text: '内容类型', width: 180 },
  { value: 'StatusCode', text: '状态', width: 90 },
  { value: 'Duration', text: '耗时(ms)', width: 100 }
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
  { value: 'Date', text: '日期', width: 160, fixed: true },
  { value: 'ApplicationLayer', text: '应用层', width: 100, fixed: true },
  { value: 'SrcMAC', text: 'SrcMAC', width: 100, },
  { value: 'DstMAC', text: 'DstMAC', width: 100 },
  { value: 'SrcIP', text: 'SrcIP', width: 100, },
  { value: 'DstIP', text: 'DstIP', width: 100 },
  { value: 'Protocol', text: '协议', width: 100 },
  { value: 'SrcPort', text: 'SrcPort', width: 100 },
  { value: 'DstPort', text: 'DstPort', width: 100 },
  { value: 'Length', text: '长度', width: 80 },
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
  <el-tabs type="border-card" v-model="activeName" height="100vh" @tab-change="handleTabChange">
    <el-tab-pane label="HTTP" name="HTTP">
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
      <EasyDataTable :headers="httpheaders" :items="httpTableData" :table-height="httpheight">
        <template #expand="item">
          <div style="padding: 15px">
            <el-space wrap style="margin-bottom: 8px">
              <el-button v-if="canDownload(item)" type="primary" size="small" @click="downloadResource(item)">
                下载（{{ formatSize(item.ContentLength) }}）
              </el-button>
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
    </el-tab-pane>
    <el-tab-pane label="IP" name="IP">
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
      <EasyDataTable :headers="tcpheaders" :items="tcpTableData" :table-height="httpheight">
        <template #expand="item">
          <div style="padding: 15px">
            <p>ApplicationLayer: {{ item.ApplicationLayer || '-' }}</p>
            <pre>{{ formatPayload(item.ApplicationPayload) }}</pre>
          </div>
        </template>
      </EasyDataTable>
    </el-tab-pane>
  </el-tabs>
</template>
<style scoped>
.el-main {
  padding: 0 !important;
}

.el-footer {
  padding-top: 5px;
}

.affix-container {
  text-align: center;
  border-radius: 4px;
  background: var(--el-color-primary-light-9);
}

.item {
  margin-right: 40px;
}
</style>