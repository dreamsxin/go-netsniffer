<script setup>
import { EventsOn } from '../wailsjs/runtime/runtime'
import { ref, reactive, useTemplateRef, watch, onMounted, computed } from 'vue'
import { ElNotification } from 'element-plus'
import { GetConfig, SetConfig, GenerateCert, InstallCert, UninstallCert, StartProxy, StopProxy, Test, GetDevices, StartTCPCapture, StopTCPCapture } from '../wailsjs/go/main/App'

const data = reactive({
  config: {
    HTTP: {},
    TCP: {},
  },
  resultText: "",
  windowWidth: 1024,
  windowHeight: 768,
  headerheight: 185,
  ftooerheight: 100,
  rate: 0,
  devices: [],
  selectdevice: null,
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
  window.addEventListener('resize', debounce(getWindowInfo, 200));// 监听窗口大小变化
})

const activeName = ref('http')

const handleTabChange = (tab, event) => {
  console.log(activeName.value, tab, event)
  if (activeName.value == "tcp") {
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


EventsOn("Packet", function (v) {
  console.log("Packet", v)
});



const httpheaders = [
  { value: 'Date', text: '日期', width: 160, fixed: true },
  { value: 'HTTPPacketType', text: '类型', width: 80, fixed: true },
  { value: 'Method', text: '方式', width: 100, fixed: true },
  { value: 'Host', text: '域名', width: 250 },
  { value: 'Path', text: '地址', width: 250 },
  { value: 'ContentType', text: '内容类型', width: 200 },
  { value: 'StatusCode', text: '状态', width: 200 }
];
const httpTableData = reactive([
])
EventsOn("HTTPPacket", function (v) {
  console.log("HTTPPacket", v)
  httpTableData.push(v)
});

const tcpheaders = [
  { value: 'Date', text: '日期', width: 160, fixed: true },
  { value: 'LayerType', text: '网络层', width: 80, fixed: true },
  { value: 'SrcMAC', text: 'SrcMAC', width: 100, },
  { value: 'DstMAC', text: 'DstMAC', width: 100 },
  { value: 'SrcIP', text: 'SrcIP', width: 100, },
  { value: 'DstIP', text: 'DstIP', width: 100 },
  { value: 'Protocol', text: '协议', width: 100 },
  { value: 'SrcPort', text: 'SrcPort', width: 100 },
  { value: 'DstPort', text: 'DstPort', width: 100 },
];
const tcpTableData = reactive([
])
EventsOn("IPPacket", function (v) {
  console.log("IPPacket", v)
  tcpTableData.push(v)
});


function generateCert() {
  GenerateCert().then(err => {
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


function installCert() {
  InstallCert().then(err => {
    if (err == null) {
      ElNotification({
        title: 'Success',
        message: "安装证书成功",
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


function uninstallCert() {
  UninstallCert().then(err => {
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
  StartProxy(data.port, data.autoProxy).then(err => {
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

function clear() {
  httpTableData.length = 0;
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

function startTCPCapture() {
  StartTCPCapture(data.selectdevice).then(err => {
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

function stopTCPCapture() {
  StopTCPCapture().then(err => {
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
    <el-tab-pane label="HTTP" name="http">
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
            <el-input v-model="data.config.HTTP.FilterHost" style="max-width: 200px" placeholder="Please input"
              @change="handleChange('HTTP.FilterHost')" class="item">
              <template #prepend>Host</template>
            </el-input>
          </el-space>
        </el-col>
      </el-row>
      <EasyDataTable :headers="httpheaders" :items="httpTableData" :table-height="httpheight">
        <template #expand="item">
          <div style="padding: 15px">
            <span v-for="(item, index) in item.Header" v-bind:key="index">
              <p>{{ index }}: {{ item.join(",") }}</p>
            </span>
            <pre>{{ item.Body }}</pre>
          </div>
        </template>
      </EasyDataTable>
    </el-tab-pane>
    <el-tab-pane label="TCP" name="tcp">
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
              <el-button type="primary" @click="startTCPCapture">启动服务</el-button>
              <el-button type="warning" @click="stopTCPCapture">停止服务</el-button>
            </el-button-group>
          </el-space>
        </el-col>
      </el-row>
      <el-row style="margin-bottom:5px">
        <el-col>
          <el-space wrap>
            <el-input-number v-model="data.config.TCP.Snaplen" @change="handleChange('TCP.Snaplen')" :controls="false"
              aria-label="数据包长度">
              <template #prefix>
                <span>数据包长度</span>
              </template>
            </el-input-number>
            <el-text>超时时间</el-text><el-input-number v-model="data.config.TCP.Timeout"
              @change="handleChange('TCP.Timeout')" :controls="false" aria-label="超时时间">
              <template #suffix>
                <span>毫秒</span>
              </template>
            </el-input-number>
            <el-switch v-model="data.config.TCP.Promisc" inline-prompt active-text="混杂模式" inactive-text="混杂模式"
              @change="handleChange('TCP.Promisc')" />
          </el-space>
        </el-col>
      </el-row>
      <EasyDataTable :headers="tcpheaders" :items="tcpTableData" :table-height="httpheight">
        <template #expand="item">
          <div style="padding: 15px">
            <span v-for="(item, index) in item.Header" v-bind:key="index">
              <p>{{ index }}: {{ item.join(",") }}</p>
            </span>
            <pre>{{ item.Body }}</pre>
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