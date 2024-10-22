<script setup>
import { EventsOn } from '../wailsjs/runtime/runtime'
import { ref, reactive, useTemplateRef, watch, onMounted, computed } from 'vue'
import { ElNotification } from 'element-plus'
import { GetConfig, SetConfig, GenerateCert, InstallCert, UninstallCert, StartProxy, StopProxy, Test, GetDevices } from '../wailsjs/go/main/App'

const data = reactive({
  config: {},
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

const activeName = ref('first')

const handleClick = (tab, event) => {
  console.log(tab, event)
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

const tableData = reactive([
])

EventsOn("Packet", function (v) {
  console.log("Packet", v)
  tableData.push(v)
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

function start() {
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

function stop() {
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
  tableData.length = 0;
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

function showDetail(row, column, event) {
  console.log(row, column, event)
}

const headers = [
  { value: 'Date', text: '日期', width: 160, fixed: true },
  { value: 'PacketType', text: '类型', width: 80, fixed: true },
  { value: 'Method', text: '方式', width: 100, fixed: true },
  { value: 'Host', text: '域名', width: 250 },
  { value: 'Path', text: '地址', width: 250 },
  { value: 'ContentType', text: '内容类型', width: 200 },
  { value: 'StatusCode', text: '状态', width: 200 }
];
</script>

<template>
  <el-tabs type="border-card" height="100vh">
    <el-tab-pane label="HTTP">
      <el-row style="margin-bottom:5px">
        <el-col>
          <el-space wrap>
            <el-button type="primary" round @click="installCert">安装证书</el-button>
            <el-button type="success" round @click="generateCert">生成证书</el-button>
            <el-button type="warning" round @click="uninstallCert">卸载证书</el-button>
            <el-button-group>
              <el-button type="primary" @click="start">启动服务</el-button>
              <el-button type="warning" @click="stop">停止服务</el-button>
              <el-button type="danger" @click="clear">清除数据</el-button>
            </el-button-group>
          </el-space>
        </el-col>
      </el-row>
      <el-row style="margin-bottom:5px">
        <el-col>
          <el-space wrap>
            <el-input-number v-model="data.config.Port" @change="handleChange('Port')" :controls="false" label="端口号" />
            <el-switch v-model="data.config.AutoProxy" inline-prompt active-text="自动代理" inactive-text="自动代理"
              @change="handleChange('AutoProxy')" />
            <el-switch v-model="data.config.SaveLogFile" inline-prompt active-text="保存到文件" inactive-text="保存到文件"
              @change="handleChange('SaveLogFile')" class="item" />
            <el-input v-model="data.config.FilterHost" style="max-width: 200px" placeholder="Please input"
              @change="handleChange('FilterHost')" class="item">
              <template #prepend>Host</template>
            </el-input>
          </el-space>
        </el-col>
      </el-row>
      <EasyDataTable :headers="headers" :items="tableData" :table-height="httpheight">
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
    <el-tab-pane label="TCP">
      <el-row style="margin-bottom:5px" gutter="10">
        <el-col :span="6">
          <el-select v-model="data.selectdevice" placeholder="选择设备" clearable>
            <el-option v-for="item in data.devices" :key="item.Name" :label="item.Description" :value="item.Name" />
          </el-select>
        </el-col>
        <el-col :span="6">
          <el-button type="primary" round @click="getDevices">获取</el-button>
        </el-col>
      </el-row>
      <el-row style="margin-bottom:5px">
        <el-col>
          <el-space wrap>
          </el-space>
        </el-col>
      </el-row>
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