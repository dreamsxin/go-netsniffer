<script setup>
import { EventsOn } from '../wailsjs/runtime/runtime'
import { ref, reactive, useTemplateRef, watch, onMounted } from 'vue'
import { ElNotification } from 'element-plus'
import { GetConfig, SetConfig, GenerateCert, InstallCert, UninstallCert, StartProxy, StopProxy, Test } from '../wailsjs/go/main/App'

const data = reactive({
  config: {},
  resultText: "",
})

onMounted(() => {
  GetConfig().then(config => {
    data.config = config
  })
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


function start() {
  StartProxy(data.port, data.autoProxy).then(result => {
    data.resultText = result
  })
}

function stop() {
  StopProxy().then(result => {
    data.resultText = result
  })
}

function test() {
  Test().then(result => {
    //data.resultText = result
    console.log(result)
  })
}

const tableData = reactive([
])


function handleChange() {

  SetConfig(data.config).then(result => {
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

</script>

<template>
  <el-container>
    <el-header>
      <el-space>  
      <el-button type="primary" round @click="installCert">安装证书</el-button>
      <el-button type="success" round @click="generateCert">生成证书</el-button>
      <el-button type="warning" round @click="uninstallCert">卸载证书</el-button>
      <el-input-number v-model="data.config.Port" @change="handleChange" />
      <el-switch v-model="data.config.AutoProxy" inline-prompt active-text="自动代理" inactive-text="自动代理"  @change="handleChange" />
      <el-button-group>
        <el-button type="primary" @click="start">Start Proxy</el-button>
        <el-button type="warning" @click="stop">Stop Proxy</el-button>
      </el-button-group>
    </el-space>
    </el-header>
    <el-main>
      <div>{{ data.resultText }}</div>
      <el-table :data="tableData" style="width: 100%">
        <el-table-column type="expand">
          <template #default="props">
            <div m="4">{{ props.row.Body }}
            </div>
          </template>
        </el-table-column>
        <el-table-column label="Date" prop="Date" sortable />
        <el-table-column label="PacketType" prop="PacketType" />
        <el-table-column label="Method" prop="Method" />
        <el-table-column label="Url" prop="URL" />
      </el-table>
    </el-main>
  </el-container>
  <el-footer>
    <el-tabs v-model="activeName" type="border-card" class="demo-tabs" @tab-click="handleClick">
      <el-tab-pane label="User" name="first">User</el-tab-pane>
      <el-tab-pane label="Config" name="second">Config</el-tab-pane>
      <el-tab-pane label="Role" name="third">Role</el-tab-pane>
      <el-tab-pane label="Task" name="fourth">Task</el-tab-pane>
    </el-tabs>
  </el-footer>
</template>
