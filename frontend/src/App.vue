<script setup>
import { EventsOn } from '../wailsjs/runtime/runtime'
import { ref, reactive, useTemplateRef, watch, onMounted } from 'vue'
import { ElNotification } from 'element-plus'
import { GetConfig, SetConfig, StartProxy, StopProxy, Test } from '../wailsjs/go/main/App'

const data = reactive({
  config: {},
  resultText: "",
})

onMounted(() => {
  GetConfig().then(config => {
    data.config = config
  })
})

EventsOn("StartProxy", function (v) {
  data.resultText = v
  ElNotification({
    title: 'Success',
    message: '代理启动成功',
    type: 'success',
  })
});

EventsOn("Test", function (v) {
  data.resultText = v
});

EventsOn("Packet", function (v) {
  console.log("Packet", v)
  tableData.push(v)
});


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
      <el-input-number v-model="data.config.Port" @change="handleChange" />
      <el-switch v-model="data.config.AutoProxy" active-text="自动代理" inactive-text="自动代理"
        style="--el-switch-on-color: #13ce66; --el-switch-off-color: #ff4949" @change="handleChange" />
      <button class="btn" @click="start">Start Proxy</button>
      <button class="btn" @click="stop">Stop Proxy</button>
      <button class="btn" @click="test">Test</button>
    </el-header>
    <el-main>
      <div>{{ data.resultText }}</div>
      <el-table :data="tableData" style="width: 100%" max-height="250">
        <el-table-column type="expand">
          <template #default="props">
            <div m="4">{{ props.row.Body }}
            </div>
          </template>
        </el-table-column>
        <el-table-column label="Date" prop="Date" />
        <el-table-column label="PacketType" prop="PacketType" />
        <el-table-column label="Method" prop="Method" />
        <el-table-column label="Url" prop="URL" />
      </el-table>
    </el-main>
  </el-container>
  <el-footer></el-footer>
</template>
