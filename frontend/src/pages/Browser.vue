<script setup>
import { reactive, onMounted } from 'vue'
import { EventsOn } from '../../wailsjs/runtime/runtime';
import { StartProxy, Test } from '../../wailsjs/go/main/App'

onMounted(() => {
})

const data = reactive({
  port: 9000,
  autoProxy: true,
  resultText: "",
})

EventsOn("StartProxy", function (v) {
  data.resultText = v
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

function test() {
  Test().then(result => {
    //data.resultText = result
    console.log(result)
  })
}
const tableData = reactive([
])
</script>

<template>
  <main>
    <button class="btn" @click="start">Start Proxy</button>
    <button class="btn" @click="test">Test</button>
    <div>{{ data.resultText }}</div>
    <el-table :data="tableData" style="width: 100%">
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
  </main>
</template>
