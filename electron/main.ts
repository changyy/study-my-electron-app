import { app, BrowserWindow } from 'electron'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import mdns from 'multicast-dns'

const require = createRequire(import.meta.url)
const __dirname = path.dirname(fileURLToPath(import.meta.url))

// The built directory structure
//
// ├─┬─┬ dist
// │ │ └── index.html
// │ │
// │ ├─┬ dist-electron
// │ │ ├── main.js
// │ │ └── preload.mjs
// │
process.env.APP_ROOT = path.join(__dirname, '..')

// 🚧 Use ['ENV_NAME'] avoid vite:define plugin - Vite@2.x
export const VITE_DEV_SERVER_URL = process.env['VITE_DEV_SERVER_URL']
export const MAIN_DIST = path.join(process.env.APP_ROOT, 'dist-electron')
export const RENDERER_DIST = path.join(process.env.APP_ROOT, 'dist')

process.env.VITE_PUBLIC = VITE_DEV_SERVER_URL ? path.join(process.env.APP_ROOT, 'public') : RENDERER_DIST

let win: BrowserWindow | null

function createWindow() {
  win = new BrowserWindow({
    icon: path.join(process.env.VITE_PUBLIC, 'electron-vite.svg'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.mjs'),
    },
  })

  // Test active push message to Renderer-process.
  win.webContents.on('did-finish-load', () => {
    win?.webContents.send('main-process-message', (new Date).toLocaleString())
  })

  if (VITE_DEV_SERVER_URL) {
    win.loadURL(VITE_DEV_SERVER_URL)
  } else {
    // win.loadFile('dist/index.html')
    win.loadFile(path.join(RENDERER_DIST, 'index.html'))
  }
}

const mdnsDevices: { [key: string]: { name: string, type: string, firstSeen: number, lastSeen: number, data: any[], answers: any[] } } = {}

function startMdnsQuery() {
  const mdnsInstance = mdns()

  console.log('mDNS Query Start...')

  // 修改 name & type
  // dns-sd -B _services._dns-sd._udp local
  mdnsInstance.query({
    questions: [{
      name: '_http._tcp.local',
      //name: '_services._dns-sd._udp.local',
      type: 'PTR'
    }]
  })

  mdnsInstance.on('response', (response: { answers: string | any[] }) => {
    console.log('mDNS Response:', response)

    if (win && response.answers.length > 0) {
      for (const answer of response.answers) {
        try {
          // 建立一個 unique key 來代表一個裝置
          const key = `${answer.name}-${answer.type}`
          if (!mdnsDevices[key]) {
            mdnsDevices[key] = {
              name: answer.name,
              type: answer.type,
              data: [answer.data],
              firstSeen: Date.now(),
              lastSeen: Date.now(),
              answers: [answer]
            }
            console.log('ADD Device:')
            console.log(mdnsDevices[key])
          } else {
            mdnsDevices[key].lastSeen = Date.now()
            mdnsDevices[key].answers.push(answer)
            if (!mdnsDevices[key].data.includes(answer.data)) {
              mdnsDevices[key].data.push(answer.data)
            }
          }
          win.webContents.send('mdns-found', mdnsDevices)
        } catch (error) {
          console.error(error)
        }
      }
    }
  })
}

// Quit when all windows are closed, except on macOS. There, it's common
// for applications and their menu bar to stay active until the user quits
// explicitly with Cmd + Q.
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit()
    win = null
  }
})

app.on('activate', () => {
  // On OS X it's common to re-create a window in the app when the
  // dock icon is clicked and there are no other windows open.
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow()
  }
})

//app.whenReady().then(createWindow)
app.whenReady().then(() => {
  createWindow()
  startMdnsQuery()
})