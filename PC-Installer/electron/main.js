const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const http = require('http');

let backendProcess = null;
let mainWindow = null;
const BACKEND_PORT = 8000;
const FRONTEND_PORT = 5173;

function getBackendPath() {
  // في التطوير: src/backend — في الإنتاج: resources
  const dev = path.join(__dirname, '../src/backend');
  if (fs.existsSync(dev)) return dev;
  return path.join(process.resourcesPath, 'src/backend');
}

function startBackend() {
  const backendDir = getBackendPath();
  const isWin = process.platform === 'win32';
  const python = isWin ? 'python' : 'python3';
  
  console.log('[NetOps] Starting backend from', backendDir);
  backendProcess = spawn(python, ['-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', String(BACKEND_PORT)], {
    cwd: backendDir,
    env: { ...process.env, PYTHONIOENCODING: 'utf-8' },
    shell: false
  });

  backendProcess.stdout.on('data', (d) => console.log('[backend]', d.toString()));
  backendProcess.stderr.on('data', (d) => console.error('[backend]', d.toString()));
  backendProcess.on('close', (code) => console.log('[backend] exited', code));
}

function waitForBackend(retries = 30) {
  return new Promise((resolve, reject) => {
    let tries = 0;
    const check = () => {
      http.get(`http://127.0.0.1:${BACKEND_PORT}/api`, (res) => {
        if (res.statusCode === 200) return resolve(true);
        if (++tries >= retries) return reject(new Error('Backend timeout'));
        setTimeout(check, 500);
      }).on('error', () => {
        if (++tries >= retries) return reject(new Error('Backend timeout'));
        setTimeout(check, 500);
      });
    };
    check();
  });
}

async function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1100,
    minHeight: 700,
    icon: path.join(__dirname, 'icon.png'),
    title: 'NetOps Autopilot V6 — مهندس شبكات آلي حقيقي',
    backgroundColor: '#f8fafc',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true
    }
  });

  // تحقق هل frontend مبني (dist) أم نستخدم vite dev أم static-demo
  const staticDemo = path.join(__dirname, '../src/frontend/static-demo.html');
  const distIndex = path.join(__dirname, '../src/frontend/dist/index.html');
  
  // انتظر Backend ثم افتح الواجهة
  try {
    await waitForBackend();
    console.log('[NetOps] Backend ready');
  } catch (e) {
    console.warn('[NetOps] Backend not ready, opening anyway', e.message);
  }

  // افتح static-demo إذا موجود (يعمل بدون build)
  const demoPath = fs.existsSync(path.join(__dirname, '../static-demo.html')) 
    ? path.join(__dirname, '../static-demo.html') 
    : staticDemo;

  if (fs.existsSync(distIndex)) {
    mainWindow.loadFile(distIndex);
  } else if (fs.existsSync(demoPath)) {
    // شغل خادم بسيط للـ static-demo
    mainWindow.loadFile(demoPath);
  } else {
    mainWindow.loadURL(`http://127.0.0.1:${BACKEND_PORT}/`);
  }

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });
}

app.whenReady().then(async () => {
  startBackend();
  await createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  if (backendProcess) {
    try { backendProcess.kill(); } catch {}
  }
});

// IPC — للواجهة لتستدعي Agent
ipcMain.handle('run-discovery', async (event, { seedIp, seedId, username, password, intent }) => {
  return new Promise((resolve, reject) => {
    const agentPath = path.join(getBackendPath(), '../agent/netops_agent.py');
    const args = ['--seed-ip', seedIp, '--seed-id', seedId, '--username', username, '--password', password, '--intent', intent, '--dry-run'];
    const p = spawn('python', [agentPath, ...args], { cwd: path.dirname(agentPath) });
    let out = '', err = '';
    p.stdout.on('data', d => out += d.toString());
    p.stderr.on('data', d => err += d.toString());
    p.on('close', code => resolve({ code, out, err }));
  });
});

ipcMain.handle('open-external', async (event, url) => {
  shell.openExternal(url);
});

ipcMain.handle('show-open-dialog', async () => {
  const r = await dialog.showOpenDialog(mainWindow, { properties: ['openFile'] });
  return r;
});
