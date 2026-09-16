const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('netops', {
  runDiscovery: (opts) => ipcRenderer.invoke('run-discovery', opts),
  openExternal: (url) => ipcRenderer.invoke('open-external', url),
  showOpenDialog: () => ipcRenderer.invoke('show-open-dialog'),
  platform: process.platform,
  version: '6.0.0'
});
