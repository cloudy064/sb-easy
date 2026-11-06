/// <reference types="vite/client" />

interface Window {
  chrome?: {
    webview?: {
      postMessage(message: unknown): void
      addEventListener(type: 'message', listener: (event: MessageEvent) => void): void
    }
  }
}
