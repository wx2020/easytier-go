/**
 * Wails Bridge: Pure Go desktop bridge replacing @tauri-apps/*
 */

declare global {
  interface Window {
    go?: {
      main?: {
        App?: Record<string, (...args: any[]) => Promise<any>>
      }
    }
    runtime?: {
      EventsOn: (eventName: string, callback: (...args: any[]) => void) => () => void
      EventsEmit: (eventName: string, ...args: any[]) => void
      WindowSetTitle: (title: string) => Promise<void>
      ClipboardSetText: (text: string) => Promise<void>
      BrowserOpenURL: (url: string) => void
      Quit: () => void
    }
  }
}

// Fallback mock responses when running in pure Vite dev mode
function mockResponse(cmd: string, args: Record<string, any>): any {
  switch (cmd) {
    case 'easytier_version':
      return '2.6.4'
    case 'get_service_status':
      return 'NotInstalled'
    case 'is_client_running':
      return false
    case 'is_web_client_connected':
      return false
    case 'list_network_instance_ids':
      return { running: [], all: [] }
    case 'get_network_metas':
      return {}
    case 'get_default_dirs':
      return { config_dir: '/etc/easytier/config.d', log_dir: '/var/log/easytier' }
    case 'get_log_dir_path':
      return '/var/log/easytier'
    case 'generate_network_config':
      return { instance_id: 'inst_1', raw_toml: args.tomlConfig || '' }
    case 'parse_network_config':
      return args.cfg?.raw_toml || ''
    default:
      return null
  }
}

/**
 * Universal invoke dispatcher to Go App methods
 */
export async function invoke<T = any>(cmd: string, args: Record<string, any> = {}): Promise<T> {
  const app = window.go?.main?.App
  if (!app) {
    return mockResponse(cmd, args)
  }

  switch (cmd) {
    case 'parse_network_config':
      return (await app.ParseNetworkConfig(args.cfg)) as T
    case 'generate_network_config':
      return (await app.GenerateNetworkConfig(args.tomlConfig)) as T
    case 'run_network_instance':
      return (await app.RunNetworkInstance(args.cfg, args.save ?? false)) as T
    case 'collect_network_info':
      return (await app.CollectNetworkInfo(args.instanceId)) as T
    case 'set_logging_level':
      return (await app.SetLoggingLevel(args.level)) as T
    case 'set_tun_fd':
      return (await app.SetTunFd(args.fd)) as T
    case 'easytier_version':
      return (await app.EasytierVersion()) as T
    case 'list_network_instance_ids':
      return (await app.ListNetworkInstanceIds()) as T
    case 'remove_network_instance':
      return (await app.RemoveNetworkInstance(args.instanceId)) as T
    case 'update_network_config_state':
      return (await app.UpdateNetworkConfigState(args.instanceId, args.disabled)) as T
    case 'save_network_config':
      return (await app.SaveNetworkConfig(args.cfg)) as T
    case 'validate_config':
      return (await app.ValidateConfig(args.cfg)) as T
    case 'get_config':
      return (await app.GetConfig(args.instanceId)) as T
    case 'load_configs':
      return (await app.LoadConfigs(args.configs, args.enabledNetworks)) as T
    case 'get_network_metas':
      return (await app.GetNetworkMetas(args.instanceIds)) as T
    case 'init_service':
      return (await app.InitService(args.opts)) as T
    case 'set_service_status':
      return (await app.SetServiceStatus(args.enable)) as T
    case 'get_service_status':
      return (await app.GetServiceStatus()) as T
    case 'init_rpc_connection':
      return (await app.InitRpcConnection(args.isNormalMode, args.url)) as T
    case 'is_client_running':
      return (await app.IsClientRunning()) as T
    case 'init_web_client':
      return (await app.InitWebClient(args.url)) as T
    case 'is_web_client_connected':
      return (await app.IsWebClientConnected()) as T
    case 'get_log_dir_path':
      return (await app.GetLogDirPath()) as T
    case 'get_default_dirs':
      return (await app.GetDefaultDirs()) as T
    default:
      console.warn(`[WailsBridge] Unknown command: ${cmd}`)
      return null as T
  }
}

// OS Type Helper
export function type(): string {
  const ua = navigator.userAgent.toLowerCase()
  if (ua.includes('win')) return 'windows'
  if (ua.includes('mac')) return 'macos'
  if (ua.includes('linux')) return 'linux'
  if (ua.includes('android')) return 'android'
  return 'windows'
}

// Event Listeners Helper
export interface Event<T = any> {
  event: string
  payload: T
}

export async function listen<T = any>(
  eventName: string,
  handler: (event: Event<T>) => void,
): Promise<() => void> {
  if (window.runtime?.EventsOn) {
    return window.runtime.EventsOn(eventName, (payload: T) => {
      handler({ event: eventName, payload })
    })
  }
  return () => {}
}

// Clipboard Helper
export async function writeText(text: string): Promise<void> {
  if (window.runtime?.ClipboardSetText) {
    await window.runtime.ClipboardSetText(text)
    return
  }
  if (navigator?.clipboard?.writeText) {
    await navigator.clipboard.writeText(text)
  }
}

// Browser/Shell Open Helper
export async function open(url: string): Promise<void> {
  if (window.runtime?.BrowserOpenURL) {
    window.runtime.BrowserOpenURL(url)
    return
  }
  window.open(url, '_blank')
}

// Process Exit Helper
export async function exit(_code: number = 0): Promise<void> {
  if (window.runtime?.Quit) {
    window.runtime.Quit()
  }
}

// Path Helpers
export async function appConfigDir(): Promise<string> {
  const dirs = await invoke<{ config_dir: string }>('get_default_dirs')
  return dirs?.config_dir || ''
}

export async function appLogDir(): Promise<string> {
  const dirs = await invoke<{ log_dir: string }>('get_default_dirs')
  return dirs?.log_dir || ''
}

export async function join(...parts: string[]): Promise<string> {
  return parts.filter(Boolean).join('/').replace(/\/+/g, '/')
}

// Window Management Helper
export function getCurrentWindow() {
  return {
    setTitle: async (title: string) => {
      if (window.runtime?.WindowSetTitle) {
        await window.runtime.WindowSetTitle(title)
      } else {
        document.title = title
      }
    },
    show: async () => {},
    hide: async () => {},
    isVisible: async () => true,
    setFocus: async () => {},
  }
}

