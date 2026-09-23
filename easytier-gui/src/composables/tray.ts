export async function useTray(_init: boolean = false) {
  return {
    setTooltip: (_tip: string) => {},
    setTitle: (_title: string) => {},
    setIcon: (_icon: string) => {},
    setMenu: (_menu: any) => {},
    setMenuOnLeftClick: (_val: boolean) => {},
  }
}

export async function generateMenuItem() {
  return []
}

export async function MenuItemExit(text: string) {
  return { text, id: 'exit' }
}

export async function MenuItemShow(text: string) {
  return { text, id: 'show' }
}

export async function setTrayMenu(_items?: any) {}

export async function setTrayRunState(_isRunning: boolean = false) {}

export async function setTrayTooltip(_tooltip: string) {}
