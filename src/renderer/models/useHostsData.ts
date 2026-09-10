/**
 * @author: oldj
 * @homepage: https://oldj.net
 */

import version from '@/version.json'
import { IHostsBasicData, IHostsListObject } from '@common/data'
import { actions } from '@renderer/core/agent'
import { isSpiderManaged } from '@common/spider'
import { currentHostsAtom, hostsDataAtom } from '@renderer/stores/hosts_data'
import { useAtom } from 'jotai'

// Shared by every hook instance in this window, including reload event listeners.
let loadGeneration = 0

export default function useHostsData() {
  const [hostsData, setHostsData] = useAtom(hostsDataAtom)
  const [currentHosts, setCurrentHosts] = useAtom(currentHostsAtom)

  const loadHostsData = async () => {
    const generation = ++loadGeneration
    const data = await actions.getBasicData()
    if (generation === loadGeneration) setHostsData(data)
  }

  const setList = async (list: IHostsListObject[]) => {
    list = list.filter((i) => !i.is_sys)

    const data: IHostsBasicData = {
      list,
      trashcan: hostsData.trashcan,
      version,
    }

    setHostsData(data)
    await actions.setList(list)
    await loadHostsData()
    await actions.updateTrayTitle()
  }

  const isHostsInTrashcan = (id: string): boolean => {
    return hostsData.trashcan.findIndex((i) => i.data.id === id) > -1
  }

  const isReadOnly = (hosts?: IHostsListObject | null): boolean => {
    hosts = hosts || currentHosts

    if (!hosts) {
      return true
    }

    if (hosts.id === '0' || isSpiderManaged(hosts.id)) {
      return true // system hosts
    }

    if (hosts.type && ['group', 'remote', 'folder', 'trashcan'].includes(hosts.type)) {
      return true
    }

    if (isHostsInTrashcan(hosts.id)) {
      return true
    }

    // ..
    return false
  }

  return {
    hostsData,
    setHostsData,
    loadHostsData,

    setList,

    currentHosts,
    setCurrentHosts,

    isHostsInTrashcan,
    isReadOnly,
  }
}
