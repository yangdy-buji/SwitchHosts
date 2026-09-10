// @vitest-environment jsdom
import { act, renderHook } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  actions: { getBasicData: vi.fn(), setList: vi.fn(), updateTrayTitle: vi.fn() },
  setData: vi.fn(),
}))
vi.mock('@renderer/core/agent', () => ({ actions: mocks.actions }))
vi.mock('@renderer/stores/hosts_data', () => ({
  hostsDataAtom: 'data',
  currentHostsAtom: 'current',
}))
vi.mock('jotai', () => ({
  useAtom: (atom: string) =>
    atom === 'data' ? [{ list: [], trashcan: [] }, mocks.setData] : [null, vi.fn()],
}))
import useHostsData from './useHostsData'

beforeEach(() => {
  vi.clearAllMocks()
})
it('does not let an earlier reload overwrite a newer native environment across hook instances', async () => {
  let resolveOld!: (data: unknown) => void
  mocks.actions.getBasicData
    .mockReturnValueOnce(
      new Promise((resolve) => {
        resolveOld = resolve
      }),
    )
    .mockResolvedValueOnce({ list: [{ id: 'prod', on: true }], trashcan: [] })
  const first = renderHook(useHostsData)
  const second = renderHook(useHostsData)
  let pending!: Promise<void>
  act(() => {
    pending = first.result.current.loadHostsData()
  })
  await act(async () => {
    await second.result.current.loadHostsData()
  })
  await act(async () => {
    resolveOld({ list: [{ id: 'daily', on: true }], trashcan: [] })
    await pending
  })
  expect(mocks.setData).toHaveBeenCalledTimes(1)
  expect(mocks.setData).toHaveBeenLastCalledWith({ list: [{ id: 'prod', on: true }], trashcan: [] })
})
it('managed profile editor is read only', () => {
  const { result } = renderHook(useHostsData)
  expect(result.current.isReadOnly({ id: 'spider-managed-environment-prod', type: 'local' })).toBe(
    true,
  )
})
