/** Stable native-owned IDs; selection is committed by the Spider transaction. */
export const SPIDER_GROUP_ID = 'spider-managed-environment'
export const isSpiderManaged = (id: string) =>
  id === SPIDER_GROUP_ID ||
  ['daily', 'staging', 'prod'].some((mode) => id === `${SPIDER_GROUP_ID}-${mode}`)
