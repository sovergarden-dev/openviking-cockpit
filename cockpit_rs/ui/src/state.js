export const MAX_WATCHES = 4;

export const state = {
  confSha: "",
  reservesSha: "",
  config: null,
  slots: [],
  liveVlm: null,
  lastMonitorSummary: null,
  watchCount: 0,
  slotProbes: new Map(),
  reserveFilter: {
    query: "",
    endpoint: "",
    status: "",
    sortBy: "index",
    sortDir: "asc",
  },
  selectedReserveIndices: new Set(),
  reserveBatchBusy: false,
  benchmarkBusy: false,
  activeAuditTarget: null,
  lastAuditJson: "",
  activeTab: "overview",
  restartConfirmPending: false,
  restartConfirmTimer: null,
  serviceBusy: false,
  memoryOverviewSeq: 0,
  searchRequestSeq: 0,
  previewRequestSeq: 0,
  onRefreshRequested: null,
  onRenderSlots: null,
  onOpenAudit: null,
  onOpenProviderTester: null,
  onOpenSettingsPopover: null,
};

let monitorMutationChain = Promise.resolve();

export function enqueueMonitorMutation(btn, taskFn) {
  if (btn) btn.disabled = true;
  const run = monitorMutationChain.then(taskFn, taskFn);
  monitorMutationChain = run.catch(() => {});
  return run.finally(() => {
    if (btn && btn.isConnected) btn.disabled = false;
  });
}
