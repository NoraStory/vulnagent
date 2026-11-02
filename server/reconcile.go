package main

// reconcileResult 复扫收敛结果
type reconcileResult struct {
	Verified int
	Closed   int
	Reopened int
	Kept     int
}

// reconcileFindingStates 复扫后收敛漏洞状态，实现见 application/scan。
// 直接读库而不是走情报快照：OSV 命中后会紧接一次复扫，
// 刚写入的受影响区间必须对本次判定可见。
func (a *App) reconcileFindingStates(assetID int64, actor string) (reconcileResult, error) {
	svc := a.scanService(loadPolicy(a.db))
	svc.Intel = a.intelRepo()
	res, err := svc.Reconcile(assetID, actor)
	return reconcileResult{
		Verified: res.Verified,
		Closed:   res.Closed,
		Reopened: res.Reopened,
		Kept:     res.Kept,
	}, err
}
