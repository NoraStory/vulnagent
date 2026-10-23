package main

// reconcileResult 复扫收敛结果
type reconcileResult struct {
	Verified int
	Closed   int
	Reopened int
	Kept     int
}

// reconcileFindingStates 复扫后收敛漏洞状态，实现见 application/scan。
func (a *App) reconcileFindingStates(assetID int64, actor string) (reconcileResult, error) {
	res, err := a.scanService(loadPolicy(a.db)).Reconcile(assetID, actor)
	return reconcileResult{
		Verified: res.Verified,
		Closed:   res.Closed,
		Reopened: res.Reopened,
		Kept:     res.Kept,
	}, err
}
