package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"vulnagent/server/internal/collect"
)

// computeSelfSBOMDigest 对 Agent 自身依赖 SBOM 取摘要，避免展示占位值。
// 同一构建产物的依赖集合稳定，因此摘要可用于核对版本一致性。
func computeSelfSBOMDigest() string {
	deps := collect.SelfSBOM()
	if len(deps) == 0 {
		return "sha256:none"
	}
	raw, err := json.Marshal(deps)
	if err != nil {
		return "sha256:none"
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])[:16]
}
