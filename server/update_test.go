package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestManifestSignAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥失败：%v", err)
	}
	sum := sha256.Sum256([]byte("demo-binary"))
	m := updateManifest{
		Version: "0.2.0",
		OS:      "plan9",
		Arch:    "amd64",
		SHA256:  hex.EncodeToString(sum[:]),
		URL:     "https://example.com/vulnagent.exe",
	}
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonicalPayload(m)))

	if err := verifyManifest(pub, m); err == nil {
		t.Fatal("目标系统与当前不一致时应失败")
	}

	m.OS = ""
	m.Arch = ""
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonicalPayload(m)))
	if err := verifyManifest(pub, m); err != nil {
		t.Fatalf("合法清单应通过：%v", err)
	}

	m.URL = "https://evil.example.com/vulnagent.exe"
	if err := verifyManifest(pub, m); err == nil {
		t.Fatal("篡改 URL 后签名应失效")
	}
}

func TestParsePublicKeyFromFile(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥失败：%v", err)
	}
	path := filepath.Join(t.TempDir(), "update.pub")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
		t.Fatalf("写入公钥失败：%v", err)
	}
	parsed, err := parsePublicKey(path)
	if err != nil {
		t.Fatalf("读取公钥失败：%v", err)
	}
	if !parsed.Equal(pub) {
		t.Fatal("解析出的公钥不一致")
	}
}

func TestReadManifestFile(t *testing.T) {
	m := updateManifest{Version: "0.3.0", SHA256: "abc", URL: "https://example.com/a"}
	data, _ := json.Marshal(m)
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("写入清单失败：%v", err)
	}
	got, err := readManifest(path)
	if err != nil {
		t.Fatalf("读取清单失败：%v", err)
	}
	if got.Version != m.Version || got.URL != m.URL {
		t.Fatalf("清单内容不一致：%+v", got)
	}
}
