package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPostWebhookSignsPayload(t *testing.T) {
	var gotEvent, gotSig string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEvent = r.Header.Get("X-VulnAgent-Event")
		gotSig = r.Header.Get("X-VulnAgent-Signature")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	payload := []byte(`{"event":"finding.new","data":{"cveId":"CVE-2021-44228"}}`)
	if err := postWebhook(notifyConfig{URL: srv.URL, Secret: "s3cret"}, "finding.new", payload); err != nil {
		t.Fatalf("推送失败：%v", err)
	}
	if gotEvent != "finding.new" {
		t.Fatalf("事件头错误：%q", gotEvent)
	}
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write(gotBody)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig != want {
		t.Fatalf("签名不匹配：got %q want %q", gotSig, want)
	}
}

func TestPostWebhookNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if err := postWebhook(notifyConfig{URL: srv.URL}, "sync.failed", []byte("{}")); err == nil {
		t.Fatal("非 2xx 应视为失败")
	}
}

func TestValidEvents(t *testing.T) {
	if !validEvents([]string{"finding.new", "ticket.created"}) {
		t.Fatal("合法事件被拒绝")
	}
	if validEvents([]string{"unknown.event"}) {
		t.Fatal("未知事件应被拒绝")
	}
}
