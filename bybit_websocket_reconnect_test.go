package bybit_connector

import (
	"context"
	"testing"
	"time"
)

// A dial that cannot succeed, and cannot touch the network doing so: gorilla
// rejects the scheme before opening a socket, so these stay hermetic.
const unreachableWS = "ws://invalid-scheme-for-test.invalid:0/"

func newTestSocket(url string) *WebSocket {
	ws := &WebSocket{url: url, onMessage: func(string) error { return nil }}
	ws.ctx, ws.cancel = context.WithCancel(context.Background())
	return ws
}

// The crash this file exists for. Connect signals a dial failure by returning
// the RECEIVER while leaving conn nil, so a caller that reads "non-nil means
// connected" starts a reader against a nil socket — a panic in a goroutine,
// which kills the process rather than the connection.
func TestConnectReportsDialFailureThroughIsConnectedNotItsReturn(t *testing.T) {
	ws := newTestSocket(unreachableWS)

	got := ws.Connect()

	if got == nil {
		t.Fatal("Connect returned nil on dial failure; callers hold the receiver and must keep being able to use it")
	}
	if ws.isConnected {
		t.Error("isConnected is true after a failed dial — this is the flag callers gate the reader on")
	}
	if ws.conn != nil {
		t.Error("conn is non-nil after a failed dial")
	}
}

// redial is what the monitor drives. On failure it must leave the socket in the
// same shape a never-connected one has, so the next tick retries cleanly instead
// of a reader being started against a half-open connection.
func TestRedialFailureLeavesNoUsableSocket(t *testing.T) {
	ws := newTestSocket(unreachableWS)

	if ws.redial() {
		t.Fatal("redial reported success against an unreachable url")
	}
	if ws.isConnected {
		t.Error("isConnected is true after a failed redial")
	}
	if ws.conn != nil {
		t.Error("conn is non-nil after a failed redial")
	}
}

// Defense in depth for the same panic: even reached with no socket, the reader
// must return rather than dereference it.
func TestHandleIncomingMessagesWithoutAConnectionDoesNotPanic(t *testing.T) {
	ws := newTestSocket(unreachableWS)
	ws.isConnected = true // as the buggy monitor used to leave it

	done := make(chan struct{})
	go func() {
		defer close(done)
		ws.handleIncomingMessages()
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleIncomingMessages blocked with no connection; it must return")
	}

	if ws.isConnected {
		t.Error("reader returned without clearing isConnected, so the monitor will never redial")
	}
}

// Disconnect is exactly what a caller runs after Connect failed to dial, which
// is the state where conn is nil.
func TestDisconnectWithoutAConnectionDoesNotPanic(t *testing.T) {
	ws := newTestSocket(unreachableWS)
	ws.Connect() // fails; leaves conn nil

	if err := ws.Disconnect(); err != nil {
		t.Fatalf("Disconnect on a never-connected socket returned %v, want nil", err)
	}
}

// The monitor must come out of a failed reconnect with the socket in a retryable
// state and must stop when its context is cancelled.
//
// Note this does NOT reproduce the production panic on its own: with the reader
// guarded, the old monitor's mistake (treating Connect's non-nil return as
// success, setting isConnected and starting a reader) now ends in the reader
// bailing out instead of dereferencing nil. The panic is regression-locked by
// TestHandleIncomingMessagesWithoutAConnectionDoesNotPanic — remove the guard in
// handleIncomingMessages and that test SIGSEGVs. What this covers is the state
// the monitor leaves behind, and that a failed reconnect does not wedge it.
func TestMonitorConnectionSurvivesAFailedReconnect(t *testing.T) {
	ws := newTestSocket(unreachableWS)
	ws.isConnected = false

	done := make(chan struct{})
	go func() {
		defer close(done)
		ws.monitorConnection()
	}()

	// One tick is 5s; cancel just after it so the failed redial has run.
	time.Sleep(6 * time.Second)
	ws.cancel()

	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("monitorConnection did not stop after its context was cancelled")
	}

	if ws.isConnected {
		t.Error("monitor left isConnected true after a failed reconnect — the bug that started a reader on a nil conn")
	}
	if ws.conn != nil {
		t.Error("monitor left a non-nil conn after a failed reconnect")
	}
}
