package bybit_connector

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

type MessageHandler func(message string) error

func (b *WebSocket) handleIncomingMessages() {
	// Snapshot the socket this reader owns. Reading b.conn every iteration races
	// a concurrent reconnect that is in the middle of replacing it, and a nil
	// read there is a panic in a goroutine — which takes the whole process down,
	// not just the socket. Bailing out instead lets monitorConnection redial.
	conn := b.conn
	if conn == nil {
		b.isConnected = false
		return
	}

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			b.isConnected = false
			return
		}

		if b.onMessage != nil {
			err := b.onMessage(string(message))
			if err != nil {
				return
			}
		}
	}
}

func (b *WebSocket) monitorConnection() {
	ticker := time.NewTicker(time.Second * 5) // Check every 5 seconds
	defer ticker.Stop()

	for {
		<-ticker.C
		if !b.isConnected && b.ctx.Err() == nil { // Check if disconnected and context not done
			// redial, not Connect: Connect reports a dial failure by returning the
			// RECEIVER (so callers can keep using the value) while leaving conn nil
			// and isConnected false. Reading that non-nil return as success is what
			// set isConnected = true and started a reader against a nil conn — a
			// nil-pointer panic in a goroutine, i.e. the process dies.
			//
			// Connect is also the wrong call for a reconnect on its own terms: it
			// starts monitorConnection and ping and installs a fresh context, so
			// driving it from the monitor doubles all three every time the socket
			// drops, and leaves two readers racing ReadMessage on one connection.
			b.redial()
		}

		select {
		case <-b.ctx.Done():
			return // Stop the routine if context is done
		default:
		}
	}
}

func (b *WebSocket) SetMessageHandler(handler MessageHandler) {
	b.onMessage = handler
}

type WebSocket struct {
	conn         *websocket.Conn
	writeMu      sync.Mutex
	url          string
	apiKey       string
	apiSecret    string
	maxAliveTime string
	pingInterval int
	onMessage    MessageHandler
	ctx          context.Context
	cancel       context.CancelFunc
	isConnected  bool
	proxyURL     string
}

type WebsocketOption func(*WebSocket)

func WithPingInterval(pingInterval int) WebsocketOption {
	return func(c *WebSocket) {
		c.pingInterval = pingInterval
	}
}

func WithMaxAliveTime(maxAliveTime string) WebsocketOption {
	return func(c *WebSocket) {
		c.maxAliveTime = maxAliveTime
	}
}

func WithWsProxyURL(proxyURL string) WebsocketOption {
	return func(c *WebSocket) {
		c.proxyURL = proxyURL
	}
}

func NewBybitPrivateWebSocket(url, apiKey, apiSecret string, handler MessageHandler, options ...WebsocketOption) *WebSocket {
	c := &WebSocket{
		url:          url,
		apiKey:       apiKey,
		apiSecret:    apiSecret,
		maxAliveTime: "",
		pingInterval: 20,
		onMessage:    handler,
	}

	// Apply the provided options
	for _, opt := range options {
		opt(c)
	}

	return c
}

func NewBybitPublicWebSocket(url string, handler MessageHandler) *WebSocket {
	c := &WebSocket{
		url:          url,
		pingInterval: 20, // default is 20 seconds
		onMessage:    handler,
	}

	return c
}

// dialer builds the websocket dialer, applying the proxy when one is configured.
//
// Split out because Connect and redial must dial the same way; when the proxy
// setup lived inline in Connect, a reconnect could only be done by calling
// Connect itself, which does far more than dial.
func (b *WebSocket) dialer() (*websocket.Dialer, error) {
	if b.proxyURL == "" {
		return websocket.DefaultDialer, nil
	}
	proxyURL, err := url.Parse(b.proxyURL)
	if err != nil {
		return nil, err
	}
	// Copy rather than mutating DefaultDialer: it is package-level shared state,
	// so setting Proxy on it configures every other dialer in the process too.
	d := *websocket.DefaultDialer
	d.Proxy = http.ProxyURL(proxyURL)
	return &d, nil
}

// redial re-establishes a dropped socket and restarts ONLY the reader, reporting
// whether the connection is usable afterwards.
//
// This is the reconnect path, deliberately distinct from Connect. Connect is the
// one-time setup: besides dialing it starts monitorConnection and ping and
// installs the context those two watch. Reconnecting through it therefore adds a
// second monitor, a second pinger and a fresh context on every drop, orphaning
// the cancel the caller holds. redial touches only what a reconnect actually
// needs to replace.
//
// On any failure the socket is left nil and disconnected, so the next monitor
// tick retries rather than a reader being started against a half-open one.
func (b *WebSocket) redial() bool {
	dialer, err := b.dialer()
	if err != nil {
		b.isConnected = false
		return false
	}

	wssUrl := b.url
	if b.maxAliveTime != "" {
		wssUrl += "?max_alive_time=" + b.maxAliveTime
	}

	conn, _, err := dialer.Dial(wssUrl, nil)
	if err != nil || conn == nil {
		b.conn = nil
		b.isConnected = false
		return false
	}
	b.conn = conn

	if b.requiresAuthentication() {
		if err := b.sendAuth(); err != nil {
			_ = conn.Close()
			b.conn = nil
			b.isConnected = false
			return false
		}
	}

	b.isConnected = true
	go b.handleIncomingMessages()
	return true
}

func (b *WebSocket) Connect() *WebSocket {
	var err error
	wssUrl := b.url
	if b.maxAliveTime != "" {
		wssUrl += "?max_alive_time=" + b.maxAliveTime
	}

	dialer, err := b.dialer()
	if err != nil {
		return nil
	}

	b.conn, _, err = dialer.Dial(wssUrl, nil)
	if err != nil || b.conn == nil {
		// Dial failed: leave the socket non-connected and do NOT spawn any
		// goroutine or attempt a write against a nil conn. Callers detect
		// failure via isConnected (mirrors the sendAuth error branch below).
		b.isConnected = false
		return b
	}

	if b.requiresAuthentication() {
		if err = b.sendAuth(); err != nil {
			// The dial succeeded, so without this the failed attempt leaves a live
			// unauthenticated socket in b.conn that nothing ever closes — the next
			// reconnect just overwrites the field and leaks it.
			_ = b.conn.Close()
			b.conn = nil
			b.isConnected = false
			return nil
		}
	}
	b.isConnected = true

	go b.handleIncomingMessages()
	go b.monitorConnection()

	b.ctx, b.cancel = context.WithCancel(context.Background())
	go ping(b)

	return b
}

func (b *WebSocket) SendSubscription(args []string) (*WebSocket, error) {
	reqID := uuid.New().String()
	subMessage := map[string]interface{}{
		"req_id": reqID,
		"op":     "subscribe",
		"args":   args,
	}
	if err := b.sendAsJson(subMessage); err != nil {
		return b, err
	}
	return b, nil
}

// SendRequest sendRequest sends a custom request over the WebSocket connection.
func (b *WebSocket) SendRequest(op string, args map[string]interface{}, headers map[string]string, reqId ...string) (*WebSocket, error) {
	finalReqId := uuid.New().String()
	if len(reqId) > 0 && reqId[0] != "" {
		finalReqId = reqId[0]
	}

	request := map[string]interface{}{
		"reqId":  finalReqId,
		"header": headers,
		"op":     op,
		"args":   []interface{}{args},
	}
	if err := b.sendAsJson(request); err != nil {
		return b, err
	}
	return b, nil
}

func (b *WebSocket) SendTradeRequest(tradeTruest map[string]interface{}) (*WebSocket, error) {
	if err := b.sendAsJson(tradeTruest); err != nil {
		return b, err
	}
	return b, nil
}

func ping(b *WebSocket) {
	if b.pingInterval <= 0 {
		return
	}

	ticker := time.NewTicker(time.Duration(b.pingInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			currentTime := time.Now().Unix()
			pingMessage := map[string]string{
				"op":     "ping",
				"req_id": fmt.Sprintf("%d", currentTime),
			}
			jsonPingMessage, err := json.Marshal(pingMessage)
			if err != nil {
				continue
			}
			if b.conn == nil {
				return
			}
			b.writeMu.Lock()
			err = b.conn.WriteMessage(websocket.TextMessage, jsonPingMessage)
			b.writeMu.Unlock()
			if err != nil {
				return
			}

		case <-b.ctx.Done():
			return
		}
	}
}

func (b *WebSocket) Disconnect() error {
	b.cancel()
	b.isConnected = false
	// A WebSocket whose Connect failed to dial has a nil conn, and Disconnect is
	// exactly what a caller runs on that failure path.
	if b.conn == nil {
		return nil
	}
	return b.conn.Close()
}

func (b *WebSocket) requiresAuthentication() bool {
	return b.url == WEBSOCKET_PRIVATE_MAINNET || b.url == WEBSOCKET_PRIVATE_TESTNET ||
		b.url == WEBSOCKET_TRADE_MAINNET || b.url == WEBSOCKET_TRADE_TESTNET ||
		b.url == WEBSOCKET_TRADE_DEMO || b.url == WEBSOCKET_PRIVATE_DEMO
	// v3 offline
	/*
		b.url == V3_CONTRACT_PRIVATE ||
			b.url == V3_UNIFIED_PRIVATE ||
			b.url == V3_SPOT_PRIVATE
	*/
}

func (b *WebSocket) sendAuth() error {
	// Get current Unix time in milliseconds
	expires := time.Now().UnixNano()/1e6 + 10000
	val := fmt.Sprintf("GET/realtime%d", expires)

	h := hmac.New(sha256.New, []byte(b.apiSecret))
	h.Write([]byte(val))

	// Convert to hexadecimal instead of base64
	signature := hex.EncodeToString(h.Sum(nil))

	authMessage := map[string]interface{}{
		"req_id": uuid.New(),
		"op":     "auth",
		"args":   []interface{}{b.apiKey, expires, signature},
	}
	return b.sendAsJson(authMessage)
}

func (b *WebSocket) sendAsJson(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.send(string(data))
}

func (b *WebSocket) send(message string) error {
	if b.conn == nil {
		return fmt.Errorf("websocket is not connected")
	}
	b.writeMu.Lock()
	defer b.writeMu.Unlock()
	return b.conn.WriteMessage(websocket.TextMessage, []byte(message))
}
