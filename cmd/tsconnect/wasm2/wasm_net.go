// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The wasm package builds a WebAssembly module that provides a subset of
// Tailscale APIs to JavaScript.
//
// When run in the browser, a newIPN(config) function is added to the global JS
// namespace. When called it returns an ipn object with the methods
// run(callbacks), login(), logout(), and ssh(...).
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"syscall/js"

	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/logpolicy"
	"tailscale.com/logtail"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/types/views"
	"tailscale.com/words"
)

// ControlURL defines the URL to be used for connection to Control.
var ControlURL = ipn.DefaultControlURL

func main() {
	js.Global().Set("newTSNet", js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 1 {
			log.Fatal("Usage: newTSNet(config)")
			return nil
		}
		// stub
		return newIPN(args[0])
	}))
	// Keep Go runtime alive, otherwise it will be shut down before newIPN gets
	// called.
	<-make(chan bool)
}

func newIPN(jsConfig js.Value) map[string]any {
	netns.SetEnabled(false)

	var store ipn.StateStore
	if jsStateStorage := jsConfig.Get("stateStorage"); !jsStateStorage.IsUndefined() {
		store = &jsStateStore{jsStateStorage}
	} else {
		store = new(mem.Store)
	}

	controlURL := ControlURL
	if jsControlURL := jsConfig.Get("controlURL"); jsControlURL.Type() == js.TypeString {
		controlURL = jsControlURL.String()
	}

	var authKey string
	if jsAuthKey := jsConfig.Get("authKey"); jsAuthKey.Type() == js.TypeString {
		authKey = jsAuthKey.String()
	}

	var hostname string
	if jsHostname := jsConfig.Get("hostname"); jsHostname.Type() == js.TypeString {
		hostname = jsHostname.String()
	} else {
		hostname = generateHostname()
	}

	var ephemeral bool
	if jsEphemeral := jsConfig.Get("ephemeral"); jsEphemeral.Type() == js.TypeString {
		ephemeral = jsEphemeral.Bool()
	} else {
		ephemeral = true
	}

	lpc := getOrCreateLogPolicyConfig(store)
	c := logtail.Config{
		Collection: lpc.Collection,
		PrivateID:  lpc.PrivateID,
		// NewZstdEncoder is intentionally not passed in, compressed requests
		// set HTTP headers that are not supported by the no-cors fetching mode.
		HTTPC: &http.Client{Transport: &noCORSTransport{http.DefaultTransport}},
	}
	logtail := logtail.NewLogger(c, log.Printf)
	logf := logtail.Logf

	srv := &tsnet.Server{
		Store:      store,
		Hostname:   hostname,
		Logf:       logf,
		Ephemeral:  ephemeral,
		AuthKey:    authKey,
		ControlURL: controlURL,
		Dir:        "/tailscale",
	}

	jsIPN := &jsIPN{
		srv:        srv,
		controlURL: controlURL,
		authKey:    authKey,
		hostname:   hostname,
	}

	return map[string]any{
		"run": js.FuncOf(func(this js.Value, args []js.Value) any {
			if len(args) != 1 {
				log.Fatal(`Usage: run({
					notifyState(state: int): void,
				})`)
				return nil
			}
			jsIPN.run(args[0])
			return nil
		}),
		"close": js.FuncOf(func(this js.Value, args []js.Value) any {
			err := jsIPN.srv.Close()
			if err != nil {
				return err
			}
			return nil
		}),
		"listen": js.FuncOf(func(this js.Value, args []js.Value) any {
			if len(args) != 1 {
				log.Fatal(`Usage: listen({
					port: number,
					protocol?: "tcp" : "udp",
					onConnection(socket: Socket): void
				})`)
				return nil
			}

			jsIPN.listen(args[0])
			return nil
		}),
		"listenTLS": js.FuncOf(func(this js.Value, args []js.Value) any {
			if len(args) != 1 {
				log.Fatal(`Usage: listenTLS({
					port: number,
					protocol?: "tcp",
					onConnection(socket: Socket): void
				})`)
				return nil
			}

			jsIPN.listenTLS(args[0])
			return nil
		}),
		"listenFunnel": js.FuncOf(func(this js.Value, args []js.Value) any {
			if len(args) != 1 {
				log.Fatal(`Usage: listenFunnel({
					port: number,
					protocol?: "tcp",
					onConnection(socket: Socket): void
				})`)
				return nil
			}

			jsIPN.listenFunnel(args[0])
			return nil
		}),
	}
}

type jsIPN struct {
	srv        *tsnet.Server
	controlURL string
	authKey    string
	hostname   string
}

var jsIPNState = map[ipn.State]string{
	ipn.NoState:          "NoState",
	ipn.InUseOtherUser:   "InUseOtherUser",
	ipn.NeedsLogin:       "NeedsLogin",
	ipn.NeedsMachineAuth: "NeedsMachineAuth",
	ipn.Stopped:          "Stopped",
	ipn.Starting:         "Starting",
	ipn.Running:          "Running",
}

var jsMachineStatus = map[tailcfg.MachineStatus]string{
	tailcfg.MachineUnknown:      "MachineUnknown",
	tailcfg.MachineUnauthorized: "MachineUnauthorized",
	tailcfg.MachineAuthorized:   "MachineAuthorized",
	tailcfg.MachineInvalid:      "MachineInvalid",
}

func (i *jsIPN) run(jsCallbacks js.Value) js.Value {
	notifyState := func(state ipn.State) {
		jsCallbacks.Call("notifyState", jsIPNState[state])
	}
	notifyState(ipn.NoState)

	return makePromise(func() (any, error) {
		status, err := i.srv.Up(context.Background())
		if err != nil {
			log.Printf("Start error: %v", err)
			return nil, err
		}
		jsCallbacks.Call("notifyState", status.BackendState)
		return nil, nil
	})
}

func makeJSSocket(conn net.Conn) map[string]any {
	readStreamConstructor := js.Global().Get("ReadableStream")
	writableStreamConstructor := js.Global().Get("WritableStream")
	uint8Array := js.Global().Get("Uint8Array")
	closed := false

	read := map[string]any{
		"pull": js.FuncOf(func(this js.Value, args []js.Value) any {
			go func() {
				if closed {
					return
				}
				buf := make([]byte, 4096)
				len, err := conn.Read(buf)
				if err != nil {
					log.Printf("Read error: %v", err)
					return
				}

				if len == 0 {
					// no data to read
					return
				}

				controller := args[0]
				chunkArr := uint8Array.New(len)
				js.CopyBytesToJS(chunkArr, buf[:len])
				controller.Call("enqueue", chunkArr)
			}()
			return nil
		}),
		"cancel": js.FuncOf(func(this js.Value, args []js.Value) any {
			if closed {
				return nil
			}
			err := conn.Close()
			if err != nil {
				log.Fatalf("failed to close: %v", err)
				return err
			}
			closed = true
			return nil
		}),
		"type": "bytes",
	}

	readStream := readStreamConstructor.New(read)

	write := map[string]any{
		"write": js.FuncOf(func(this js.Value, args []js.Value) any {
			return makePromise(func() (any, error) {
				if closed {
					return nil, errors.New("trying to write to a closed socket")
				}
				arr := uint8Array.New(args[0])
				sz := arr.Get("length").Int()
				buf := make([]byte, sz)
				copySz := js.CopyBytesToGo(buf, arr)
				if sz != copySz {
					return nil, errors.New("mismatch between copy size and expected size")
				}
				sz, err := conn.Write(buf)
				if err != nil {
					return nil, err
				}
				return sz, nil
			})
		}),
		"close": js.FuncOf(func(this js.Value, args []js.Value) any {
			if closed {
				return nil
			}
			err := conn.Close()
			if err != nil {
				log.Fatalf("failed to close: %v", err)
				return err
			}
			closed = true
			return nil
		}),
	}

	writeStream := writableStreamConstructor.New(write)

	return map[string]any{
		"localAddress": conn.LocalAddr().String(),
		"peerAddress":  conn.RemoteAddr().String(),
		"closed":       closed,
		"read":         readStream,
		"write":        writeStream,
		"close": js.FuncOf(func(this js.Value, args []js.Value) any {
			if closed {
				return nil
			}
			conn.Close()
			return nil
		}),
	}
}

func (i *jsIPN) listen(args js.Value) js.Value {
	port := args.Get("port").Int()

	var protocol string
	if jsProtocol := args.Get("protocol"); jsProtocol.Type() == js.TypeString {
		protocol = jsProtocol.String()
	} else {
		protocol = "tcp"
	}

	return makePromise(func() (any, error) {
		l, err := i.srv.Listen(protocol, fmt.Sprintf(":%d", port))
		if err != nil {
			log.Printf("Listen error: %v", err)
			return nil, err
		}
		log.Printf("Listening on port %d", port)

		stop := false

		go func() {
			for !stop {
				conn, err := l.Accept()
				if err != nil {
					log.Printf("Accept error: %v", err)
					return
				}
				args.Call("onConnection", makeJSSocket(conn))
			}
			l.Close()
		}()

		listener := map[string]any{
			"closed": stop,
			"close": js.FuncOf(func(this js.Value, args []js.Value) any {
				if !stop {
					stop = true
				}

				return nil
			}),
		}

		return listener, nil
	})
}

func (i *jsIPN) listenTLS(args js.Value) js.Value {
	port := args.Get("port").Int()

	return makePromise(func() (any, error) {
		l, err := i.srv.ListenTLS("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			log.Printf("Listen error: %v", err)
			return nil, err
		}
		log.Printf("Listening on port %d", port)

		stop := false

		go func() {
			for !stop {
				conn, err := l.Accept()
				if err != nil {
					log.Printf("Accept error: %v", err)
					return
				}
				args.Call("onConnection", makeJSSocket(conn))
			}
		}()

		listener := map[string]any{
			"closed": stop,
			"close": js.FuncOf(func(this js.Value, args []js.Value) any {
				if !stop {
					stop = true
				}

				return nil
			}),
		}

		return listener, nil
	})
}

func (i *jsIPN) listenFunnel(args js.Value) js.Value {
	port := args.Get("port").Int()

	return makePromise(func() (any, error) {
		l, err := i.srv.ListenFunnel("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			log.Printf("Listen error: %v", err)
			return nil, err
		}
		log.Printf("Listening on port %d", port)

		stop := false

		go func() {
			for !stop {
				conn, err := l.Accept()
				if err != nil {
					log.Printf("Accept error: %v", err)
					return
				}
				args.Call("onConnection", makeJSSocket(conn))
			}
		}()

		listener := map[string]any{
			"closed": stop,
			"close": js.FuncOf(func(this js.Value, args []js.Value) any {
				if !stop {
					stop = true
				}

				return nil
			}),
		}

		return listener, nil
	})
}

type jsStateStore struct {
	jsStateStorage js.Value
}

func (s *jsStateStore) ReadState(id ipn.StateKey) ([]byte, error) {
	jsValue := s.jsStateStorage.Call("getState", string(id))
	if jsValue.String() == "" {
		return nil, ipn.ErrStateNotExist
	}
	return hex.DecodeString(jsValue.String())
}

func (s *jsStateStore) WriteState(id ipn.StateKey, bs []byte) error {
	s.jsStateStorage.Call("setState", string(id), hex.EncodeToString(bs))
	return nil
}

func mapSlice[T any, M any](a []T, f func(T) M) []M {
	n := make([]M, len(a))
	for i, e := range a {
		n[i] = f(e)
	}
	return n
}

func mapSliceView[T any, M any](a views.Slice[T], f func(T) M) []M {
	n := make([]M, a.Len())
	for i := range a.LenIter() {
		n[i] = f(a.At(i))
	}
	return n
}

func filterSlice[T any](a []T, f func(T) bool) []T {
	n := make([]T, 0, len(a))
	for _, e := range a {
		if f(e) {
			n = append(n, e)
		}
	}
	return n
}

func generateHostname() string {
	tails := words.Tails()
	scales := words.Scales()
	if rand.Int()%2 == 0 {
		// JavaScript
		tails = filterSlice(tails, func(s string) bool { return strings.HasPrefix(s, "j") })
		scales = filterSlice(scales, func(s string) bool { return strings.HasPrefix(s, "s") })
	} else {
		// WebAssembly
		tails = filterSlice(tails, func(s string) bool { return strings.HasPrefix(s, "w") })
		scales = filterSlice(scales, func(s string) bool { return strings.HasPrefix(s, "a") })
	}

	tail := tails[rand.Intn(len(tails))]
	scale := scales[rand.Intn(len(scales))]
	return fmt.Sprintf("%s-%s", tail, scale)
}

// makePromise handles the boilerplate of wrapping goroutines with JS promises.
// f is run on a goroutine and its return value is used to resolve the promise
// (or reject it if an error is returned).
func makePromise(f func() (any, error)) js.Value {
	handler := js.FuncOf(func(this js.Value, args []js.Value) any {
		resolve := args[0]
		reject := args[1]
		go func() {
			if res, err := f(); err == nil {
				resolve.Invoke(res)
			} else {
				reject.Invoke(err.Error())
			}
		}()
		return nil
	})

	promiseConstructor := js.Global().Get("Promise")
	return promiseConstructor.New(handler)
}

const logPolicyStateKey = "log-policy"

func getOrCreateLogPolicyConfig(state ipn.StateStore) *logpolicy.Config {
	if configBytes, err := state.ReadState(logPolicyStateKey); err == nil {
		if config, err := logpolicy.ConfigFromBytes(configBytes); err == nil {
			return config
		} else {
			log.Printf("Could not parse log policy config: %v", err)
		}
	} else if err != ipn.ErrStateNotExist {
		log.Printf("Could not get log policy config from state store: %v", err)
	}
	config := logpolicy.NewConfig(logtail.CollectionNode)
	if err := state.WriteState(logPolicyStateKey, config.ToBytes()); err != nil {
		log.Printf("Could not save log policy config to state store: %v", err)
	}
	return config
}

// noCORSTransport wraps a RoundTripper and forces the no-cors mode on requests,
// so that we can use it with non-CORS-aware servers.
type noCORSTransport struct {
	http.RoundTripper
}

func (t *noCORSTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("js.fetch:mode", "no-cors")
	resp, err := t.RoundTripper.RoundTrip(req)
	if err == nil {
		// In no-cors mode no response properties are returned. Populate just
		// the status so that callers do not think this was an error.
		resp.StatusCode = http.StatusOK
		resp.Status = http.StatusText(http.StatusOK)
	}
	return resp, err
}
