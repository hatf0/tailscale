// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Type definitions need to be manually imported for dts-bundle-generator to
// discover them.
/// <reference path="../types/esbuild.d.ts" />
/// <reference path="../types/wasm_js.d.ts" />

import wasmURL from "./main.wasm"
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TextEncoder, TextDecoder } from 'node:util';
import { webcrypto } from 'node:crypto';
import { resolve } from 'node:path';
// @ts-ignore
import { WebSocket } from "ws";

/**
 * Superset of the IPNConfig type, with additional configuration that is
 * needed for the package to function.
 */
type IPNPackageConfig = IPNConfig & {
  // Auth key used to initialize the Tailscale client (required)
  authKey: string
  // URL of the main.wasm file that is included in the page, if it is not
  // accessible via a relative URL.
  wasmURL?: string
  // Function invoked if the Go process panics or unexpectedly exits.
  panicHandler: (err: string) => void
}

export async function createTSNet(config: IPNPackageConfig): Promise<IPN> {
  const tsStateStorage: { [key: string]: any } = {};
  const sessionStateStorage: IPNStateStorage = {
    setState(id, value) {
      tsStateStorage[`ipn-state-${id}`] = value
    },
    getState(id) {
      return tsStateStorage[`ipn-state-${id}`] || ""
    },
  }

  // @ts-ignore
  globalThis.TextEncoder = TextEncoder;
  // @ts-ignore
  globalThis.TextDecoder = TextDecoder;
  // @ts-ignore
  globalThis.crypto ??= webcrypto
  globalThis.fetch = fetch;
  globalThis.Headers = Headers;
  // Patch out process (temporarily)
  // @ts-ignore
  globalThis.process = undefined;
  // @ts-ignore
  globalThis.WebSocket = WebSocket;
  require("./wasm_exec");

  const go = new Go()
  const wasmInstance = await WebAssembly.instantiate(
    fs.readFileSync(path.join(new URL(import.meta.url).pathname, `../${wasmURL}`)),
    go.importObject
  )

  // The Go process should never exit, if it does then it's an unhandled panic.
  go.run(wasmInstance.instance).then(() =>
    config.panicHandler("Unexpected shutdown")
  )

  return newTSNet({
    ...config,
    stateStorage: sessionStateStorage
  })
}
