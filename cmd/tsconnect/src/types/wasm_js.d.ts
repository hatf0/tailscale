// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview Type definitions for types exported by the wasm_js.go Go
 * module.
 */

declare global {
  function newTSNet(config: IPNConfig): IPN

  interface IPN {
    run(callbacks: IPNCallbacks): void
    listen(args: ListenArgs): void
  }

  interface IPNSSHSession {
    resize(rows: number, cols: number): boolean
    close(): boolean
  }

  interface IPNStateStorage {
    setState(id: string, value: string): void
    getState(id: string): string
  }

  type IPNConfig = {
    stateStorage?: IPNStateStorage
    authKey?: string
    controlURL?: string
    hostname?: string
  }

  type ListenArgs = {
    port: number,
    onConnection: (socket: IPNSocket) => void,
  };

  type IPNSocket = {
    read: ReadableStream<Uint8Array>,
    write: WritableStream<Uint8Array>,
    close: () => void,
  }

  type IPNCallbacks = {
    notifyState: (state: IPNState) => void
    notifyNetMap: (netMapStr: string) => void
    notifyBrowseToURL: (url: string) => void
    notifyPanicRecover: (err: string) => void
  }

  type IPNNetMap = {
    self: IPNNetMapSelfNode
    peers: IPNNetMapPeerNode[]
    lockedOut: boolean
  }

  type IPNNetMapNode = {
    name: string
    addresses: string[]
    machineKey: string
    nodeKey: string
  }

  type IPNNetMapSelfNode = IPNNetMapNode & {
    machineStatus: IPNMachineStatus
  }

  type IPNNetMapPeerNode = IPNNetMapNode & {
    online?: boolean
    tailscaleSSHEnabled: boolean
  }

  /** Mirrors values from ipn/backend.go */
  type IPNState =
    | "NoState"
    | "InUseOtherUser"
    | "NeedsLogin"
    | "NeedsMachineAuth"
    | "Stopped"
    | "Starting"
    | "Running"

  /** Mirrors values from MachineStatus in tailcfg.go */
  type IPNMachineStatus =
    | "MachineUnknown"
    | "MachineUnauthorized"
    | "MachineAuthorized"
    | "MachineInvalid"
}

export {}
