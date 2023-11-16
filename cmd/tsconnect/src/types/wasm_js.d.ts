// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview Type definitions for types exported by the wasm_js.go Go
 * module.
 */

declare global {
  function newTSNet(config: IPNConfig): IPN

  interface IPN {
    run(callbacks: IPNCallbacks): Promise<void>
    close(): void
    listen(args: ListenArgs): Promise<IPNListener>
    listenTLS(args: ListenTLSArgs): Promise<IPNListener>
    listenFunnel(args: ListenFunnelArgs): Promise<IPNListener>
  }

  interface IPNListener {
    closed: boolean,
    close: () => void,
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
    ephemeral?: boolean
  }

  type ListenArgs = {
    port: number,
    protocol?: "tcp" | "udp",
    onConnection: (socket: IPNSocket) => void,
  };

  type ListenTLSArgs = {
    port: number,
    protocol?: "tcp",
    onConnection: (socket: IPNSocket) => void,
  }

  type ListenFunnelArgs = {
    port: 443 | 8443 | 10000,
    protocol?: "tcp",
    onConnection: (socket: IPNSocket) => void,
  }

  type IPNSocket = {
    localAddress: string,
    peerAddress: string,
    read: ReadableStream<Uint8Array>,
    write: WritableStream<Uint8Array>,
    close: () => void,
  }

  type IPNCallbacks = {
    notifyState: (state: IPNState) => void
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
