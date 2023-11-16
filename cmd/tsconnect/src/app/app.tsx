// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import { render, Component } from "preact"
import { URLDisplay } from "./url-display"
import { Header } from "./header"
import { GoPanicDisplay } from "./go-panic-display"

type AppState = {
  ipn?: IPN
  ipnState: IPNState
  goPanicError?: string
}

class App extends Component<{}, AppState> {
  state: AppState = { ipnState: "NoState" }
  #goPanicTimeout?: number

  render() {
    const { ipn, ipnState, goPanicError } = this.state

    let goPanicDisplay
    if (goPanicError) {
      goPanicDisplay = (
        <GoPanicDisplay error={goPanicError} dismiss={this.clearGoPanic} />
      )
    }


    let machineAuthInstructions
    if (ipnState === "NeedsMachineAuth") {
      machineAuthInstructions = (
        <div class="container mx-auto px-4 text-center">
          An administrator needs to approve this device.
        </div>
      )
    }


    return (
      <>
        <Header state={ipnState} ipn={ipn} />
        {goPanicDisplay}
        <div class="flex-grow flex flex-col justify-center overflow-hidden">
          {machineAuthInstructions}
        </div>
      </>
    )
  }

  runWithIPN(ipn: IPN) {
    this.setState({ ipn }, () => {
      ipn.run({
        notifyState: this.handleIPNState,
      })
    })
  }

  handleIPNState = (state: IPNState) => {
    const { ipn } = this.state
    this.setState({ ipnState: state })
    if (state === "NeedsLogin") {
    } else if (["Running", "NeedsMachineAuth"].includes(state)) {
      ipn?.listen({
        port: 80,
        onConnection(socket) {
          const reader = socket.read.getReader();
          const writer = socket.write.getWriter();
          (async () => {
            const arr = await reader.read()
            if (arr.value) {
              console.log(new TextDecoder().decode(arr.value!))
            }
            const writeBuf = new TextEncoder().encode(`HTTP/1.1 200 OK\r\nServer: tailscale-web\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\nHello, world! You are talking to a web server hosted inside of a web browser!\r\nIt is currently ${new Date().toISOString()}. My user-agent is: ${navigator.userAgent}.\r\n\r\n`)
            try {
              await writer.write(writeBuf);
            } catch (e) {
              console.error(e);
            }
            socket.close();
          })();
        },});
    }
  }

  handleGoPanic = (error: string) => {
    if (DEBUG) {
      console.error("Go panic", error)
    }
    this.setState({ goPanicError: error })
    if (this.#goPanicTimeout) {
      window.clearTimeout(this.#goPanicTimeout)
    }
    this.#goPanicTimeout = window.setTimeout(this.clearGoPanic, 10000)
  }

  clearGoPanic = () => {
    window.clearTimeout(this.#goPanicTimeout)
    this.#goPanicTimeout = undefined
    this.setState({ goPanicError: undefined })
  }
}

export function renderApp(): Promise<App> {
  return new Promise((resolve) => {
    render(
      <App ref={(app) => (app ? resolve(app) : undefined)} />,
      document.body
    )
  })
}
