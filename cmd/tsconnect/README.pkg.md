# tailnet

NPM package that contains a WebAssembly-based Tailscale client. This is derived from Tailscale's Connect SDK (see: `@tailscale/connect`).

## Installation
```
$ npm i --save tailnet
```

## Usage
```
import { createTSNet } from 'tailnet'

async main() {
  const ts = createTSNet({
    authKey: "tskey-auth-your-auth-key-here",
    hostname: "my-cool-node-js-client",
    panicHandler: console.error,
    ephemeral: true
  });

  await ts.run({
    notifyState: (state) => {
      console.log(`New state: ${state}`)
    }
  });

  // after this point, you should be logged in with Tailscale!
  const listener = await ts.listen({
    protocol: "tcp",
    port: 80,
    onConnection: (connection) => {
      // handle connection
    }
  });

  // and cleanup everything...
  listener.close();
  ts.close();
}
```