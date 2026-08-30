# sb-easy Agent UI

The local Agent console is an independent Svelte application. The C++ Agent
does not compile HTML, CSS, or JavaScript into its executable; it only exposes
the authenticated `/api/*` contract and serves the static directory selected by
`AGENT_UI_PATH`.

```sh
npm ci
npm run check
npm run build

export AGENT_UI_PASSWORD='use-a-strong-local-password'
export AGENT_UI_PATH="$PWD/dist"
../build/cpp/sb-easy-cpp-agent
```

For frontend development, run `npm run dev`. Vite listens on port 51823 and
proxies `/api` and `/health` to an Agent listening on `127.0.0.1:51822`.

The production Docker image installs the build output at
`/usr/share/sb-easy/agent-ui`, which is also the Agent's default path. Operators
can replace that directory with another compatible UI without rebuilding the
service process.
