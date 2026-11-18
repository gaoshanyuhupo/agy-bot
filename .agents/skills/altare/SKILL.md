---
name: altare
description: Use Altare through the altr CLI and the Altare MCP tools. Start disposable Linux machines (Altare Go) to run code, builds, tests and servers; manage the user's Altare servers, sandboxes and snapshots; Altare Workstations (full Linux VMs in London, as SSH servers or desktops you can see and control with screenshots, mouse and keyboard); deploy apps from GitHub (deploys, logs, variables, previews) or from Docker images; deploy Edge Functions; manage Postgres, MySQL and Valkey databases, KV, queues and U3 buckets; DNS zones and records, app domains and the Email Gateway; Altare AI API keys, usage and alerts; the private network, Mesh and tunnels. Use when the user mentions Altare, altr, Altare Go, Altare AI or any of these, or when you need a clean Linux environment, root access, more CPU or memory than the local machine, a Linux desktop or GUI app, or a place to run untrusted or long-running code.
---

# Altare

`altr` is the Altare command line. The Altare MCP server (`altr mcp`) gives the same platform to agents as tools. Altare Go machines are Linux boxes that start in seconds: Debian 13 by default, with 8 GB memory, 40 GB disk, 4 CPUs, root and internet access. They last up to 12 hours. Free accounts can run 3 at a time, Altare Plus 15.

## Before you start

- Check that altr is installed and signed in: `altr whoami`. If it says "not logged in", ask the user to run `altr login` (it opens a browser). Don't log in for them.
- If altr is missing, the user can install it with `curl -fsSL https://altare.gg/install.sh | sh`.
- Without a browser (CI, a remote agent), the user runs `altr token` on a signed-in computer and sets `ALTARE_TOKEN` to it. A team API token (`alt_…`) also works there or in `--token`, limited to its team and scopes; it can't start Go machines or list other teams, and most products need `altr login`.
- Team resources (everything but Go machines) use the current team (`altr team use "Name"`), or `--team` on any command. MCP tools take an optional `team` argument (name or ID) the same way; `teams_list` shows the teams.
- Add `--json` to any command for machine-readable output.

## MCP tools or the CLI

If the Altare MCP server is connected (tools named `go_start`, `servers_list`…), prefer its tools to shell commands. It has tools for:

- Go machines: `go_start`, `go_exec`, `go_read_file`, `go_write_file`, `go_pause`, `go_resume`, `go_fork`, `go_expose`, `go_save`, `go_stop` and more.
- Workstations: `workstations_list`, `workstation_get`, `workstation_catalog`, `workstation_create`, `workstation_power`, `workstation_resize`, `workstation_update`, `workstation_delete`, `workstation_exec`, `workstation_read_file`, `workstation_write_file`, ports, snapshots, `workstation_metrics`, and computer use: `workstation_screenshot`, `workstation_click`, `workstation_move`, `workstation_drag`, `workstation_scroll`, `workstation_type`, `workstation_key`, `workstation_wait`.
- Teams, servers, sandboxes, snapshots, SSH keys and the private network: `teams_list`, `servers_list`, `server_create`, `server_power`, `server_command`, server files, `snapshots_list`, `snapshot_restore`, `network_info`.
- Apps: `apps_list`, `app_deploy`, `app_logs`, `app_env_list`/`app_env_set`, domains, previews; Docker apps: `docker_create`, `docker_info`, `docker_set`, `docker_redeploy`, `docker_env_set`.
- Edge Functions: `functions_list`, `function_info`, `function_deploy` (a local folder), `function_logs`, `function_rollback`, `function_env`/`function_env_set`, `function_delete`.
- Databases (`engine`: postgres, mysql or valkey): `databases_list`, `database_info`, `database_create`, `database_restart`, backups, `database_restore`, `database_delete`; `attach_to_app` connects a database, KV namespace, queue or bucket to an app.
- KV (`kv_get`, `kv_put`, `kv_keys`…), queues (`queue_send`, `queue_peek`, `queue_purge`…), U3 (`u3_list`, `u3_get`, `u3_put` for text up to 1 MB…).
- DNS zones and records, email domains, `email_send`, `email_logs`; Altare AI: `ai_status`, `ai_models`, `ai_keys`, `ai_key_update`, `ai_key_delete`, `ai_usage`, `ai_alerts`.

CLI only, because they keep running, stream, open a shell or print a secret: `altr ws ssh`, `altr ws password`, `altr ws desktop` (opens the browser), `altr mesh up`, `altr tunnel`, `altr logs -f`, `altr functions logs -f`, `altr email logs -f`, `altr <engine> connect`, `altr <engine> url` and `reset-password`, `altr ai keys create` and `roll`, `altr ai credit add`, registry logins for private images, binary or local-file uploads to U3, and function bindings, routes, cron, queue and bucket triggers and email routes. Run streaming commands in the background and stop them when done; ask the user to run the secret-printing ones themselves.

## Safety rules

- Ask the user, naming the exact resource, before anything that deletes, removes, purges, empties, restores, stops or kills, rolls or deletes a key, removes a DNS record, or sends email (`altr email send`, `email_send`). Show who an email goes to and what it says first. Don't touch servers, apps or data the user didn't mention.
- MCP deletes need `confirm` set to the resource's exact name. Pass it only after the user agrees. With the CLI, only pass `--yes` once they have.
- If a delete says Altare wants an emailed code (step-up), stop: tell the user to run the altr command it names in their terminal. Never ask them to paste the code to you.
- Never print, log, echo or commit secrets: workstation passwords, database passwords and URLs, API key secrets, registry tokens, variable values, webhook secrets. Don't run `altr <engine> url`, `info --reveal`, `env ls --reveal`, `ai keys create` or `ai keys roll` yourself. To give an app a database, use `attach_to_app` or `altr postgres attach`, which set the URL without showing it. Never ask the user to paste a secret into the chat.
- Push to GitHub before deploying: Altare builds what's on GitHub.

## Altare Go machines

```bash
altr go -d --json                 # start Debian, don't open a shell; prints the machine as JSON
altr go -d --json --image ubuntu  # or: alpine, fedora, arch, debian-12, ubuntu-26.04, any Docker Hub image (node:22)
altr go ls --json                 # list machines
altr go exec go-abc123 -- 'apt-get update && apt-get install -y build-essential'
altr go cp ./project.tar.gz go-abc123:/root/
altr go cp go-abc123:/root/out/report.txt .
altr go rm go-abc123              # stop it when you're done
altr go save go-abc123 node-dev   # save it as an image; start from it with --image saved:node-dev
```

- Always pass `-d` (detach): without it, `altr go` opens an interactive shell.
- `exec` runs as root and exits with the command's exit code. Quote the command as one argument. Each call is a fresh session: use absolute paths or `cd /dir && …`. Start long-running processes with `nohup cmd > /root/log.txt 2>&1 &` or in `tmux`.
- `--location us-iad` picks a location (the default image in the US starts instantly; others take about a minute). `--ttl 2h` sets a shorter lifetime, `--idle 30m` pauses a forgotten machine by itself.
- Between tasks, `altr go pause` instead of removing (disk and remaining time kept, processes stop, frees a running slot); `altr go resume` brings it back. `altr go fork <machine> --name go-try` copies its files to a new machine.
- `altr go expose go-abc123 3000 --restart` gives port 3000 a public `https://` address (a new port restarts the machine: expose before starting the app). Anyone with the address can reach it. `altr go forward go-abc123 3000` shows it on the user's localhost instead.
- They're containers: no systemd, no Docker inside, no kernel modules. Everything is deleted when a machine is removed or reaches its lifetime.

## Workstations (beta)

Workstations are full Linux virtual machines in London that last until deleted: a server reached over SSH, or a desktop (XFCE, GNOME or KDE) the user opens in their browser and you can see and use. Distros: Ubuntu 24.04 and 26.04, Debian 13 and 12, Fedora, AlmaLinux 10, Arch, Kali (desktop only); `altr ws catalog` or `workstation_catalog` lists them with the team's limits and prices.

**A workstation or a Go machine?** Use a Go machine (or a sandbox) for quick, throwaway work: builds, tests, trying code. It starts in seconds and is free within the account's limits. Use a workstation when the user has one or asks for one, or the task needs a desktop or a GUI app, a real VM (systemd, Docker, kernel modules, a VPN), or a machine that keeps its disk and stays up for days. Don't create one unasked: it costs money while it runs.

```bash
altr ws list                        # altr ws get dev, altr ws catalog
altr ws create dev --preset developer --wait            # a server; adds ~/.ssh/id_ed25519.pub
altr ws create desk --desktop xfce --memory 8G --auto-stop 1h --wait
altr ws exec dev -- 'apt-get update && apt-get install -y ripgrep'   # as root, exits with its code
altr ws cp ./app.tar.gz dev:/home/altare/            # either way, up to 32 MB
altr ws ports add dev 8080 --label web               # a public host:port; anyone can reach it
altr ws snapshots take dev -m 'before upgrade'       # snapshots ls / restore / rm (up to 5)
altr ws stop dev                    # start / restart / stop --force; the disk is kept
altr ws resize dev --vcpus 4 --memory 8G             # restart for CPU and memory; disks only grow
altr ws set dev --schedule "09:00-18:00 mon-fri Europe/London"   # --auto-stop 2h, --startup-script @boot.sh
altr ws screenshot desk -o desk.png
```

- `exec` (`workstation_exec`) and the file tools run as **root** through the guest agent, without SSH. Each call is a fresh non-interactive `sh`; it waits up to 300 seconds (default 60) and then leaves the command running, so start long jobs with `nohup … > /root/job.log 2>&1 &` and check on them. The machine must be running.
- The login user (default `altare`) has a generated password for sudo and the desktop. You never see it: the user reads it with `altr ws password <name>`. Don't run that yourself or ask them to paste it.
- Computer use on a desktop: take `workstation_screenshot`, do one action (`workstation_click`, `_type`, `_key` such as `ctrl+alt+t` or `Return`, `_scroll`, `_drag`), then look at the screenshot the action returns before the next one. Coordinates are pixels in the latest screenshot (scaled to at most 1280 wide; the tool maps them back). Use `workstation_wait` while something loads. Click into a field before typing. Prefer `workstation_exec` and the file tools when the job doesn't need the screen: they are faster and exact.
- Costs: usage-billed by the hour while running (vCPUs, dedicated cores, memory) plus disk per GB-month, also while stopped. Stop it when the work is done unless the user wants it kept running; set `--auto-stop` so a forgotten one stops by itself. Beta seats on Altare Free (`altr experiments join workstations`) pay 500 bolts a day running and 100 stopped, get one small workstation, and stop after 2 hours idle.
- Beta: Plus and Business teams have them; on Free the team owner joins the beta. Deleting (`altr ws delete`, `workstation_delete` with confirm) removes the disk and snapshots for good and may ask for an emailed code.
- Safety: exec is root on a machine the user may use every day, so ask before changing system settings, installing services, opening ports or deleting files they didn't mention. Never put secrets in commands, files or typed text unless the user asked for exactly that, and don't screenshot or read files that hold their secrets without need.

## Servers

```bash
altr servers                       # servers in the current team; altr teams, altr team use "Team"
altr server info <server>
altr server restart <server>       # also: start, stop, kill
altr server cmd <server> say hello # console command
altr server create mc --template <template> --memory 2048   # see altr server templates and locations
altr files cat <server> /server.properties             # files ls / put / get / rm
altr snapshots take <server>       # snapshots ls; snapshots restore <server> <id> replaces its files
altr ssh <sandbox>                 # SSH into a sandbox server (team keys: altr keys ls / add)
```

## Apps from GitHub and Docker images

```bash
altr apps                          # apps across teams: repo@branch, latest deploy, URL
altr deploy                        # inside a clone: deploy this repo's app, stream the build log
altr deploy my-bot --ref v1.2.0 --json   # a branch, tag or commit; exits 1 if the deploy failed
altr logs my-bot --since 1h --grep error # kept logs; -f streams live
altr env ls my-bot                 # env set my-bot KEY=value, env unset my-bot KEY
altr domains add my-bot app.example.com  # domains ls / rm
altr previews create my-bot feature-x    # previews ls / redeploy / rm
altr docker create web nginx:1.27 --port 80 -e KEY=value
altr docker set web --tag 1.28     # docker info, docker redeploy, docker env set web KEY=value
```

## Edge Functions

```bash
altr functions deploy api ./worker --create -m 'First version'   # bundles .js/.ts/.json/.wasm…
altr functions logs api            # recent requests; -f follows live
altr functions rollback api 3      # versions: altr functions versions api
altr functions secrets set api TOKEN=…   # env set/ls/unset; bindings, routes, cron, queues, buckets, email
```

## Databases and storage

```bash
altr postgres create main --region eu   # also mysql and valkey: ls, info, backups, restart, delete
altr postgres attach main my-bot        # sets DATABASE_URL on the app and redeploys it
altr postgres backups restore main <backup-id> --name main-copy   # restores into a new database
altr kv put sessions key value --ttl 3600   # kv ls/create/keys/get/rm/delete/attach
altr queues send jobs '{"id": 1}' --json-body   # queues ls/create/peek/purge/delete/attach
altr u3 put ./cat.png uploads/images/cat.png    # u3 ls/get/rm/empty/delete/attach
```

## DNS, domains and email

```bash
altr dns add example.com           # then point the nameservers it prints; dns ls / check / rm
altr dns records add example.com A @ 203.0.113.10   # records ls / rm (--type when names repeat)
altr email add example.com --receiving   # prints the DNS records; then altr email verify example.com
altr email send --from hi@example.com --to you@example.org --subject Hi --text 'It works'
altr email logs --direction out    # email routes add support@example.com --forward me@example.org
```

## Altare AI (OpenAI-compatible API)

```bash
altr ai                            # Token Plan, 5-hour and weekly limits, API credit, base URL
altr ai models
altr ai keys                       # ai keys update ci --limit 50, ai keys rm ci
altr ai usage --days 7             # also: ai keys usage <key>, ai credit, ai alerts
```

The user creates and rolls keys (`altr ai keys create <name>`, `altr ai keys roll <key>`) in their own terminal: the secret is shown once.

## Private network, Mesh and tunnels

Every app has a private address and a name `<app>.<team>.internal` (`altr network`, `altr network dns`, or the `network_info` tool). `altr mesh up --daemon` puts this computer on that network over WireGuard as `<device>.<team>.mesh`; it needs root (altr asks for sudo). `altr tunnel 3000` shares a local port on a public `https://` address and keeps running, printing each request: run it in the background and stop it when done. Both are CLI only.

```bash
altr mesh up --daemon              # altr mesh status / down
altr mesh keys create --reusable --ephemeral --tag tag:ci   # for CI: sudo altr mesh up --auth-key altk_… --daemon
altr tunnel 3000                   # --name shop (Plus), --domain, --auth user:pass; altr tunnel tcp 25565
```
