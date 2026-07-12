# Recording the Sluice demo GIF

Use this after `bash scripts/demo.sh` works on your machine.

## What to show (30 seconds)

1. Terminal: `bash scripts/demo.sh` running
2. **Block 1** — direct secret in outbound call → JSON-RPC error
3. **Block 2** — `read_file` succeeds, then `send_email` with same secret → `taint_leak` error
4. Optional: browser tab on `http://127.0.0.1:4444/_sluice/` showing blocked events

## macOS — Kap (easiest)

1. Install [Kap](https://getkap.co/)
2. Set capture area to terminal window
3. Run `bash scripts/demo.sh`
4. Export as GIF (15–30 fps, ~1280px wide)
5. Save to `docs/assets/demo.gif`

## macOS / Linux — asciinema + agg

```bash
# Install: brew install asciinema agg
asciinema rec /tmp/sluice-demo.cast
# run: bash scripts/demo.sh
# exit recording with Ctrl-D

agg /tmp/sluice-demo.cast docs/assets/demo.gif
```

## ffmpeg (screen region)

```bash
# Record ~30s of a screen region (adjust coordinates)
ffmpeg -f avfoundation -i "1:none" -t 30 -r 15 demo.mov
ffmpeg -i demo.mov -vf "fps=10,scale=1280:-1:flags=lanczos" -loop 0 docs/assets/demo.gif
```

## After recording

1. Commit `docs/assets/demo.gif`
2. README already references it once the file exists
3. Use the GIF in GitHub release notes and social posts

## Cursor / Claude Desktop variant

For a second GIF showing the desktop client:

1. Add Sluice to MCP config (`sluice stdio --config ...`)
2. Ask agent to read a file containing a fake AWS key
3. Ask agent to email or post that value
4. Show the tool call failing in the UI

See [docs/guide.md](guide.md) sections 6–7 for wiring.
