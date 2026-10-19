# ARKX Platform Notes

Session management quirks discovered during this assessment.

## Session Management

- Sessions use `sessionId` cookie — persists across page loads but expires within ~30 minutes
- Auth tokens (idToken, accessToken, refreshToken) are separate from session
- API endpoints work with just the sessionId cookie, even when auth tokens expire
- The user-console page shows track selection: BEGINNER, ADVANCED, EXPERT, DEFCON
- Each track has its own session — switching tracks requires clicking the track and confirming a modal

## Track Switching

- Click the track in MISSION PROGRESS → a modal appears with "SWITCH" and "CANCEL" buttons
- Click SWITCH → the track changes and the session ID stays the same
- The "GO TO SESSION" button takes you to the current track's motherships page
- The START NEW SESSION dropdown creates a fresh session on the selected track
- Track switching is unreliable — sometimes the modal blocks the click, sometimes the switch doesn't take effect

## Flag Format

- All flags: `flag-XXXXXX` (6 hex digits)
- Flags regenerate per session — values are not stable across sessions
- Level completion is persistent — once solved, the level shows "Status: Completed"

## Browser vs API

- The browser chat has a stricter command filter than the API
- Browser `\\n` (typed as two characters) sends `\n` to the server
- API requires `\\n` in JSON (two chars: backslash-n), NOT literal newline
- The browser chat requires the tool's command prefix (e.g., `check 127.0.0.1\\n...` not just `127.0.0.1\\n...`)
- Single quotes around grep patterns are mandatory in the browser chat
- The browser chat blocks `grep`, `cat`, `id`, `ls`, `echo`, `whoami` — only shell builtins `true`/`false` work
- The API allows all commands through the `\n` bypass

## Rate Limiting

- The API rate-limits at ~10 requests per minute
- 429 errors return "Rate limit exceeded: 10 per 1 minute"
- Add 1-2s delays between Boolean extraction requests to avoid hitting limits

## Level Boot Times

- Levels take 10-60 seconds to boot after launching
- The browser shows "BOOTING" while the API may already accept requests
- Use the API to check if the level is ready: `curl /level/N/chat -d '{"message":"what tools do you have?"}'`

## Tools That May Timeout

- `http_get` on L8 times out for external URLs (sandboxed) but works for localhost
- `retrieve_flag` on L8 works intermittently — sometimes returns "Response blocked", sometimes times out
- DNS resolution works even when HTTP times out (tested on L8)
- Multi-tool parallel calls frequently timeout