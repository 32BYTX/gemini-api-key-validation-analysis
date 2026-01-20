# gemini-api-key-validation-analysis

**Technical analysis and proof-of-concept demonstrating how the Google Gemini / Generative Language API validates API-key-shaped input and returns differentiated error semantics prior to model execution.**

---

## Overview

This repository documents a technical analysis of the **pre-authentication API key validation behavior** implemented by the Google Gemini / Generative Language API (`generativelanguage.googleapis.com`).

The focus of this work is **not model behavior**, prompt processing, or AI output, but rather the **API gateway and key-validation layer** that processes requests *before* any Gemini model execution occurs.

The analysis demonstrates that:

- Arbitrary API-key-shaped input is accepted without authentication
- The validation layer returns **distinct, structured error responses**
- These responses allow classification of key state and project association
- Model execution is not required to observe this behavior

This repository is intended as a **neutral, technical research artifact**.

---

## Scope & Non-Goals

### In Scope
- API gateway behavior
- Pre-authentication key validation
- Error semantics and response differentiation
- Automation feasibility

### Out of Scope
- Gemini model internals
- Prompt injection or LLM attacks
- Quota bypass or billing abuse
- Claims of secret data exposure

---

## Simplified Reproduction Request

The behavior can be observed using a **single unauthenticated HTTPS request**.

```http
POST https://generativelanguage.googleapis.com/v1/models/gemini-2.5-flash:generateContent?key=AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Content-Type: application/json

{
  "contents": [
    { "role": "user", "parts": [ { "text": "ping" } ] }
  ]
}
```

No valid API key, Google account, or Gemini usage is required.

Repeating this request with different API-key-shaped strings results in **deterministic, differentiated responses**.

---

## Observed Response Classes

| HTTP Code | Classification | Notes |
|---------|---------------|------|
| 400 | Invalid Key | Key does not map to any project |
| 403 | Service Disabled | Key maps to real project (disabled) |
| 403 | Consumer Suspended | Project suspended |
| 429 | Rate Limited | Project quota exceeded |
| 200 | OK | Request forwarded to model |

Certain error responses include metadata referencing:

```
projects/<PROJECT_ID>
```

---

## Architecture Perspective

### Request Flow

```mermaid
sequenceDiagram
    participant Client as Unauthenticated Client
    participant Gateway as API Gateway
    participant Policy as Key & Project Policy Engine
    participant Model as Gemini Model

    Client->>Gateway: POST /generateContent?key=<ARBITRARY_STRING>
    Gateway->>Policy: Validate key format & lookup

    alt Key does not exist
        Policy-->>Gateway: INVALID_KEY
        Gateway-->>Client: 400 API key not valid
    else Key exists
        Policy->>Policy: Check project state
        alt Project disabled
            Policy-->>Gateway: SERVICE_DISABLED
            Gateway-->>Client: 403 + metadata
        else Project suspended
            Policy-->>Gateway: CONSUMER_SUSPENDED
            Gateway-->>Client: 403 + metadata
        else Quota exceeded
            Policy-->>Gateway: RATE_LIMITED
            Gateway-->>Client: 429 + metadata
        else Valid & enabled
            Policy-->>Gateway: OK
            Gateway->>Model: Forward request
            Model-->>Gateway: Model response
            Gateway-->>Client: 200 Response
        end
    end

    note over Gateway,Model: In PoC cases, model execution is not required
```

---

## Threat Model

### Actors

- **Attacker**: Any unauthenticated internet user
- **Victim**: Google Cloud projects using Gemini / Generative Language APIs

### Assumptions

- Attacker has no Google account
- Attacker has no valid API key
- Attacker can generate API-key-shaped strings

### Capabilities

- Send arbitrary HTTPS requests
- Observe response codes and error bodies
- Automate requests at scale

### Observed Effects

- Validation of key existence
- Classification of project operational state
- Confirmation of project association

---

## Automation Scenario

```mermaid
sequenceDiagram
    participant Script as Enumeration Script
    participant Gateway as API Gateway

    loop For each generated key
        Script->>Gateway: POST ?key=<GENERATED_STRING>
        Gateway-->>Script: Differentiated error response
        Script->>Script: Classify key state
    end
```
```mermaid
flowchart TD
    A[Unauthenticated Request] --> B[Key Validation Layer]

    B -->|400| C[Non-existent Key]
    B -->|403| D[Real Project Identified]
    B -->|429| E[Active Project\nQuota Exceeded]
    B -->|200| F[Valid API Key]

    D --> D1[Extract Project ID]
    D --> D2[Learn Project State]

    E --> E1[Confirm Project Activity]
    E --> E2[Target for further abuse]

    F --> F1[Confirmed Credential]

    style B fill:#f6f6f6,stroke:#333
    style D fill:#ffe6e6
    style E fill:#fff2cc
    style F fill:#e6ffe6
```

The provided PoC demonstrates this behavior using parallel requests and response parsing.

---

## Security Discussion

This work does **not** assert that:

- Project IDs are secret
- API keys can be brute-forced feasibly
- Authentication is bypassed

Instead, it documents that:

- Pre-auth validation exists
- Error semantics are differentiated
- The API functions as a **classification oracle** for attacker-supplied input

The impact lies in **response behavior**, not in exploitation.

---

## Ethical Notice

- No private API keys were used
- No billing or quota abuse was performed
- All observations were made via standard API interaction

This repository is published for **educational and research purposes only**.

---

## License

MIT License

---

## Author

32BYTX **Independent security research**

