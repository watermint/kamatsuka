# Dropbox API Request Styles Guide

The Dropbox API utilizes three distinct request styles, each with its own protocol for sending and receiving data. This document explains how to properly use each style and how to interpret the `x-stone-style` extension in the OpenAPI specification.

## Request Styles Overview

### 1. RPC Style (`x-stone-style: rpc`)

**Description**: Both request and response bodies are JSON.

**Request Format**:
- HTTP Method: POST
- Content-Type: application/json
- Request Body: JSON object matching the schema referenced in the request body

**Response Format**:
- Content-Type: application/json
- Response Body: JSON object matching the schema referenced in the response

**Example Request**:
```sh
curl -X POST https://api.dropboxapi.com/2/users/get_current_account \
    --header "Authorization: Bearer <access-token>" \
    --header "Content-Type: application/json" \
    --data "null"
```

**When to Use**: For standard API operations that don't involve file transfers (e.g., getting metadata, listing files, managing settings).

---

### 2. Upload Style (`x-stone-style: upload`)

**Description**: Request has JSON parameters in the Dropbox-API-Arg header and binary data in the body. Response body is JSON.

**Request Format**:
- HTTP Method: POST
- Content-Type: application/octet-stream
- Dropbox-API-Arg: JSON string containing parameters
- Request Body: Binary data (file content)

**Response Format**:
- Content-Type: application/json
- Response Body: JSON object matching the schema referenced in the response

**Example Request**:
```sh
curl -X POST https://content.dropboxapi.com/2/files/upload \
    --header "Authorization: Bearer <access-token>" \
    --header "Dropbox-API-Arg: {\"path\": \"/Homework/math/Prime_Numbers.txt\",\"mode\": \"add\",\"autorename\": true,\"mute\": false,\"strict_conflict\": false}" \
    --header "Content-Type: application/octet-stream" \
    --data-binary @local_file.txt
```

**When to Use**: For uploading files or other binary content to Dropbox.

---

### 3. Download Style (`x-stone-style: download`)

**Description**: Request has JSON parameters in the Dropbox-API-Arg header. Response has JSON metadata in the Dropbox-API-Result header and binary data in the body.

**Request Format**:
- HTTP Method: POST (occasionally GET)
- Dropbox-API-Arg: JSON string containing parameters
- Request Body: Empty

**Response Format**:
- Content-Type: application/octet-stream
- Dropbox-API-Result: JSON string containing metadata
- Response Body: Binary data (file content)

**Example Request**:
```sh
curl -X POST https://content.dropboxapi.com/2/files/download \
    --header "Authorization: Bearer <access-token>" \
    --header "Dropbox-API-Arg: {\"path\": \"/Homework/math/Prime_Numbers.txt\"}" \
    --output local_file.txt
```

**When to Use**: For downloading files or other binary content from Dropbox.

---

## Server Selection

Endpoints are also marked with a `host` attribute that determines which server to use:

- **API Server** (`host: api`): `https://api.dropboxapi.com/2`
- **Content Server** (`host: content`): `https://content.dropboxapi.com/2`
- **Notify Server** (`host: notify`): `https://notify.dropboxapi.com/2`

Most upload and download style endpoints use the content server, while RPC-style endpoints typically use the API server.

## Additional Attributes

The OpenAPI specification includes other important Stone attributes as extensions:

- `x-stone-auth`: Authentication type (user, team, app, noauth)
- `x-stone-allow-app-folder`: Whether the endpoint can be used with app folder permissions
- `x-stone-select-admin-mode`: Admin mode selection for team endpoints
- `x-stone-preview`: Whether the endpoint is in preview/beta status
- `x-stone-cloud-doc-auth`: Whether the endpoint uses cloud docs authentication

These attributes provide important context for using the API correctly and should be considered when implementing API clients.
