"""
Developer Experience (DX) & GraphQL Federation v2 Module for APIHub-Pro v3.0.
Provides:
- Multi-Language Client SDK Generator (Python, TypeScript, Go, cURL)
- Interactive Webhook Simulator with HMAC verification diagnostics
- Apollo GraphQL Federation v2 Gateway Resolver (`_service { sdl }`, `_entities`, unified queries)
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from apihub.ai_gateway import ai_gateway
from apihub.analytics import analytics_engine
from apihub.gateway import gateway_manager
from apihub.marketplace import marketplace_manager
from apihub.resilience import resilience_engine
from apihub.webhooks import WebhookManager


FEDERATED_GRAPHQL_SDL = """
extend schema @link(url: "https://specs.apollo.dev/federation/v2.3", import: ["@key", "@shareable"])

type Project @key(fields: "id") {
  id: ID!
  name: String!
  slug: String!
  plan_tier: String!
  rpm_limit: Int!
}

type GatewayEndpoint @key(fields: "id") {
  id: ID!
  name: String!
  version: String!
  method: String!
  path: String!
  full_gateway_path: String!
  lifecycle_state: String!
  timeout_ms: Int!
}

type AIModel @key(fields: "id") {
  id: ID!
  provider: String!
  model: String!
  input_cost_per_1k_usd: Float!
  output_cost_per_1k_usd: Float!
}

type Query {
  projects: [Project!]!
  endpoints(version: String): [GatewayEndpoint!]!
  aiModels: [AIModel!]!
  analyticsSummary: JSON!
  marketplaceListings: JSON!
  serviceRegistry: JSON!
  _service: _Service!
}

type _Service {
  sdl: String!
}
""".strip()


class DeveloperExperienceEngine:
    """Provides multi-language SDK generation, webhook simulation, and GraphQL Federation v2 resolution."""

    @staticmethod
    def generate_sdk(
        endpoint_path: str,
        method: str = "GET",
        version: str = "v2",
        language: str = "python",
        base_url: str = "http://localhost:8000",
        api_key_placeholder: str = "ahp_live_YOUR_API_KEY",
    ) -> Dict[str, Any]:
        norm_path = "/" + endpoint_path.strip().lstrip("/")
        full_url = f"{base_url.rstrip('/')}/gateway/{version.strip('/')}{norm_path}"
        m = method.upper()
        lang = language.lower()

        if lang == "python":
            lines = [
                "import httpx",
                "",
                "class APIHubProClient:",
                f'    def __init__(self, api_key: str = "{api_key_placeholder}", base_url: str = "{base_url}"):',
                "        self.api_key = api_key",
                '        self.base_url = base_url.rstrip("/")',
                "",
                "    def call_endpoint(self, payload: dict | None = None) -> dict:",
                f'        url = f"{{self.base_url}}/gateway/{version}{norm_path}"',
                '        headers = {"X-API-Key": self.api_key, "Content-Type": "application/json"}',
                "        with httpx.Client(timeout=10.0) as client:",
                f'            response = client.request("{m}", url, headers=headers, json=payload)',
                "            response.raise_for_status()",
                "            return response.json()",
            ]
            code = "\n".join(lines)
        elif lang in ("typescript", "ts", "javascript", "js"):
            lines = [
                "export class APIHubProClient {",
                f'  constructor(private readonly apiKey: string = "{api_key_placeholder}", private readonly baseUrl: string = "{base_url}") {{}}',
                "",
                "  async callEndpoint(payload?: Record<string, unknown>): Promise<unknown> {",
                f'    const response = await fetch(`${{this.baseUrl}}/gateway/{version}{norm_path}`, {{',
                f'      method: "{m}",',
                '      headers: { "X-API-Key": self.apiKey, "Content-Type": "application/json" },',
                "      body: payload ? JSON.stringify(payload) : undefined,",
                "    });",
                "    if (!response.ok) throw new Error(`APIHub error: ${response.status}`);",
                "    return response.json();",
                "  }",
                "}",
            ]
            code = "\n".join(lines)
        elif lang in ("go", "golang"):
            lines = [
                "package apihub",
                "",
                'import ("fmt"; "io"; "net/http")',
                "",
                "func CallEndpoint(apiKey string) ([]byte, error) {",
                f'\treq, err := http.NewRequest("{m}", "{full_url}", nil)',
                "\tif err != nil { return nil, err }",
                '\treq.Header.Set("X-API-Key", apiKey)',
                "\tresp, err := http.DefaultClient.Do(req)",
                "\tif err != nil { return nil, err }",
                "\tdefer resp.Body.Close()",
                '\tif resp.StatusCode >= 400 { return nil, fmt.Errorf("status %d", resp.StatusCode) }',
                "\treturn io.ReadAll(resp.Body)",
                "}",
            ]
            code = "\n".join(lines)
        else:
            code = (
                f'curl -X {m} "{full_url}" \\\n'
                f'  -H "X-API-Key: {api_key_placeholder}" \\\n'
                f'  -H "Content-Type: application/json"'
            )

        return {
            "language": lang,
            "method": m,
            "full_url": full_url,
            "sdk_code": code,
        }

    @staticmethod
    def simulate_webhook(
        event_type: str,
        payload: Dict[str, Any],
        secret: str = "whsec_simulator_secret",
        tamper_payload: bool = False,
    ) -> Dict[str, Any]:
        ts = int(time.time())
        raw_json = json.dumps(
            {"event": event_type, "timestamp": ts, "data": payload}, sort_keys=True
        )
        signature = WebhookManager.sign_payload(secret, raw_json, ts)
        received_body = raw_json + ("_tampered" if tamper_payload else "")
        verified = WebhookManager.verify_signature(secret, received_body, signature)
        return {
            "simulator": "apihub-pro-webhook-simulator",
            "event_type": event_type,
            "headers_sent": {
                "Content-Type": "application/json",
                "X-APIHub-Event": event_type,
                "X-APIHub-Signature-256": signature,
            },
            "payload_sent": json.loads(raw_json),
            "tamper_simulated": tamper_payload,
            "signature_verified": verified,
        }

    @staticmethod
    def execute_graphql_query(
        query: str, variables: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        q = query.strip()
        data: Dict[str, Any] = {}

        if "_service" in q:
            data["_service"] = {"sdl": FEDERATED_GRAPHQL_SDL}
        if "projects" in q:
            data["projects"] = marketplace_manager.list_projects()
        if "endpoints" in q:
            ver = (variables or {}).get("version")
            data["endpoints"] = gateway_manager.list_endpoints(version=ver)
        if "aiModels" in q:
            data["aiModels"] = ai_gateway.list_supported_models()
        if "analyticsSummary" in q:
            data["analyticsSummary"] = analytics_engine.get_summary()
        if "marketplaceListings" in q:
            data["marketplaceListings"] = marketplace_manager.list_marketplace_listings()
        if "serviceRegistry" in q:
            data["serviceRegistry"] = resilience_engine.list_services()
        if "_entities" in q:
            reps: List[Dict[str, Any]] = (variables or {}).get("representations", [])
            entities = []
            for rep in reps:
                tname = rep.get("__typename")
                if tname == "Project" and rep.get("id"):
                    entities.append(marketplace_manager.get_project(rep["id"]))
                elif tname == "GatewayEndpoint" and rep.get("id"):
                    entities.append(gateway_manager.get_endpoint(rep["id"]))
            data["_entities"] = entities

        if not data:
            data["serviceInfo"] = {
                "name": "apihub-pro-graphql-federation",
                "version": "3.0.0",
                "federation_version": "v2.3",
            }
        return {"data": data}


dx_engine = DeveloperExperienceEngine()
