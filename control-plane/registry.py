"""Project the registered gateway operations into routing and public contracts."""

import argparse
import hashlib
import json
import re
from pathlib import Path

IDENTIFIER = re.compile(r"[A-Za-z0-9._:-]{1,128}")
PATH = re.compile(r"/(?:[A-Za-z0-9._~:-]+|\{id\})?(?:/(?:[A-Za-z0-9._~:-]+|\{id\}))*/*")
METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
POLICY_FIELDS = {
    "method",
    "path",
    "audience",
    "operation",
    "resource",
    "requires_audit_receipt",
    "vault_provider",
    "accept_delegation",
    "delegate_to",
}
CONTRACT_FIELDS = {
    "summary",
    "slo",
    "protocol",
    "metering_units",
    "quota_dimensions",
    "parameters",
    "request_body",
    "responses",
}
MODEL_USAGE = {
    "maas.chat.create",
    "maas.completions.create",
    "maas.embeddings.create",
    "maas.batches.create",
}
QUOTA_DIMENSIONS = ["tenant", "project", "env"]


def identifier(value):
    return isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None


def json_bytes(value):
    return (
        json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode()


def granted_resources(route):
    resource = route["resource"]
    choices = {"urn:plat:maas:model:" + alias for alias in resource.get("targets", {})}
    if "urn" in resource:
        choices.add(resource["urn"])
    if resource["kind"] == "rpc":
        choices.update(resource["policy"]["methods"].values())
        choices.update(
            tool["urn"] for tool in resource["policy"].get("tools", {}).values()
        )
    return choices


def protocol_for(resource):
    kind = resource["kind"]
    if kind == "rpc":
        return resource["policy"]["protocol"]
    if kind == "mcp-session":
        return "mcp"
    if kind in {"model", "model-list", "maas-asset"}:
        return "openai"
    return "rest"


def metering_for(route):
    units = ["requests", "egress_bytes"]
    if (
        route["audience"] == "urn:plat:maas:kstack"
        and route["operation"] in MODEL_USAGE
    ):
        units.extend(("prompt_tokens", "completion_tokens"))
    return units


def method_name(operation):
    words = [word for word in re.split(r"[._:-]+", operation.lower()) if word]
    if not words:
        raise ValueError("registry operation needs an alphanumeric SDK name")
    # Retain segment boundaries in the Go name even when the following segment starts with a number.
    return "_".join(words), "".join(
        word.title() if word[0].isalpha() else "_" + word for word in words
    )


def path_parameter(route):
    if "{id}" not in route["path"]:
        return None
    if route["resource"]["kind"] != "maas-asset":
        raise ValueError("registry path template requires a MaaS asset route")
    urn = route["resource"].get("urn")
    if urn == "urn:plat:maas:files":
        return "file-"
    if urn == "urn:plat:maas:batches":
        return "batch_"
    raise ValueError("registry path template requires a MaaS file or batch resource")


class Registry:
    def __init__(self, routes):
        if not isinstance(routes, dict) or not routes:
            raise ValueError("configure at least one registered route")
        self.routes = {}
        self.grants = {}
        self.bindings = {}
        self.contracts = {}
        for name, definition in sorted(routes.items()):
            if (
                not identifier(name)
                or not isinstance(definition, dict)
                or definition.keys() - (POLICY_FIELDS | {"routing", "contract"})
            ):
                raise ValueError("invalid registered route fields")
            route = {
                key: value for key, value in definition.items() if key in POLICY_FIELDS
            }
            operation = route["operation"]
            if not identifier(operation) or operation in self.grants:
                raise ValueError("registry operation IDs must be unique identifiers")
            self.grants[operation] = granted_resources(route)
            self.routes[name] = route
            if "routing" in definition:
                self.bindings[name] = definition["routing"]
            self.contracts[name] = definition.get("contract", {})
        if self.bindings and self.bindings.keys() != self.routes.keys():
            raise ValueError("registry routing requires bindings for every route")
        self.routers = self.render_routers()
        if self.routers:
            self.open_api()

    def render_routers(self):
        blocks = []
        for name, binding in self.bindings.items():
            if (
                not isinstance(binding, dict)
                or set(binding) != {"service", "entrypoints"}
                or not identifier(binding["service"])
                or not isinstance(binding["entrypoints"], list)
                or not binding["entrypoints"]
                or not all(map(identifier, binding["entrypoints"]))
                or len(set(binding["entrypoints"])) != len(binding["entrypoints"])
            ):
                raise ValueError(
                    "registry routing requires a service and unique entrypoints"
                )
            route = self.routes[name]
            validate_target(route)
            matcher = "PathTemplate" if path_parameter(route) else "Path"
            rule = f"{matcher}(`{route['path']}`) && Method(`{route['method']}`)"
            blocks.append(
                f"routers {json.dumps(name)} {{\n"
                f"  rule = {json.dumps(rule)}\n"
                f"  service = {json.dumps(binding['service'])}\n"
                f"  entrypoints = {json.dumps(binding['entrypoints'])}\n"
                "}\n"
            )
        return "\n".join(blocks)

    def open_api(self):
        paths = {}
        sdk_names = (set(), set())
        for name, route in self.routes.items():
            validate_target(route)
            path, method = route["path"], route["method"].lower()
            item = paths.setdefault(path, {})
            names = method_name(route["operation"])
            if method in item or any(
                value in used for value, used in zip(names, sdk_names)
            ):
                raise ValueError(
                    "registry HTTP targets and SDK operation names must be unique"
                )
            for value, used in zip(names, sdk_names):
                used.add(value)
            item[method] = self.describe(name, route)
        return {
            "openapi": "3.1.0",
            "info": {"title": "kgateway registered API", "version": "1.0.0"},
            "paths": paths,
            "components": {
                "securitySchemes": {
                    "KenseKey": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "Kense Key",
                    },
                    "KenseDelegation": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "Kense delegation ticket",
                    },
                }
            },
        }

    def describe(self, name, route):
        contract = self.contracts[name]
        if not isinstance(contract, dict) or contract.keys() - CONTRACT_FIELDS:
            raise ValueError("invalid public route contract fields")
        protocol, units = protocol_for(route["resource"]), metering_for(route)
        if protocol not in {"rest", "openai", "mcp", "a2a"}:
            raise ValueError("unknown registered protocol")
        expected = {
            "protocol": protocol,
            "metering_units": units,
            "quota_dimensions": QUOTA_DIMENSIONS,
        }
        if any(contract.get(key, value) != value for key, value in expected.items()):
            raise ValueError(
                "route contract disagrees with enforced protocol, metering or quota dimensions"
            )
        if name in self.bindings and not {"slo", *expected} <= contract.keys():
            raise ValueError(
                "generated routes require protocol, metering, quota dimensions and an SLO"
            )
        metadata = {
            "protocol": protocol,
            "resourceUrns": sorted(self.grants[route["operation"]]),
            "meteringUnits": units,
            "quotaDimensions": QUOTA_DIMENSIONS,
            "audit": "receipt" if route.get("requires_audit_receipt") else "async",
        }
        if "slo" in contract:
            slo = contract["slo"]
            if (
                not isinstance(slo, dict)
                or set(slo) != {"availability", "p99_ms"}
                or type(slo["availability"]) not in {float, int}
                or not 0 < slo["availability"] <= 1
                or type(slo["p99_ms"]) is not int
                or slo["p99_ms"] <= 0
            ):
                raise ValueError(
                    "registry SLO requires an availability fraction and positive p99 milliseconds"
                )
            metadata["slo"] = slo
        resource = route["resource"]
        if resource["kind"] == "rpc":
            policy = resource["policy"]
            metadata["rpcMethods"] = policy["methods"]
            if "tools" in policy:
                metadata["tools"] = policy["tools"]
        if "batch_max_requests" in resource:
            metadata["reservedRequests"] = resource["batch_max_requests"]
        parameters = contract.get("parameters", [])
        if not isinstance(parameters, list) or any(
            not isinstance(param, dict)
            or param.get("in") not in {"query", "header", "cookie"}
            for param in parameters
        ):
            raise ValueError(
                "contract parameters must declare query, header or cookie input"
            )
        parameters = parameters.copy()
        if prefix := path_parameter(route):
            parameters.append(
                {
                    "name": "id",
                    "in": "path",
                    "required": True,
                    "schema": {
                        "type": "string",
                        "pattern": "^" + prefix + "[0-9a-f]{24}$",
                    },
                }
            )
        responses = {
            "401": {"description": "Invalid or expired Kense credential"},
            "403": {"description": "Credential scope does not allow the operation"},
            "429": {"description": "Request allowance exhausted"},
            "503": {"description": "Admission or upstream unavailable"},
        }
        declared = contract.get(
            "responses", {"2XX": {"description": "Registered service response"}}
        )
        if (
            not isinstance(declared, dict)
            or not declared
            or any(not isinstance(value, dict) for value in declared.values())
        ):
            raise ValueError("contract responses require a non-empty mapping")
        responses.update(declared)
        security = [{"KenseKey": []}]
        if route.get("accept_delegation"):
            security.append({"KenseDelegation": []})
        result = {
            "operationId": route["operation"],
            "responses": responses,
            "security": security,
            "x-kense": metadata,
        }
        if parameters:
            result["parameters"] = parameters
        for source, target in (("summary", "summary"), ("request_body", "requestBody")):
            if source in contract:
                result[target] = contract[source]
        if (
            "summary" in result
            and not isinstance(result["summary"], str)
            or "requestBody" in result
            and not isinstance(result["requestBody"], dict)
        ):
            raise ValueError("contract summary and request body have invalid types")
        return result

    def write_artifacts(self, output):
        spec = json_bytes(self.open_api())
        digest = hashlib.sha256(spec).hexdigest()
        templates = Path(__file__).with_name("sdk")
        files = {"openapi.json": spec}
        for language in ("rs", "go"):
            template = (templates / f"client.{language}.in").read_text(encoding="utf-8")
            methods = sdk_methods(self.routes, language)
            files[f"client.{language}"] = (
                template.replace("@CONTRACT_SHA256@", digest)
                .replace("@METHODS@", methods)
                .encode()
            )
        if self.routers:
            files["routers.acl"] = self.routers.encode()
        manifest = json_bytes(
            {
                "schema": "kgateway.registry-artifacts.v1",
                "sha256": {
                    name: hashlib.sha256(content).hexdigest()
                    for name, content in files.items()
                },
            }
        )
        output.mkdir(parents=True, exist_ok=True)
        for name, content in files.items():
            (output / name).write_bytes(content)
        (output / "manifest.json").write_bytes(manifest)


def validate_target(route):
    path = route["path"]
    if (
        route["method"] not in METHODS
        or not isinstance(path, str)
        or len(path) > 256
        or not PATH.fullmatch(path)
        or "//" in path
        or {".", ".."}.intersection(path.split("/"))
        or path.count("{id}") > 1
    ):
        raise ValueError(
            "registry route requires an exact HTTP method and canonical absolute path"
        )


def sdk_methods(routes, language):
    methods = []
    for route in sorted(routes.values(), key=lambda item: item["operation"]):
        rust, go = method_name(route["operation"])
        path, verb, prefix = route["path"], route["method"], path_parameter(route)
        if language == "rs":
            parameter = ", id: &str" if prefix else ""
            id_arg = f'Some((id, "{prefix}"))' if prefix else "None"
            methods.append(f"""    pub fn request_{rust}(&self{parameter}) -> Result<reqwest::RequestBuilder> {{
        self.request(reqwest::Method::{verb}, "{path}", {id_arg})
    }}""")
        else:
            parameter = ", id string" if prefix else ""
            id_args = f'id, "{prefix}"' if prefix else '"", ""'
            methods.append(f"""func (client *Client) Request{go}(ctx context.Context{parameter}, body io.Reader) (*http.Request, error) {{
\treturn client.request(ctx, http.Method{verb.title()}, "{path}", {id_args}, body)
}}""")
    return "\n\n".join(methods)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        Registry(
            json.loads(args.config.read_text(encoding="utf-8"))["routes"]
        ).write_artifacts(args.output)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"registry: {error}\n")


if __name__ == "__main__":
    main()
