"""Compile the human doctrine into explicit Tethers runtime fixtures.

This module is deliberately small and explicit. It does **not** evaluate
authority. It translates the human-facing doctrine (``doctrine/*.json``) into
the exact Tethers runtime configuration, Tether sources, and capability
manifests that the Tethers Authority Gate consumes. The Gate and Tethers Core
remain the only semantic authority for ALLOW / ASK / DENY.

The mapping from a semantic action to a Tether capability is one-to-one, so the
human vocabulary in the doctrine is the same vocabulary Tethers decides on.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import doctrine_contract

SCHEMA = doctrine_contract.SCHEMA_ID
PROVIDER_IDENTITY = "permission-slip-fixture"
PROVIDER_DISPLAY = "Permission Slip Fixture"
CAPABILITY_VERSION = 1
CONTRACT_DIGEST = "CORE-CONTRACT-PERMISSION-SLIP-1"
PROGRAM_ID = "program.permission-slip.spike"
EVENT_NAME = "permission_slip.action_requested"
FIXTURE_FORMAT_VERSION = "0.1"

# The materialisation shape of every semantic capability. ``args`` maps an
# action argument name to its manifest JSON type. ``scope_arg`` names the
# argument a path_prefix scope is bound to. ``requires`` are the extra trusted
# facts a Tether condition needs.
CAPABILITY_SHAPES: dict[str, dict[str, Any]] = {
    "dev.tests.run": {"args": {"path": "string"}, "scope_arg": "path"},
    "project.files.edit": {"args": {"path": "string"}, "scope_arg": "path"},
    "git.push.feature": {
        "args": {
            "repository": "string",
            "remote_repository": "string",
            "destination_ref": "string",
            "push_effect": "string",
        },
        "scope_arg": "repository",
    },
    "git.merge.accepted": {
        "args": {"repository": "string"},
        "scope_arg": "repository",
    },
    "data.external_upload.repository": {"args": {"destination": "string"}},
    "data.external_upload.secret": {
        "args": {"destination": "string", "secret_kind": "string"},
    },
    "git.history.rewrite": {
        "args": {
            "repository": "string",
            "remote_repository": "string",
            "destination_ref": "string",
            "push_effect": "string",
        },
        "scope_arg": "repository",
    },
    "money.real_charge": {"args": {"amount_cents": "integer", "vendor": "string"}},
    "money.promotional_credit.use": {
        "args": {"amount_cents": "integer", "vendor": "string", "path": "string"},
        "scope_arg": "path",
    },
    "identity.public_publish": {"args": {"channel": "string"}},
}

OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {"ok": {"type": "boolean"}},
    "required": ["ok"],
    "additionalProperties": False,
}


class DoctrineError(ValueError):
    """Raised when a doctrine is valid but this compiler cannot materialise it."""


def _unsupported(detail: str) -> str:
    # Structural validity and implementation support are different questions.
    # A doctrine that satisfies Doctrine Contract v1 but has no materialisation
    # shape here is not a malformed document -- it is outside this compiler's
    # support, and the message says so.
    return f"valid doctrine contract, unsupported by this compiler: {detail}"


def load_doctrine(path: str | Path) -> dict[str, Any]:
    """Read a doctrine document and return it only if Contract v1 accepts it.

    Parsing, duplicate-key detection and validation all belong to the
    contract; this function owns no structural rules of its own.
    """
    text = Path(path).read_text(encoding="utf-8")
    return doctrine_contract.parse_doctrine_json(text)


def slug(action: str) -> str:
    return action.replace(".", "-").replace("_", "-").lower()


def _jcs_bytes(value: Any) -> bytes:
    # RFC 8785 for the value domain used by manifests (strings, integers,
    # booleans, null, arrays, objects; no floats). Matches Tethers'
    # serde_json_canonicalizer. The encoder itself is shared with Doctrine
    # Contract v1 so the two digest domains can never disagree.
    return doctrine_contract.canonical_json_bytes(value)


def manifest_digest(manifest: dict[str, Any]) -> str:
    filtered = {
        key: value
        for key, value in manifest.items()
        if key not in ("digest", "title", "description")
    }
    return "sha256:" + hashlib.sha256(_jcs_bytes(filtered)).hexdigest()


def _scope_argument_value(scope_arg: str, action: str) -> str:
    # A deterministic, in-scope resource path for capabilities whose scope is
    # path_prefix but whose real consequence is not itself a file path.
    return f"runtime/spike-workspace/{slug(action)}/{scope_arg}"


def _build_manifest(capability: dict[str, Any]) -> dict[str, Any]:
    action = capability["action"]
    shape = CAPABILITY_SHAPES.get(action)
    if shape is None:
        raise DoctrineError(_unsupported(f"no materialisation shape for capability {action!r}"))

    scope = capability["scope"]
    scope_kind = scope["kind"]
    if capability["standing"] == "allow" and scope_kind != "path_prefix":
        raise DoctrineError(
            _unsupported(
                f"capability {action!r} stands allow and therefore needs a "
                "path_prefix scope"
            )
        )
    if scope_kind == "path_prefix":
        permission_scope: Any = {
            "kind": "path_prefix",
            "allowed_prefixes": list(scope["prefixes"]),
        }
    elif scope_kind == "unrestricted":
        permission_scope = None
    else:
        raise DoctrineError(_unsupported(f"scope kind {scope_kind!r} for {action!r}"))

    per_call_required = permission_scope is None
    manifest: dict[str, Any] = {
        "manifest_format_version": "1.0",
        "capability_name": action,
        "capability_version": CAPABILITY_VERSION,
        "title": f"Permission Slip fixture: {action}",
        "description": capability["purpose"],
        "input_schema": {
            "type": "object",
            "properties": {
                name: {"type": json_type} for name, json_type in shape["args"].items()
            },
            "required": list(shape["args"].keys()),
            "additionalProperties": False,
        },
        "output_schema": OUTPUT_SCHEMA,
        "effects": list(capability["effects"]),
        "permission_scope": permission_scope,
        "reversibility": capability["reversibility"],
        "determinism": "deterministic",
        "idempotency": {
            "mechanism": "argument_key",
            "argument_name": "idempotency_key",
            "key_source": "evaluation_id/action_id",
        },
        "confirmation_policy": {
            "standing_permitted": capability["standing"] == "allow",
            "per_call_required": per_call_required,
        },
        "timeout_ms": 5000,
        "retry_policy": {
            "max_retries": 0,
            "backoff_ms": 500,
            "allowed_on": ["outcome_unknown"],
            "requires_idempotency_proof": False,
        },
        "provider": {
            "identity": PROVIDER_IDENTITY,
            "display_name": PROVIDER_DISPLAY,
            "identity_source": "host_configuration",
            "description": "Test-only deterministic stdio provider.",
        },
        "binding": {
            "kind": "mcp",
            "server_name": PROVIDER_IDENTITY,
            "tool_name": f"fixture_{slug(action).replace('-', '_')}",
            "adapter": None,
        },
    }
    manifest["digest"] = manifest_digest(manifest)
    return manifest


def _build_tether(capability: dict[str, Any]) -> str:
    action = capability["action"]
    shape = CAPABILITY_SHAPES[action]
    requires = list(capability.get("requires", []))

    condition_lines = ["    actor.trusted is true"]
    for fact in requires:
        condition_lines.append(f"    and {fact} is true")

    argument_lines = [
        f"        {name}: anchor.{name}" for name in shape["args"].keys()
    ]

    return "\n".join(
        [
            f'tether "permission slip {action}"',
            "",
            "anchor",
            f"    {EVENT_NAME}",
            "",
            "when",
            *condition_lines,
            "",
            "do",
            f"    {action}",
            *argument_lines,
            "",
        ]
    )


@dataclass
class CompiledCapability:
    action: str
    tether_id: str
    tether_version: str
    arguments: list[str]
    scope_arg: str | None
    requires: list[str]
    standing: str
    reversibility: str

    def in_scope_argument(self) -> str | None:
        return self.scope_arg


@dataclass
class CompiledFixture:
    target: Path
    config_path: Path
    capabilities: dict[str, CompiledCapability] = field(default_factory=dict)

    def capability(self, action: str) -> CompiledCapability:
        return self.capabilities[action]


def _input_fact(fact: str) -> dict[str, Any]:
    json_type = "boolean"
    description = {
        "actor.trusted": "actor is supplied by the trusted harness profile",
        "actor.merge_authority": "trusted actor holds accepted-work merge authority",
        "promo.within_bound": (
            "trusted charge uses the configured promotional provider and is within "
            "the configured per-call promotional limit"
        ),
    }.get(fact, "trusted harness fact")
    return {
        "source_name": fact,
        "fact_id": "fact." + fact.replace(".", "_"),
        "host_snapshot_key": fact,
        "scalar_type": json_type,
        "schema_description": description,
    }


def compile_doctrine(doctrine: dict[str, Any], target: str | Path) -> CompiledFixture:
    # A valid contract is a precondition, not an assumption: nothing is
    # written until the document has passed Doctrine Contract v1.
    doctrine_contract.validate_doctrine(doctrine)
    target = Path(target)
    (target / "tethers").mkdir(parents=True, exist_ok=True)
    (target / "manifests").mkdir(parents=True, exist_ok=True)

    capabilities = doctrine["capabilities"]

    compiled = CompiledFixture(target=target, config_path=target / "runtime.json")
    tethers_config: list[dict[str, Any]] = []
    requirements: list[dict[str, Any]] = []
    provider_capabilities: list[dict[str, Any]] = []
    policy_rules: list[dict[str, Any]] = []

    for capability in capabilities:
        action = capability["action"]
        shape = CAPABILITY_SHAPES.get(action)
        if shape is None:
            raise DoctrineError(_unsupported(f"no materialisation shape for capability {action!r}"))
        manifest = _build_manifest(capability)
        name = f"{slug(action)}.json"
        (target / "manifests" / name).write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n"
        )

        tether_slug = slug(action)
        (target / "tethers" / f"{tether_slug}.tether").write_text(
            _build_tether(capability), encoding="utf-8", newline="\n"
        )

        requires = list(capability.get("requires", []))
        facts = ["actor.trusted", *requires]
        tether_id = f"ps-{tether_slug}"
        tethers_config.append(
            {
                "id": tether_id,
                "version": "1",
                "source_path": f"tethers/{tether_slug}.tether",
                "core_environment": {
                    "program_id": PROGRAM_ID,
                    "core_version": "1",
                    "capabilities": [
                        {
                            "source_name": action,
                            "capability_id": f"cap.semantic.{tether_slug}",
                            "contract_digest": CONTRACT_DIGEST,
                            "runtime_name": action,
                        }
                    ],
                    "input_facts": [_input_fact(fact) for fact in dict.fromkeys(facts)],
                },
            }
        )

        requirements.append(
            {
                "name": action,
                "version": CAPABILITY_VERSION,
                "reason": capability["purpose"],
            }
        )

        provider_capability: dict[str, Any] = {
            "name": action,
            "version": CAPABILITY_VERSION,
            "manifest_path": f"manifests/{name}",
            "pinned_digest": manifest["digest"],
        }
        scope_arg = shape.get("scope_arg")
        if manifest["permission_scope"] is not None:
            provider_capability["scope_binding"] = {
                "kind": "path_prefix",
                "argument_json_pointer": f"/{scope_arg}",
            }
        provider_capabilities.append(provider_capability)

        policy_rules.append(
            {
                "name": action,
                "version": CAPABILITY_VERSION,
                "decision": capability["standing"],
            }
        )

        compiled.capabilities[action] = CompiledCapability(
            action=action,
            tether_id=tether_id,
            tether_version="1",
            arguments=list(shape["args"].keys()),
            scope_arg=scope_arg,
            requires=requires,
            standing=capability["standing"],
            reversibility=capability["reversibility"],
        )

    runtime = {
        "format_version": FIXTURE_FORMAT_VERSION,
        "tether_set": {
            "id": "permission-slip.spike",
            "version": "1",
            "tethers": tethers_config,
            "capability_requirements": requirements,
        },
        "providers": [
            {
                "id": PROVIDER_IDENTITY,
                "display_name": PROVIDER_DISPLAY,
                "transport": {
                    "kind": "stdio",
                    "command": "pwsh.exe",
                    "args": [
                        "-NoProfile",
                        "-File",
                        "providers/fixture.ps1",
                    ],
                    "protocol_version": "2025-11-25",
                },
                "capabilities": provider_capabilities,
            }
        ],
        "policy": {"default": "deny", "rules": policy_rules},
    }
    compiled.config_path.write_text(
        json.dumps(runtime, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    return compiled


def in_scope_argument(action: str) -> str:
    """The deterministic in-scope path for a path-scoped capability."""
    shape = CAPABILITY_SHAPES[action]
    return _scope_argument_value(shape["scope_arg"], action)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Compile Permission Slip doctrine into a Tethers fixture.")
    parser.add_argument("doctrine", help="path to doctrine JSON")
    parser.add_argument("target", help="output fixture directory")
    args = parser.parse_args(argv)
    doctrine = load_doctrine(args.doctrine)
    fixture = compile_doctrine(doctrine, args.target)
    print(f"wrote {fixture.config_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
