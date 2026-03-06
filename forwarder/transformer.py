"""
Sentinel-Core Event Forwarder — Transformer

Converts raw Tetragon JSON events into the unified Sentinel JSON Schema.
"""

import uuid
from datetime import datetime, timezone
from typing import Any


def transform_event(raw: dict[str, Any]) -> dict[str, Any] | None:
    """
    Transform a raw Tetragon JSON event into the Sentinel unified schema.

    Returns None if the event type is not relevant (e.g., test events).
    """
    event_type = _detect_event_type(raw)
    if event_type is None:
        return None

    # Extract the inner event payload
    payload = raw.get(event_type, {})
    process_info = payload.get("process", {})
    parent_info = process_info.get("parent", {})
    pod_info = process_info.get("pod", {})

    # Build telemetry block
    telemetry = _build_telemetry(process_info, parent_info, pod_info, event_type, payload)

    sentinel_event: dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "timestamp": raw.get("time", datetime.now(timezone.utc).isoformat()),
        "source": "tetragon",
        "event_type": event_type,
        "node_name": raw.get("node_name", "unknown"),
        "telemetry": telemetry,
        # Downstream teammates fill these:
        "triage": None,
        "explanation": None,
        "remediation": None,
    }

    return sentinel_event


def _detect_event_type(raw: dict[str, Any]) -> str | None:
    """Identify the Tetragon event type from the raw JSON."""
    known_types = [
        "process_exec",
        "process_exit",
        "process_kprobe",
        "process_tracepoint",
        "process_loader",
    ]
    for t in known_types:
        if t in raw:
            return t
    return None


def _build_telemetry(
    process_info: dict[str, Any],
    parent_info: dict[str, Any],
    pod_info: dict[str, Any],
    event_type: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Build the telemetry block for a Sentinel event."""
    binary = process_info.get("binary", "unknown")
    arguments = process_info.get("arguments", "")
    args_list = arguments.split(" ") if isinstance(arguments, str) and arguments else []

    telemetry: dict[str, Any] = {
        "pid": process_info.get("pid", 0),
        "binary": binary,
        "args": args_list,
        "uid": process_info.get("uid", 0),
        "user": _uid_to_user(process_info.get("uid", 0)),
        "cwd": process_info.get("cwd", ""),
        "namespace": pod_info.get("namespace", ""),
        "pod": pod_info.get("name", ""),
        "container_id": process_info.get("docker", ""),
        "parent_binary": parent_info.get("binary", ""),
        "parent_pid": parent_info.get("pid", 0),
    }

    # For kprobe events, extract syscall-specific data
    if event_type == "process_kprobe":
        kprobe_data = _extract_kprobe_data(payload)
        telemetry["kprobe"] = kprobe_data

    return telemetry


def _extract_kprobe_data(payload: dict[str, Any]) -> dict[str, Any]:
    """Extract kprobe-specific data (syscall name, arguments, return value)."""
    function_name = payload.get("function_name", "unknown")
    policy_name = payload.get("policy_name", "unknown")
    action = payload.get("action", "KPROBE_ACTION_POST")

    # Extract syscall args
    args = []
    for arg in payload.get("args", []):
        arg_entry: dict[str, Any] = {}
        # Tetragon encodes args with type-specific keys
        for key in ["string_arg", "int_arg", "sock_arg", "skb_arg", "size_arg",
                     "bytes_arg", "file_arg", "truncated_bytes_arg"]:
            if key in arg:
                arg_entry[key] = arg[key]
        if arg_entry:
            args.append(arg_entry)

    return {
        "function": function_name,
        "policy": policy_name,
        "action": action,
        "args": args,
        "return_value": payload.get("return", {}).get("int_arg", None),
    }


def _uid_to_user(uid: int) -> str:
    """Map common UIDs to usernames (best-effort for demo)."""
    uid_map = {
        0: "root",
        33: "www-data",
        65534: "nobody",
        1000: "user",
    }
    return uid_map.get(uid, f"uid:{uid}")
