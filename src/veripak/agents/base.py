"""Lightweight agent runner for veripak v2.

Provides tool registration, multi-turn conversation loop with model_caller,
turn budget enforcement, and HITL flag collection. Not a framework — just
a thin loop around litellm tool calling.
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .. import model_caller

logger = logging.getLogger(__name__)

# Maximum total tool calls across all turns (safety net against runaway agents)
_DEFAULT_MAX_TOOL_CALLS = 15


@dataclass
class ToolDef:
    """A tool available to an agent."""
    name: str
    description: str
    parameters: dict  # JSON Schema for the function parameters
    fn: Callable[..., Any]


@dataclass
class HITLFlag:
    """Human-in-the-loop flag raised by an agent."""
    field_name: str
    agent: str
    reason: str
    blocked_url: Optional[str] = None


@dataclass
class AgentResult:
    """Result of running an agent."""
    answer: dict
    hitl_flags: list[HITLFlag] = field(default_factory=list)
    turns_used: int = 0
    tool_calls_used: int = 0
    error: Optional[str] = None


def _tool_schemas(tools: list[ToolDef]) -> list[dict]:
    """Convert ToolDefs to the OpenAI-compatible tool schema format."""
    return [
        {
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description,
                "parameters": t.parameters,
            },
        }
        for t in tools
    ]


def _dispatch_tool_call(
    tool_call: Any,
    registry: dict[str, ToolDef],
    hitl_flags: list[HITLFlag],
    agent_name: str,
) -> dict:
    """Execute a single tool call and return the result as a message dict."""
    fn_name = tool_call.function.name
    call_id = tool_call.id

    # Parse arguments
    try:
        args = json.loads(tool_call.function.arguments or "{}")
    except json.JSONDecodeError:
        args = {}

    # Special handling for flag_hitl — collect and acknowledge
    if fn_name == "flag_hitl":
        flag = HITLFlag(
            field_name=args.get("field", "unknown"),
            agent=agent_name,
            reason=args.get("reason", ""),
            blocked_url=args.get("blocked_url"),
        )
        hitl_flags.append(flag)
        result_str = json.dumps({"status": "flagged", "field": flag.field_name})
        return {
            "role": "tool",
            "tool_call_id": call_id,
            "content": result_str,
        }

    # Look up and execute the tool
    tool_def = registry.get(fn_name)
    if not tool_def:
        return {
            "role": "tool",
            "tool_call_id": call_id,
            "content": json.dumps({"error": f"Unknown tool: {fn_name}"}),
        }

    try:
        result = tool_def.fn(**args)
        result_str = json.dumps(result, default=str) if not isinstance(result, str) else result
    except Exception as exc:
        logger.warning("Tool %s raised %s: %s", fn_name, type(exc).__name__, exc)
        result_str = json.dumps({"error": f"{type(exc).__name__}: {exc}"})

    return {
        "role": "tool",
        "tool_call_id": call_id,
        "content": result_str,
    }


def _parse_final_answer(content: str) -> dict:
    """Extract JSON from the agent's final text response."""
    text = content.strip()

    # Strip markdown code fences if present
    if text.startswith("```"):
        text = text.split("\n", 1)[-1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try to find JSON object within the text
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                pass
        return {"_raw_response": content}


# The flag_hitl tool schema — always available to every agent
_FLAG_HITL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "flag_hitl",
        "description": (
            "Flag a field for human review when data sources are inaccessible, "
            "signals are contradictory, or confidence is low."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "field": {
                    "type": "string",
                    "description": "The output field being flagged (e.g. 'eol', 'cve_count')",
                },
                "reason": {
                    "type": "string",
                    "description": "Why human review is needed",
                },
                "blocked_url": {
                    "type": "string",
                    "description": "URL that could not be accessed, if applicable",
                },
            },
            "required": ["field", "reason"],
        },
    },
}


def _extract_on_budget(
    messages: list,
    agent_name: str,
    hitl_flags: list[HITLFlag],
    turns_used: int,
    tool_calls_used: int,
    reason: str,
) -> AgentResult:
    """Give the agent one final turn without tools to produce its answer.

    Called when the tool-call or turn budget is exhausted. Instead of
    discarding all intermediate results, we ask the model to synthesize
    what it has gathered so far into the expected JSON format.
    """
    messages.append({
        "role": "user",
        "content": (
            f"Your {reason} budget is exhausted. You MUST provide your final JSON answer "
            "now based on all the information you have gathered so far. "
            "Do not attempt to call any more tools — just output the JSON."
        ),
    })

    try:
        response = model_caller.call_model_chat(messages, tools=None)
        content = getattr(response, "content", "") or ""
        answer = _parse_final_answer(content)
    except Exception as exc:
        logger.error("Agent %s: extraction turn failed: %s", agent_name, exc)
        answer = {}

    extraction_ok = answer and "_raw_response" not in answer
    error_msg = (
        f"{reason.capitalize()} budget exhausted, answer extracted from partial results"
        if extraction_ok
        else f"{reason.capitalize()} budget exhausted and extraction failed"
    )

    return AgentResult(
        answer=answer,
        hitl_flags=hitl_flags,
        turns_used=turns_used + 1,
        tool_calls_used=tool_calls_used,
        error=error_msg,
    )


def run_agent(
    system_prompt: str,
    user_prompt: str,
    tools: list[ToolDef],
    agent_name: str = "agent",
    max_turns: int = 8,
    max_tool_calls: int = _DEFAULT_MAX_TOOL_CALLS,
) -> AgentResult:
    """Run a multi-turn agent loop.

    The agent receives a system prompt, an initial user message, and a set of
    tools. It can call tools and reason over results for up to max_turns
    conversation rounds. The loop ends when the agent produces a response
    without tool calls (the final answer) or budgets are exhausted.

    When a budget is exhausted, the agent gets one final extraction turn
    (without tools) to synthesize its findings into the expected JSON format.

    Returns an AgentResult with the parsed answer, HITL flags, and usage stats.
    """
    registry = {t.name: t for t in tools}
    schemas = _tool_schemas(tools) + [_FLAG_HITL_SCHEMA]
    hitl_flags: list[HITLFlag] = []

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    total_tool_calls = 0

    for turn in range(max_turns):
        try:
            response = model_caller.call_model_chat(messages, tools=schemas)
        except Exception as exc:
            logger.error("Agent %s: model call failed on turn %d: %s", agent_name, turn, exc)
            return AgentResult(
                answer={},
                hitl_flags=hitl_flags,
                turns_used=turn + 1,
                tool_calls_used=total_tool_calls,
                error=f"Model call failed: {exc}",
            )

        # Check if the model wants to call tools
        tool_calls = getattr(response, "tool_calls", None) or []
        if not tool_calls:
            # Final answer — parse and return
            content = getattr(response, "content", "") or ""
            answer = _parse_final_answer(content)
            return AgentResult(
                answer=answer,
                hitl_flags=hitl_flags,
                turns_used=turn + 1,
                tool_calls_used=total_tool_calls,
            )

        # Append the assistant message (with tool_calls) to history
        messages.append(response)

        # Execute ALL tool calls in this batch before checking budget.
        # Cutting a batch short leaves orphaned tool_calls without results,
        # which confuses the model on the extraction turn.
        for tc in tool_calls:
            total_tool_calls += 1
            tool_msg = _dispatch_tool_call(tc, registry, hitl_flags, agent_name)
            logger.debug("Agent %s tool %s -> %s", agent_name,
                         tc.function.name, tool_msg["content"][:200])
            messages.append(tool_msg)

        # Check budget AFTER the full batch is processed
        if total_tool_calls >= max_tool_calls:
            logger.warning(
                "Agent %s: tool call budget exhausted (%d/%d calls)",
                agent_name, total_tool_calls, max_tool_calls,
            )
            return _extract_on_budget(
                messages, agent_name, hitl_flags,
                turns_used=turn + 1,
                tool_calls_used=total_tool_calls,
                reason="tool call",
            )

    # Turn budget exhausted — try extraction
    logger.warning("Agent %s: turn budget exhausted (%d turns)", agent_name, max_turns)
    return _extract_on_budget(
        messages, agent_name, hitl_flags,
        turns_used=max_turns,
        tool_calls_used=total_tool_calls,
        reason="turn",
    )
