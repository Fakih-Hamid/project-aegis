"\"\"\"FastAPI application exposing the AEGIS guard sandbox.\"\"\""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from aegis_guard.agent import SandboxedAgent

app = FastAPI(title="AEGIS Guard", version="0.1.0")
agent = SandboxedAgent()


class ChatRequest(BaseModel):
    prompt: str = Field(..., min_length=1)


class ChatResponse(BaseModel):
    response: str
    decision: Dict[str, Any]


class ToolRequest(BaseModel):
    tool: str
    args: Dict[str, Any] = Field(default_factory=dict)


class ToolResponse(BaseModel):
    result: Any
    decision: Dict[str, Any]


@app.post("/chat", response_model=ChatResponse)
async def chat_endpoint(request: ChatRequest) -> ChatResponse:
    try:
        response = agent.chat(request.prompt)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return ChatResponse(response=response.content, decision=asdict(response.decision))


@app.post("/tools/fetch", response_model=ToolResponse)
async def tool_endpoint(request: ToolRequest) -> ToolResponse:
    try:
        response = agent.call_tool(request.tool, **request.args)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return ToolResponse(result=response.content, decision=asdict(response.decision))


def run() -> None:
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)

