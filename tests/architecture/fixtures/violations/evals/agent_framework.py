"""FIXTURE: importing another autonomous-agent framework (PY002)."""

from langchain.agents import AgentExecutor
from langgraph.graph import StateGraph


def build() -> AgentExecutor:
    return AgentExecutor(graph=StateGraph())
