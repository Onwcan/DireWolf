"""FIXTURE: deliberately invalid.

The runtime importing the eval harness (PY003). The harness can spawn a process
and holds an execution-environment double; importing it from the cognition
plane is how a test convenience becomes a second path to effect.
"""

from direwolf_evals.process import spawn
from direwolf_evals.test_environment import EvalTestEnvironment


def run_a_tool(script: str) -> str:
    EvalTestEnvironment()
    with spawn(script) as child:
        child.wait()
        return "\n".join(child.stdout)
