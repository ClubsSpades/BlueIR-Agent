from typing import Protocol

from blueir_agent.agent.state import AnalysisState


class Skill(Protocol):
    name: str
    description: str

    def score(self, state: AnalysisState) -> int:
        ...

    def run(self, state: AnalysisState) -> None:
        ...
