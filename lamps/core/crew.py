from __future__ import annotations


def build_crewai_agents(llm=None) -> dict[str, object]:
    """Create CrewAI Agent objects when CrewAI is installed.

    The runtime pipeline remains deterministic for safe static analysis. These
    Agent objects document and expose the same role boundaries as the LAMPS
    paper and the author's replication script.
    """
    try:
        from crewai import Agent
    except Exception as exc:
        raise RuntimeError("crewai is required to build CrewAI agents.") from exc

    return {
        "fetcher": Agent(
            role="Package Harvester",
            goal="Resolve a PyPI package and retrieve its source archive metadata.",
            backstory="Knows PyPI API and package metadata structure.",
            llm=llm,
            verbose=True,
        ),
        "extractor": Agent(
            role="Code File Extractor",
            goal="Extract and select Python files relevant for static malware analysis.",
            backstory="Understands package archive layouts and ignores non-code noise.",
            llm=llm,
            verbose=True,
        ),
        "classifier": Agent(
            role="Security Code Classifier",
            goal="Classify Python source files as benign or malicious.",
            backstory="Uses a fine-tuned CodeBERT classifier or a transparent heuristic fallback.",
            llm=llm,
            verbose=True,
        ),
        "verdict": Agent(
            role="Package Verdict Synthesizer",
            goal="Aggregate file-level classifications into a package-level verdict.",
            backstory="Applies conservative LAMPS policy and explains the evidence.",
            llm=llm,
            verbose=True,
        ),
    }
