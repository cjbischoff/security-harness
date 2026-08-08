"""The correlation workspace: a dir holding the manifest, edge graph, verdicts, and artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class CorrelationWorkspace:
    """Filesystem layout for one product's correlation outputs (spans repos).

    Attributes:
        root: The correlation workspace root directory.
    """

    root: Path

    def __post_init__(self) -> None:
        """Coerce ``root`` to :class:`Path`."""
        self.root = Path(self.root)

    @property
    def manifest_path(self) -> Path:
        """Path to the product manifest copy.

        Returns:
            Path to product.json.
        """
        return self.root / "product.json"

    @property
    def edges_path(self) -> Path:
        """Path to the cross-repo edge graph.

        Returns:
            Path to edges.json.
        """
        return self.root / "edges.json"

    @property
    def verdicts_path(self) -> Path:
        """Path to the correlation verdicts (B-Plan 2).

        Returns:
            Path to verdicts.json.
        """
        return self.root / "verdicts.json"

    @property
    def gates_dir(self) -> Path:
        """Directory for adversary gate records (B-Plan 2).

        Returns:
            Path to gates directory.
        """
        return self.root / "gates"

    @property
    def artifacts_dir(self) -> Path:
        """Directory for the combined artifacts (B-Plan 3).

        Returns:
            Path to artifacts directory.
        """
        return self.root / "artifacts"

    def ensure(self) -> None:
        """Create the correlation workspace tree if absent.

        Creates root, gates, and artifacts directories with parents as needed.
        """
        self.root.mkdir(parents=True, exist_ok=True)
        self.gates_dir.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
