"""Tests for Warden Red-Team Adversarial Benchmark."""

import pytest
from warden.security.redteam import run_redteam_benchmark


@pytest.mark.asyncio
async def test_redteam_adversarial_benchmark():
    report = await run_redteam_benchmark()
    assert report.grade == "A+"
    assert report.total_vectors == 5
    assert report.deflected_count == 5
    assert report.deflection_rate == "100%"

    for result in report.results:
        assert result.deflected is True
        assert len(result.detail) > 0
