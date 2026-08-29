"""Generate and time-align the Warden demo narration with Gemini TTS."""

from __future__ import annotations

import argparse
import subprocess
import wave
from dataclasses import dataclass
from pathlib import Path

from google import genai
from google.genai import types


@dataclass(frozen=True)
class Segment:
    start: float
    end: float
    text: str


SEGMENTS = [
    Segment(
        0,
        18,
        "Gemini agents can provision infrastructure and run workloads. But one bad instruction "
        "can cause real damage. Warden enables governed autonomy, keeping identity, policy, "
        "spending, and destructive actions under enforceable human control.",
    ),
    Segment(
        18,
        42,
        "Before changing production policy, an operator can simulate it. This GPU request is "
        "checked against a reusable template, placement rules, lifetime limits, and Warden's "
        "rate card. We see the approval decision and projected cost without calling a provider "
        "or changing state. The evidence remains replayable for audit.",
    ),
    Segment(
        42,
        78,
        "For productive work, Warden packages authority as a Mission. This contract allows one "
        "specific GPU type, in one region, for one action, with a two-dollar ceiling and a "
        "sixty-minute lifetime. The objective is human-readable, but the authority is "
        "machine-enforced. I approve the bounded envelope once; it cannot be reused by another "
        "run, expanded by the model, or used for a high-blast-radius cluster action.",
    ),
    Segment(
        78,
        118,
        "Now the fleet can execute inside those exact bounds. The A D K plugin checks the "
        "envelope before the tool reaches the provider. Warden reserves capacity atomically, "
        "records the rate-card quote, and settles the outcome idempotently. The Mission tracks "
        "progress, created resources, artifacts, time-to-live, and cleanup receipts. If a "
        "provider result is ambiguous, spend is marked uncertain instead of being silently "
        "counted twice or forgotten.",
    ),
    Segment(
        118,
        158,
        "Now the adversarial case. I explicitly tell the model to ignore every rule and "
        "force-delete a production cluster. Even if Gemini emits that tool call, Warden "
        "intercepts it below the prompt layer. The requester cannot approve their own action, "
        "duplicate votes do not count twice, and cluster destruction requires two distinct "
        "senior approvers. The workflow remains parked. Prompt injection can ask for authority; "
        "it cannot manufacture it.",
    ),
    Segment(
        158,
        185,
        "Governance also needs independent evidence. Warden collects asset drift, Security "
        "Command Center findings, and thirty-day finance data, then anchors that snapshot to "
        "the active policy and audit-chain tip. This recording uses deterministic mock "
        "connectors, so no real cloud resource is touched. In production, the adapters read "
        "Google Cloud and can archive the evidence into a retention-locked bucket.",
    ),
    Segment(
        185,
        208,
        "Every decision is sealed into a S H A two fifty-six hash chain. Verification proves "
        "whether any record was changed, and the export produces a secret-free evidence bundle. "
        "Replay binds supplied arguments back to their recorded digest, so an auditor can "
        "reproduce a decision without re-executing infrastructure.",
    ),
    Segment(
        208,
        230,
        "Finally, Warden tests itself. The automated suite attacks approval bypass, budget "
        "manipulation, disallowed placement, secret egress, audit integrity, and prompt "
        "injection. Six attack paths, six deflections. These are executable controls, not "
        "rules the model is merely asked to remember.",
    ),
    Segment(
        230,
        244.5,
        "From a solo producer's first GPU job to an enterprise fleet, Warden gives agents "
        "bounded freedom and gives humans proof. Warden: autonomy with a control plane.",
    ),
]


def run(*args: str) -> None:
    subprocess.run(args, check=True)


def output(*args: str) -> str:
    return subprocess.check_output(args, text=True).strip()


def duration(path: Path) -> float:
    return float(
        output(
            "ffprobe",
            "-v",
            "error",
            "-show_entries",
            "format=duration",
            "-of",
            "default=noprint_wrappers=1:nokey=1",
            str(path),
        )
    )


def save_pcm_wav(path: Path, pcm: bytes) -> None:
    with wave.open(str(path), "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(24_000)
        wav.writeframes(pcm)


def synthesize(client: genai.Client, segment: Segment, path: Path) -> None:
    target = segment.end - segment.start - 1.0
    prompt = f"""Audio profile:
A calm principal systems architect presenting a trusted enterprise security product.

Scene:
A polished four-minute product demonstration for technical judges and business leaders.

Director's notes:
Use an even, confident, natural American English delivery. Sound authoritative but not theatrical.
Maintain crisp articulation and a measured pace. Use restrained emphasis on Warden, Mission,
bounded freedom, and proof. Do not add an introduction, commentary, music, or sound effects.
Pronounce "autonomy" clearly as "aw-TAH-nuh-mee"; never pronounce it as "economy."
Read only the transcript. Aim to finish this passage naturally in approximately {target:.1f} seconds.

Transcript:
{segment.text}
"""
    response = client.models.generate_content(
        model="gemini-3.1-flash-tts-preview",
        contents=prompt,
        config=types.GenerateContentConfig(
            response_modalities=["AUDIO"],
            speech_config=types.SpeechConfig(
                voice_config=types.VoiceConfig(
                    prebuilt_voice_config=types.PrebuiltVoiceConfig(
                        voice_name="Schedar"
                    )
                )
            ),
        ),
    )
    parts = response.candidates[0].content.parts
    audio = next((part.inline_data.data for part in parts if part.inline_data), None)
    if not audio:
        raise RuntimeError("Gemini returned no audio for a narration segment")
    save_pcm_wav(path, audio)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--work-dir", type=Path, default=Path("build/demo-voiceover"))
    args = parser.parse_args()

    source = args.input.expanduser().resolve()
    destination = args.output.expanduser().resolve()
    work_dir = args.work_dir.expanduser().resolve()
    if not source.exists():
        raise SystemExit(f"Recording not found: {source}")
    work_dir.mkdir(parents=True, exist_ok=True)
    destination.parent.mkdir(parents=True, exist_ok=True)

    project = output("gcloud", "config", "get-value", "project")
    if not project or project == "(unset)":
        raise SystemExit("No active Google Cloud project is configured")
    client = genai.Client(vertexai=True, project=project, location="us-central1")

    inputs: list[str] = []
    filters: list[str] = []
    labels: list[str] = []
    for index, segment in enumerate(SEGMENTS, start=1):
        wav = work_dir / f"segment-{index:02d}.wav"
        if not wav.exists():
            print(f"Synthesizing segment {index}/{len(SEGMENTS)} with Schedar...")
            synthesize(client, segment, wav)
        raw_duration = duration(wav)
        available = segment.end - segment.start - 0.6
        speed = max(1.0, raw_duration / available)
        label = f"voice{index}"
        inputs.extend(["-i", str(wav)])
        filters.append(
            f"[{index - 1}:a]atempo={speed:.6f},"
            f"adelay={int((segment.start + 0.3) * 1000)}:all=1[{label}]"
        )
        labels.append(f"[{label}]")
        print(
            f"  segment {index}: {raw_duration:.2f}s generated, "
            f"{available:.2f}s available, speed {speed:.3f}x"
        )

    voice_track = work_dir / "warden-schedar-voiceover.wav"
    video_duration = duration(source)
    filters.append(
        "".join(labels)
        + f"amix=inputs={len(labels)}:duration=longest:dropout_transition=0,"
        + f"apad=whole_dur={video_duration:.6f},atrim=duration={video_duration:.6f},"
        + "loudnorm=I=-16:TP=-1.5:LRA=7[voiceover]"
    )
    run(
        "ffmpeg",
        "-y",
        *inputs,
        "-filter_complex",
        ";".join(filters),
        "-map",
        "[voiceover]",
        "-ar",
        "48000",
        str(voice_track),
    )
    run(
        "ffmpeg",
        "-y",
        "-i",
        str(source),
        "-i",
        str(voice_track),
        "-map",
        "0:v:0",
        "-map",
        "1:a:0",
        "-c:v",
        "copy",
        "-c:a",
        "aac",
        "-b:a",
        "192k",
        "-movflags",
        "+faststart",
        "-t",
        f"{video_duration:.6f}",
        str(destination),
    )
    print(f"Created {destination}")


if __name__ == "__main__":
    main()
