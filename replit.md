# FaceGate_Server

## Project overview

This repository contains the FaceGate license server, public download pages, and browser-based PSD editor under `/editor`.

The editor includes a safe AI-assisted fictional profile-card workflow. It composites a selected photo into a non-official demo design and permanently stamps `SAMPLE — NOT A REAL ID`. AI only suggests short copy and a color accent; it does not control the renderer or watermark.

## Development

```bash
npm install
npm test
npm start
```

The server listens on `PORT` (default `3000`). Set `OPENAI_API_KEY` in the runtime environment to enable AI suggestions. Without it, the safe demo-card route uses a deterministic fallback and remains functional.

## User preferences

- Keep official-document creation or alteration out of the editor.
- Prefer explicit validation, visible loading/error states, and reliable PNG downloads over silent fallbacks.