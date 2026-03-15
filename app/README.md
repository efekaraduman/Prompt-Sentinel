# PromptSentinel Backend

PromptSentinel is a small FastAPI-based backend designed to simulate prompt-injection attacks against an LLM and produce a simple risk assessment.

## Features

- **`POST /test-llm`**: Accepts a system prompt and model name, simulates 5 prompt-injection attempts, and returns:
  - An overall **risk score** from 0–100
  - A short **summary**
  - Per-test details including detected leakage and instruction-override behavior

## Running the API

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the development server:

```bash
uvicorn app.main:app --reload
```

The OpenAPI docs will be available at `http://localhost:8000/docs`.

