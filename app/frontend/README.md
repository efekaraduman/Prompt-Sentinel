## PromptSentinel Frontend

This is the Next.js (App Router) frontend for **PromptSentinel**, a small SaaS-style dashboard that simulates prompt-injection attacks against an LLM system prompt and visualizes the resulting risk.

### Running the stack locally

From the project root (where your FastAPI backend lives):

1. **Start the backend** (FastAPI):

   ```bash
   uvicorn app.main:app --reload
   ```

   This starts the API server on `http://127.0.0.1:8000`.

2. **Start the frontend** (Next.js):

   ```bash
   cd frontend
   npm run dev
   ```

   The dashboard will be available at `http://localhost:3000`.

### How the proxy works

The frontend is configured with a rewrite in `next.config.ts`:

- Requests to `/api/:path*` from the browser are proxied to `http://127.0.0.1:8000/:path*`.
- The UI calls the backend **only** via `/api/test-llm`, so no direct `127.0.0.1` URLs or CORS configuration are required in the frontend.

In particular, the security test flow is:

1. The dashboard sends `POST /api/test-llm` from the browser.
2. Next.js rewrites this to `POST http://127.0.0.1:8000/test-llm`.
3. The FastAPI backend runs the simulated attacks and returns the JSON result.
4. The frontend renders the overall risk score, summary, and per-test details.
