# Dandiya Night

Public site and student-facing API for the Dandiya Night event: landing, event info, registration, UPI/cash payment submission, pass and community chat.

Staff tooling (admin console, gate scanner, database functions) is not part of this repository.

## Run

    bun install && bun run dev      # site
    cd api && npm install && node server.mjs   # API (needs DATABASE_URL, see api/.env.example)
