# MISSION — sentinel-bench

> Lab personal de Cyber Threat Intelligence que prioriza vulnerabilidades por evidencia real de explotación (KEV / EPSS / GHSA / NVD / MSRC + 11 fuentes OT/ICS) y entrega un briefing diario por Telegram + dashboard público + API REST.

**Owner:** iamtweaks
**Date:** 2026-09-13

## Es

- Ingestar vulnerabilidades de 5 fuentes IT (CISA KEV, NVD, EPSS, GHSA, MSRC) y 11 fuentes OT/ICS (ABB, Rockwell, Siemens, Moxa, Fortinet, Cisco, Palo Alto, CERT@VDE, CISA ICS, NVD ICS, …).
- Calcular un puntaje de riesgo 0–100 por CVE, explicable, basado en señales públicas (KEV, EPSS, PoC público, vendor advisory).
- Entregar un briefing diario por Telegram cuando cambia el top-5.
- Exponer el resultado en un dashboard Astro estático y en una API REST pública de solo lectura.

## NO es

- **NO es un scanner de código (SAST / DAST)** — esto ingiere feeds públicos de vendors, no analiza repos ni código de usuarios.
- **NO es un SIEM / SOC platform** — no ingiere logs privados, no correlaciona eventos internos, no maneja IoCs corporativos.
- **NO es un vulnerability management con auth / multi-tenant / SSO** — todo lo que se publica es 100% público al momento de ingestarse; no hay cuentas ni vista por organización.
- **NO es un chatbot de seguridad / Slack bot / Discord bot** — la entrega es Telegram cron + dashboard + API, no un asistente conversacional.
- **NO es un threat intel platform pago con API keys, rate limits por usuario, ni planes Free / Pro** — es un proyecto personal, gratis, open source, sin billing.
- **NO es un agregador de IoCs privados ni scrapea infra interna** — si una fuente no es pública y validable, no entra.
- **NO es un producto de exploit intelligence (exploit chains, marketplaces, PoCs funcionales)** — solo señala que un PoC público existe, no lo hostea ni lo enlaza a kits.
- **NO es real-time / streaming** — los crons son cada 30 min / 8 h / diario / semanal; no hay webhooks push.

## Reglas

- **Todo dato publicado debe ser 100% público al momento de ingestarse.** Si una fuente requiere auth, scraping interno, o datos privados, queda afuera.
- **El scoring se calcula en SQL, no con LLM.** El LLM se invoca solo cuando cambia el top-5 para redactar el briefing, nunca para puntuar.
- **Cost ceiling: $0 de infra fija, < $1/mes de LLM.** Vercel Hobby + Supabase Free + feeds públicos. Si una feature lo rompe, no entra.
