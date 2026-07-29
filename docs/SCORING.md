# Scoring v1

## Fórmula

```
score = clip(0..100,
    30 * kev_present
  + 25 * (1 if epss_percentile >= 0.99 else 0)
  + 15 * (epss_score if epss_score >= 0.5 else 0)        # 0..0.15
  + 12 * cvss_v3 / 10                                     # 0..12
  +  8 * exploitation_factor                              # 0..1
  +  5 * recency_factor                                   # 0..1
  +  3 * source_diversity_factor                          # 0..1
  +  2 * vendor_exposure_factor                           # 0..1
)
```

Cada factor persiste en `risk_scores.factors` (jsonb). Si un dato es ausente,
queda como `null` explícito — nunca se inventa.

## Factores

| Factor | Fuente | Rango | Peso máximo |
|---|---|---|---|
| `kev_present` | CISA KEV | {0, 30} | 30 |
| `epss_top1pct` | FIRST EPSS | {0, 25} | 25 |
| `epss_score` | FIRST EPSS (si ≥ 0.5) | {0..0.15} | 15 |
| `cvss_v3_score` | NVD / GHSA | {0..12} | 12 |
| `exploitation_factor` | derivado de KEV/PoC | {0..1} | 8 |
| `recency_factor` | published_at / first_seen_at | {0, 5} | 5 |
| `source_diversity_factor` | count distinct advisories por CVE | {0..3} | 3 |
| `vendor_exposure_factor` | intersection con lista de vendors high-exposure | {0, 2} | 2 |

## Lista de vendors high-exposure (proxy)

`microsoft, apple, google, linux, cisco, adobe, oracle, ibm, sap, vmware,
fortinet, paloaltonetworks, citrix, juniper`

(Si un vendor crítico no está, agregalo a `score.py:HIGH_EXPOSURE_VENDORS`.)

## Exploitation factor

| exploitation_status | factor |
|---|---|
| `confirmed` (en KEV) | 1.0 |
| `poc` (PoC público, sin KEV) | 0.6 |
| `probable` (referencias lo sugieren) | 0.3 |
| `none` / `unknown` | 0.0 |

## Recency factor

| Antigüedad | factor |
|---|---|
| < 7 días | 1.0 |
| < 30 días | 0.5 |
| < 90 días | 0.2 |
| ≥ 90 días | 0.0 |

(Usamos `first_seen_at` en la tabla vulnerabilities — el día que Sentinel-Bench
lo vio por primera vez. Esto evita que CVEs viejos con score histórico alto
reciban recency_factor=1 cuando ya están parcheados en todos lados.)

## Limitaciones conocidas

- **NVD sin CVSS**: muchos KEV entries no tienen CVSS en NVD. Score máximo posible
  sin CVSS = 88. Para los KEV viejos que ya nadie parchea, están "over-priorizados".
  Mejora futura: descontar según `kev_due_date < now` o `last_patched_at > 30d`.
- **MSRC sin CVE-level**: la lista MSRC no incluye CVEs. Necesita parsear CVRF XML.
  Está marcado como future work en `lib/normalize.py:normalize_msrc`.
- **Single vendor CPE**: el `vendors` array se extrae de NVD CPE strings. Algunos
  vendors vienen con espacios o variantes. Mejora: normalizar (lowercase, trim).

## Versionado

- `model_version='v1'` es lo que persiste en `risk_scores.model_version`.
- Cambios incompatibles requieren bump a `v2` y mantener histórico.

## Cómo iterar

1. Editar `ingest/lib/score.py`.
2. Re-correr: `python -m ingest.score --limit=2000`.
3. Comparar top-10 antes/después en el dashboard.
4. Si conviene, mergear + commit.