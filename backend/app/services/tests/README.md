# app.services tests

This directory centralizes tests for modules under `app/services/`.

## Run

From `backend/`:

```bash
pytest
```

## Optional integration tests

Some tests require external services and are skipped by default:

- OpenSearch: set `RUN_OPENSEARCH_TESTS=1`
- Neo4j: set `RUN_NEO4J_TESTS=1`

