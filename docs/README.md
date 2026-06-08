# API Documentation

API documentation generated from the OpenAPI specification.

The generated files are intentionally not committed. Run `make docs` to create
them locally from the tracked `openapi.yaml`.

## Files

- `index.html` - Generated interactive HTML documentation with search and examples
- `API_REFERENCE.md` - Generated Markdown reference for quick lookup

## Documentation Types

### Interactive HTML (`index.html`)
- Try API calls directly from the docs
- Works on desktop and mobile  
- Navigate through endpoints with search
- Code examples in multiple languages

### Simple Markdown (`API_REFERENCE.md`)
- Fast lookup of endpoints and parameters
- Copy/paste examples
- Readable diffs in git
- View with `cat`, `less`, etc.

## Generation

Documentation can be generated whenever `openapi.yaml` changes.

Manual generation:
```bash
make docs
```

## Source

All documentation is generated from [`openapi.yaml`](../openapi.yaml) - edit that file to update the API docs.
