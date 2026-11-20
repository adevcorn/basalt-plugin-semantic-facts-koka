# basalt-plugin-semantic-facts-koka

Provides `semantic-facts@koka/v1` for `.kk` and `.kki` files by combining:
- `parse.retrieval@koka/v1` (declarations)
- `parse.call-sites@koka/v1` (call edges + stdlib I/O classification)
- Koka signature effect-row analysis (`<console, fsys, net, io, st<h>, async>`)
- `import` module dependencies

## Build

```sh
cargo build --release --target wasm32-unknown-unknown
```
