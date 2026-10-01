// The `rust` env's entry: the normal Rust hub with the JavaScript WebSocket
// glue in wsglue.mjs. The glue is imported first, so the Wasm module sees
// the replaced WebSocketPair.
import './wsglue.mjs';

export * from './build/worker/shim.mjs';
export { default } from './build/worker/shim.mjs';
