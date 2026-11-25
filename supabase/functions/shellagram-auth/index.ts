// Shellagram production Edge Function entry point.
// All logic lives in handler.mjs (runtime-agnostic, unit-tested under Node in
// test/production/); this file only binds it to Deno.serve.
import { createHandler } from './handler.mjs';

Deno.serve(createHandler());
