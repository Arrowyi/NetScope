package indi.arrowyi.netscope.sdk.integration

/**
 * Marker interface that every NetScope-produced instrumentation object
 * (OkHttp `Interceptor`, `URLConnection` wrapper, `WebSocketListener`
 * wrapper, `WebSocket` wrapper) implements.
 *
 * The Gradle Transform and the runtime wrappers both check for this
 * marker before injecting / wrapping again, so double-injection is a
 * no-op. This is the core mechanism that makes NetScope's
 * "no double-count, no miss" guarantee work even when:
 *
 *   - the host integrates the interceptor manually AND the plugin runs,
 *   - two different Gradle Transforms both touch the same class,
 *   - an already-wrapped `URLConnection` is passed back through the
 *     instrumented call site (e.g. a `URL.openConnection()` call inside
 *     an already-instrumented library).
 *
 * DO NOT remove — `docs/AGENT_HANDOFF.md` Golden Rule AOP-G1.
 */
interface NetScopeInstrumented
