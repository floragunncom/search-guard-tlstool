# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Offline command-line tool that generates and validates SSL/TLS certificates for Search Guard / Elasticsearch clusters. It reads a single YAML config describing a CA plus node and client certificates, then produces PEM key/cert files and ready-to-paste `elasticsearch.yml` config snippets. Everything is done locally with BouncyCastle — no network or running cluster is required.

The build ships **two** executables:
- `sgtlstool` — main tool (`SearchGuardTlsTool`), creates CAs, certificates, and CSRs.
- `sgtlsdiag` — diagnostics tool (`SearchGuardTlsDiagnosis`), dumps and validates existing certificate chains.

Target runtime is **Java 8** (`maven.compiler.release=8`). Do not use language features or APIs newer than Java 8 in `src/main`.

## Build & Test

```bash
mvn clean install            # compile, run tests, build all distribution artifacts
mvn test                     # run unit tests only
mvn clean install -DskipTests

# Run a single test class / method
mvn test -Dtest=CreateNodeCertificateTest
mvn test -Dtest=CreateCaTest#testWithIntermediateCert
```

The version is injected via the `revision` property (default `master-SNAPSHOT`); CI overrides it, e.g. `mvn -Drevision=1.9.0-SNAPSHOT ...`. Release builds add `-Prelease`.

`mvn package` produces three things in `target/releases/`:
- the assembly zip/tar.gz (`sgtlstool-standalone.xml`) containing `tools/`, `config/`, and a `deps/` folder of jars — this is what users download;
- a shaded fat jar (classifier `shaded`);
- a self-executing jar (`really-executable-jar`).

## Running locally

```bash
# via the launcher scripts (expect a deps/ dir next to tools/, i.e. from an unpacked assembly)
tools/sgtlstool.sh -c config/example.yml -ca -crt -t ./out
tools/sgtlsdiag.sh <cert-or-config-files...>

# or directly against the shaded jar
java -jar target/releases/search-guard-tlstool-<version>-shaded.jar -c config/example.yml -ca -crt
```

Key `sgtlstool` flags: `-c/--config` (required), `-t/--target` (output dir, defaults to `out`), `-ca/--create-ca`, `-crt/--create-cert`, `-csr/--create-csr`, `-o/--overwrite`, `-f/--force` (skip validation), `-v/--verbose`.

## Architecture

Flow lives in `SearchGuardTlsTool.run()`:

1. Parse CLI options (commons-cli) and load the YAML config into `Config` (Jackson + `applyDefaults()`).
2. Register the BouncyCastle provider and build a shared `Context` — this is the single mutable state bag passed to every task. It holds the config, the `SecureRandom`, the signing certificate/key (populated by `CreateCa`/`LoadCa`), the target directory, the overwrite flag, and the `FileOutput`.
3. Assemble an ordered `List<Task>` based on the flags, then execute them **sequentially**. A `Validate` task is prepended unless `-f` is given. `-ca` adds `CreateCa`; `-crt` adds `LoadCa` (loads/creates the CA) then one `CreateNodeCertificate`/`CreateClientCertificate` per configured node/client; `-csr` adds the `*Csr` variants instead.
4. **Nothing is written to disk during task execution.** Tasks accumulate output via `Context.getFileOutput().add()/addEncrypted()/append()`. Only after all tasks succeed does `FileOutput.saveAllFiles()` flush everything. This is deliberate: a failure partway through leaves the target directory untouched ("No files have been written").

### Key packages (`src/main/java/com/floragunn/searchguard/tools/`)

- `tlstool/` — main tool entry point, `Config` (nested static classes mirror the YAML: `Ca`, `Node`, `Client`, `Defaults`), `Context`, `FileOutput`, `ToolException` (the checked exception used for all user-facing errors).
- `tlstool/tasks/` — one class per unit of work, all extending the abstract `Task`. `Task` centralizes crypto/IO helpers: key-pair generation (RSA or EC depending on `defaults.useEllipticCurves`), PEM reading/decryption, DN parsing/sanitizing, password resolution (`auto` → generated, `none` → unencrypted, else literal), and overwrite checks. Add new certificate-generation behavior here.
- `tlsdiag/` and `tlsdiag/tasks/` — the diagnostics tool, with its own `Task` hierarchy (`DumpCert`, `ValidateCert`).
- `util/` — `EsNodeConfig` (deserializes an existing `elasticsearch.yml` for the diag tool), `PemFileUtils`, `WildcardMatcher`.

### Config semantics worth knowing

Password fields accept `auto` (random password, written into the generated config snippet / `client-certificates.readme`), `none` (unencrypted key), or a literal string. The `ca.intermediate` section is optional — if absent, the root CA signs certificates directly. `defaults.nodesDn` may contain wildcards and `//`-delimited regexes to recognize legitimate nodes.

## Tests

JUnit 4. Tests construct `Config`/`Context` objects programmatically (no CLI) and assert on generated certificates. `src/test/resources/{with-intermediate, without-intermediate, with-intermediate-unencrypted-pk}/` hold golden reference PEM/key/snippet files for the different CA topologies; `TestResources.getAbsolutePath()` resolves them from the classpath.
