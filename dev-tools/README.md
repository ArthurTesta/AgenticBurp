# dev-tools/

Reusable, no-Maven-Central verification infrastructure for this project's
Java code, built up across sessions rather than reconstructed each time.
This exists because this sandbox has never had Maven Central access
(`repo.maven.apache.org` is not in the egress allowlist -- confirmed
repeatedly, not assumed), so `gradle build` cannot run here. `RunTests.java`
plus `stubs/` is how `IdentityCompareLogic`, `UrlIdentifierDiff`,
`PathScorer`, `WorkflowReplayLogic`, and `SsrfCallbackLogic` were compiled
and their JUnit5 tests actually executed this session -- not narrated.

## What's here

- **`stubs/burp/api/montoya/...`** -- a minimal stub of the real Montoya API,
  containing *only* the interfaces/methods this project's code actually
  calls. Every signature was individually fetched and verified against
  `raw.githubusercontent.com/PortSwigger/burp-extensions-montoya-api` this
  session (that domain is allowlisted; `repo.maven.apache.org` is not).
  **This is not a complete Montoya stub** -- e.g. `BurpExtension`,
  `core.ToolType`, and `ui.contextmenu.*` are not included, because
  `LlmHarnessExtension.java` and `HarnessContextMenu.java` weren't touched
  this session. Extend it the same way if those files change: fetch the
  real interface source, transcribe only the methods actually called, cite
  the source file.
- **`stubs/org/junit/jupiter/api/...`** -- a minimal JUnit5 stub (`@Test`,
  `@DisplayName`, `Assertions`) covering only the overloads this project's
  test files use, verified against `junit-team/junit5`'s real source.
- **`RunTests.java`** -- a reflection-based runner. Since the JUnit5 stub
  has no real discovery/execution engine, this finds `@Test`-annotated
  methods on a class and actually invokes them, reporting PASS/FAIL per
  method. This is real execution against real assertion logic -- it is
  NOT the real JUnit5 engine (no real test discovery, lifecycle, parallel
  execution, etc.), so a real `gradle test` in an environment with Maven
  Central access is still the stronger signal and should supersede this
  the moment it's available.

## How to use

```bash
cd burp-extension
mkdir -p /tmp/out
javac -d /tmp/out \
  $(find src/main/java/com/harness/llm/logic src/main/java/com/harness/llm/surface -name '*.java') \
  $(find src/test/java -name '*.java') \
  $(find ../dev-tools/stubs -name '*.java')
javac -cp /tmp/out -d /tmp/out ../dev-tools/RunTests.java
java -cp /tmp/out RunTests \
  com.harness.llm.logic.IdentityCompareLogicTest \
  com.harness.llm.surface.PathScorerTest \
  com.harness.llm.logic.WorkflowReplayLogicTest \
  com.harness.llm.logic.SsrfCallbackLogicTest
```

Expect `50 passed, 0 failed`. If that number changes because a new pure
logic class was added, update this README's expected count too -- a
stale expected-count is exactly the kind of thing that looks like a
passing check while quietly meaning nothing.

## Type-checking Montoya-dependent files (not just pure logic)

`ValidationExecutor.java` itself doesn't compile standalone -- it needs a
`HarnessClient` (real one pulls in Gson, a separate dependency this
sandbox also can't fetch). For isolation, stub `HarnessClient`'s public
API faithfully (see this session's transcript / archive/HANDOVER.md item 10 for
the exact stub used) rather than the real file, then:

```bash
javac -d /tmp/out2 \
  $(find ../dev-tools/stubs -name '*.java') \
  /path/to/isolation/HarnessClient.java \
  src/main/java/com/harness/llm/ValidationExecutor.java \
  src/main/java/com/harness/llm/logic/*.java \
  src/main/java/com/harness/llm/model/AnalysisModels.java
```

Zero errors = type-checked, in this document's vocabulary: stronger than
source review, weaker than compiling against the real jar with real
Gradle. The real Gradle build in an environment with Maven Central access
is still the milestone that actually matters -- see archive/HANDOVER.md.
