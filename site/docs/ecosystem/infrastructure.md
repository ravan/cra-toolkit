# Infrastructure Components

The CRA toolkit integrates with several infrastructure components that provide policy evaluation, cryptographic signing, and code analysis capabilities. These are not standalone tools you run separately — they are embedded in or invoked by the toolkit itself.

---

## OPA / Rego

[Open Policy Agent](https://www.openpolicyagent.org/) (OPA) powers the PolicyKit evaluation engine. Policies are written in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/), a declarative query language designed for policy decisions over structured data.

### How the toolkit uses OPA

The toolkit embeds 10 default CRA compliance policies written in Rego. Each policy evaluates input documents — SBOMs, VEX documents, scan results, and provenance attestations — against specific CRA Annex I requirements. The OPA engine is compiled into the toolkit binary, so there is no external OPA server or daemon to manage.

### Built-in policies

The embedded policies cover CRA requirements including:

- **CRA-AI-1.x** — Security design and default configuration checks
- **CRA-AI-2.x** — Vulnerability handling and VEX coverage
- **CRA-AI-3.x** — Supply chain integrity and SLSA provenance
- **CRA-REACH-x** — Reachability analysis quality

Each policy produces structured results with pass/fail/warn status, descriptions, and remediation guidance.

### Custom policies

Organizations can extend the built-in policy set by loading additional Rego files from a directory:

```bash
cra policykit --sbom sbom.cdx.json --vex vex.json \
  --policy-dir ./custom-policies
```

Custom policies follow the same Rego conventions as the built-in policies. They are evaluated alongside (not instead of) the defaults, allowing organizations to layer company-specific compliance requirements on top of the CRA baseline.

See [`cra policykit`](../tools/policykit.md) for full usage details.

---

## Cosign

[Cosign](https://github.com/sigstore/cosign) (part of the Sigstore project) signs evidence bundles for integrity and authenticity verification. Signing provides tamper-evident assurance that compliance artifacts have not been modified after generation — a requirement for conformity assessment under CRA Annex VII.

### Signing modes

**Keyless signing** (default): Uses [Fulcio](https://github.com/sigstore/fulcio) for short-lived certificates and [Rekor](https://github.com/sigstore/rekor) for transparency log entries. No key management required — the signer authenticates via OIDC (OpenID Connect), and the certificate is valid only for the duration of the signing operation. The transparency log provides a public, immutable record of the signing event.

```bash
cra evidence --sbom sbom.cdx.json --vex vex.json \
  --scan grype.json --policy-result policy.json \
  -o evidence-bundle.json
```

**Key-based signing**: Uses a local private key for environments without OIDC access or where organizational key management is required.

```bash
cra evidence --sbom sbom.cdx.json --vex vex.json \
  --scan grype.json --policy-result policy.json \
  --signing-key cosign.key \
  -o evidence-bundle.json
```

### Verification

Evidence bundles signed with Cosign can be verified by downstream consumers and auditors using standard Cosign verification commands. Keyless signatures are verified against the Fulcio root CA and Rekor transparency log. Key-based signatures are verified against the corresponding public key.

See [`cra evidence`](../tools/evidence.md) for full usage details.

---

## Tree-sitter

[Tree-sitter](https://tree-sitter.github.io/tree-sitter/) is an incremental parsing framework that powers reachability analysis in `cra vex`. The toolkit includes tree-sitter grammars for 8 languages, enabling it to build interprocedural call graphs and determine whether vulnerable functions are reachable from application entry points.

### Supported languages

| Language | Entry points detected |
|---|---|
| Go | `main()`, HTTP handlers, exported functions |
| Rust | `main()`, `#[no_mangle]` functions, public API |
| Python | `__main__` blocks, WSGI/ASGI handlers, decorated routes |
| JavaScript | Module exports, Express/Koa handlers, event listeners |
| Java | `main()` methods, servlet handlers, Spring controllers |
| C# | `Main()` methods, ASP.NET controllers, middleware |
| PHP | Script entry points, route handlers, CLI commands |
| Ruby | Script entry points, Rails controllers, Rack handlers |

### How reachability analysis works

1. **Parse** — tree-sitter parses the application source code into concrete syntax trees for each file.
2. **Identify entry points** — the toolkit detects language-specific entry points (main functions, HTTP handlers, exported APIs).
3. **Build call graph** — interprocedural analysis traces function calls from entry points through the codebase.
4. **Match vulnerable functions** — known vulnerable functions (from CVE advisory data) are checked against the call graph.
5. **Score confidence** — each reachability finding receives a confidence score (high, medium, or low) based on the completeness of the call graph traversal.
6. **Record call paths** — when a vulnerable function is reachable, the exact call chain from entry point to vulnerable code is recorded as evidence.

### Confidence scores

| Level | Meaning |
|---|---|
| `high` | Full call graph traced from entry point to vulnerable function |
| `medium` | Partial analysis — some call edges resolved statically, others inferred |
| `low` | Pattern match only — vulnerable function name found but call graph incomplete |

### Call path evidence

When a vulnerable function is found to be reachable, the exact function call chain is recorded and propagated through downstream tools:

- **`cra report`** renders call paths in Article 14 notifications so CSIRT reviewers can see precisely how a vulnerability is reachable.
- **`cra csaf`** includes reachability information in advisory notes.
- **`cra evidence`** bundles call path evidence in the compliance package for conformity assessment.

See [`cra vex`](../tools/vex.md) for full usage details on reachability analysis.
