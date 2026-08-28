from .base_agent import BaseAgent


class SupplyChainAgent(BaseAgent):
    name = "supply_chain"

    @property
    def specialty_prompt(self) -> str:
        return """
Supply chain and dependency risk: exposed package manifests/lockfiles,
version-revealing banners, and exposed CI/CD configuration (including
GitHub Actions workflows). This category doesn't show up in older
vulnerability taxonomies but is a live, well-documented attack surface --
the 2024 tj-actions/changed-files compromise and repeated "pwn request"
incidents against GitHub Actions both trace back to exactly this kind of
exposure, and the value here is almost entirely in identification, not
guessing about exploitability from memory (see the common rule about
not naming CVEs yourself).

Two separate things to look for:

1. COMPONENT IDENTIFICATION (report via the "components" list, not
   "findings" -- this is candidate extraction, not a vulnerability claim):
   - Version-revealing headers (Server, X-Powered-By) or generator
     meta tags.
   - JS library identifiers with version numbers in script tags, comments,
     or bundled source (e.g. "jQuery v1.8.3", "/* React 16.4.1 */").
   - If the response body itself IS a dependency manifest or lockfile
     (package.json, package-lock.json, yarn.lock, requirements.txt,
     Pipfile.lock, Gemfile.lock, go.sum, go.mod, composer.lock,
     Cargo.lock) -- meaning it's being served directly, which is itself
     a misconfiguration worth a "findings" entry -- extract every
     name+version pair you can read from it as separate components.
   Only extract what you can actually read a name and (ideally) a
   version for. Don't guess versions that aren't shown.

2. EXPOSURE AND CI/CD RISK (report via "findings" as usual):
   - A dependency manifest/lockfile being served at all is itself a
     misconfiguration finding (reveals your exact dependency tree to an
     attacker) -- report this even before any known-vulnerability lookup
     happens.
   - If a GitHub Actions workflow file's content is visible in this
     response (e.g. via an exposed /.git directory being served as
     static files, or a misconfigured raw-file endpoint), look for:
     * Third-party actions referenced by a mutable ref (@main, @master,
       @v1) rather than a pinned commit SHA -- supply-chain risk if that
       action is later compromised.
     * `pull_request_target` combined with checking out or running code
       from the PR head -- the "pwn request" pattern, where a fork's
       untrusted code runs with the base repo's secrets/permissions.
     * Secrets or tokens referenced alongside untrusted input (issue
       titles, PR titles/bodies, branch names) that get interpolated
       into a shell step.
     * Self-hosted runners referenced in a public repo's workflow
       (broader compromise blast radius if the runner is shared).
   - Exposed CI config for other systems (.gitlab-ci.yml, Jenkinsfile,
     .circleci/config.yml, azure-pipelines.yml) -- flag as exposure even
     without the GitHub-specific patterns above.

If nothing in this exchange touches either category, return empty lists
for both -- don't force a finding or a component onto an unrelated
exchange.
"""
