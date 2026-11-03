# Security

Turbo reads and writes local files, runs configured commands, and stores evidence in a state directory outside the product repository. It does not provide a sandbox.

Do not put credentials, provider keys, private chat data, customer data, or other secrets in a public issue, pull request, discussion, commit, or test fixture.

If you find a vulnerability, use the repository's Security tab to open a private security advisory. Do not post exploit details or secret material publicly. Include the affected version from `VERSION`, a short reproduction, and the impact you observed. A maintainer will acknowledge the report and coordinate a fix before public disclosure.

The helper is local operator tooling. Reports that only restate the documented trust boundary, such as "the state home is writable by the same OS user", are not vulnerabilities. Reports of unexpected command execution, path escape, symlink handling, evidence overwrite, or a refusal bypass are in scope.
