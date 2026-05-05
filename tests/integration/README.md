# Integration tests

One test file per MCP server we claim compatibility with. Each test
file ships three scenarios and a small JSON fixture per scenario:

| Scenario | What it asserts |
|---|---|
| **Smoke**  | The server's `initialize` reply round-trips through the proxy unchanged. |
| **Benign** | A realistic-shape tool result with no payload passes through and gets `det_verdict=PASS`. |
| **Attack** | A realistic-shape tool result containing a known prompt-injection class is replaced with a sanitised reply, with `det_verdict=BLOCK` in the audit log. |

The proxy is launched with `cat` as the upstream MCP server. `cat`
echoes whatever bytes we feed it, which is enough to exercise the
proxy's s2c inspection path on a fixture-driven response. We never
make a real API call in these tests.

To add a new server:

1. Create `fixtures/<server>/{handshake,benign_<name>,attack_<name>}.json`.
2. Copy `test_github.py` to `test_<server>.py` and adapt the imports +
   fixture names. The three test methods are template-shaped; you
   only edit the assertions for the specific attack class.
3. Run `pytest tests/integration/test_<server>.py -v`.

Sources for protocol shapes are linked in the docstring of each test
file. We do **not** assert on byte-equality with upstream releases —
servers add fields over time. We only assert on the shape that
matters for inspection (`result.content[*].type == "text"`,
`result.isError`, `id` echo).
